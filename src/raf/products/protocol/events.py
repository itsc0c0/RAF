"""Native R$F event records built from a capture analysis (used by the ``pcap`` ingestion parser).

* one ``network.flow`` per flow (client -> server, bytes and packets per direction);
* one ``dns.query`` per DNS transaction (query matched with its response);
* one ``http.request`` per HTTP request line seen at the start of a segment;
* one ``tls.handshake`` per ClientHello (server name, ALPN, negotiated version).

Actors and targets are IP objects (captures contain addresses, not host names);
entity resolution in the ingestion pipeline links them to known hosts.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from functools import partial
from typing import Any
from urllib.parse import urlsplit

from raf.core.timeutil import format_ts
from raf.products.protocol.analysis import CaptureAnalysis, DnsTransaction, HttpRequest, TlsHandshake
from raf.products.protocol.flows import Flow
from raf.products.protocol.model import endpoint_text, ns_to_datetime

MAX_URL = 900
_HOST = re.compile(r"(?:[A-Za-z0-9_.-]{1,253}|\[[0-9A-Fa-f:.]{2,45}\])(?::\d{1,5})?")  # plausible Host header


@dataclass(frozen=True, slots=True)
class NativeRecord:
    locator: str
    data: dict[str, Any] | None
    problem: str | None = None  # why no event could be built (the record is rejected with this reason)


def capture_records(analysis: CaptureAnalysis) -> Iterator[NativeRecord]:
    seen: set[str] = set()
    for flow in analysis.flows:
        yield _record(f"flow {flow.id}", flow.first_ns, partial(flow_event, flow), seen)
    for dns in analysis.dns:
        yield _record(f"packet {dns.packet}", dns.timestamp_ns, partial(dns_event, dns), seen)
    for request in analysis.http:
        yield _record(f"packet {request.packet}", request.timestamp_ns, partial(http_event, request), seen)
    for handshake in analysis.tls:
        yield _record(f"packet {handshake.packet}", handshake.timestamp_ns, partial(tls_event, handshake), seen)


def _record(
    locator: str, timestamp_ns: int | None, build: Callable[[], dict[str, Any]], seen: set[str]
) -> NativeRecord:
    unique, suffix = locator, 2
    while unique in seen:  # event IDs derive from the locator: keep them unique per capture
        unique, suffix = f"{locator} #{suffix}", suffix + 1
    seen.add(unique)
    if ns_to_datetime(timestamp_ns) is None:
        return NativeRecord(
            unique, None, f"{locator} has no usable timestamp (pcapng simple packet block or bad clock)"
        )
    return NativeRecord(unique, build())


def _ts(timestamp_ns: int | None) -> str | None:
    return format_ts(ns_to_datetime(timestamp_ns))


def _ip(value: str) -> dict[str, str]:
    return {"type": "ip", "name": value}


def _compact(values: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in values.items() if v not in (None, "", [])}


# --------------------------------------------------------------------------- events


def flow_event(flow: Flow) -> dict[str, Any]:
    client, server, reason = flow.orientation()
    app, evidence = flow.application()
    has_ports = flow.proto in (6, 17, 132)
    service = f":{server.port}" if has_ports else ""
    return {
        "timestamp": _ts(flow.first_ns),
        "event_type": "network.flow",
        "action": "flow",
        "actor": _ip(client.ip),
        "target": _ip(server.ip),
        "message": (
            f"{flow.protocol} {client.ip} → {server.ip}{service} ({app}): {flow.packets} packets, "
            f"{client.ip_bytes:,} bytes out / {server.ip_bytes:,} bytes in"
        ),
        "attributes": _compact(
            {
                "flow_id": flow.id,
                "community_id": flow.community_id(),
                "protocol": flow.protocol,
                "app": app,
                "app_evidence": evidence,
                "src_ip": client.ip,
                "src_port": client.port if has_ports else None,
                "dst_ip": server.ip,
                "dst_port": server.port if has_ports else None,
                "packets": flow.packets,
                "packets_out": client.packets,
                "packets_in": server.packets,
                "bytes_out": client.ip_bytes,
                "bytes_in": server.ip_bytes,
                "payload_bytes_out": client.payload_bytes,
                "payload_bytes_in": server.payload_bytes,
                "duration_s": flow.duration_s,
                "last_seen": _ts(flow.last_ns),
                "tcp_flags": flow.tcp_flag_names,
                "server_inference": reason,
            }
        ),
    }


def dns_event(record: DnsTransaction) -> dict[str, Any]:
    ends = record.endpoints
    outcome = None if record.rcode is None else ("success" if record.rcode == "NOERROR" else "failure")
    answers = ", ".join(record.answers[:5]) or record.rcode or "no response captured"
    return {
        "timestamp": _ts(record.timestamp_ns),
        "event_type": "dns.query",
        "action": "query",
        "actor": _ip(ends.client),
        "target": {"type": "domain", "name": record.name},
        "outcome": outcome,
        "message": f"{ends.client} asked {ends.server} for {record.qtype} {record.name}: {answers}",
        "attributes": _compact(
            {
                "query_type": record.qtype,
                "answers": list(record.answers),
                "rcode": record.rcode,
                "src_ip": ends.client,
                "dst_ip": ends.server,
                "dst_port": ends.server_port,
                "transport": record.transport,
                "transaction_id": f"0x{record.transaction_id:04x}",
                "flow_id": record.flow_id,
            }
        ),
    }


def request_url(record: HttpRequest) -> str:
    """URL from the request target and Host header (the server address when Host is missing or bogus)."""
    ends = record.endpoints
    fallback = f"http://{_authority(ends.server, ends.server_port)}"
    target = record.target or "/"
    if target.lower().startswith(("http://", "https://")):
        candidates = [target]
    elif record.method == "CONNECT":
        candidates = [f"http://{target}"]
    else:
        path = target if target.startswith("/") else "/" + target
        host = record.host if record.host and _HOST.fullmatch(record.host) else None
        candidates = [f"http://{host}{path}"] if host else []
        candidates.append(fallback + path)
    for url in candidates:
        if _parses(url[:MAX_URL]):
            return url[:MAX_URL]
    return fallback + "/"


def _parses(url: str) -> bool:
    try:
        urlsplit(url)
    except ValueError:
        return False
    return True


def _authority(ip: str, port: int) -> str:
    """URL authority for an address: IPv6 in brackets, the default HTTP port omitted."""
    if port != 80:
        return endpoint_text(ip, port)
    return f"[{ip}]" if ":" in ip else ip


def _domain(host: str | None) -> str | None:
    """The DNS name in a Host header (None for IP literals and implausible values)."""
    if not host or not _HOST.fullmatch(host) or host.startswith("["):
        return None  # missing, implausible, or an IPv6 literal
    name = host.split(":", 1)[0]
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return name.lower()
    return None


def http_event(record: HttpRequest) -> dict[str, Any]:
    ends = record.endpoints
    url = request_url(record)
    outcome = None if record.status is None else ("failure" if record.status >= 400 else "success")
    return {
        "timestamp": _ts(record.timestamp_ns),
        "event_type": "http.request",
        "action": record.method.lower()[:32] or "request",
        "actor": _ip(ends.client),
        "target": {"type": "url", "name": url},
        "outcome": outcome,
        "message": f"{record.method} {url}" + (f" -> {record.status}" if record.status is not None else ""),
        "attributes": _compact(
            {
                "method": record.method,
                "path": record.target,
                "host": record.host,
                "domain": _domain(record.host),
                "user_agent": record.user_agent,
                "status": record.status,
                "src_ip": ends.client,
                "dst_ip": ends.server,
                "dst_port": ends.server_port,
                "flow_id": record.flow_id,
            }
        ),
    }


def tls_event(record: TlsHandshake) -> dict[str, Any]:
    ends = record.endpoints
    target = {"type": "domain", "name": record.sni} if record.sni else _ip(ends.server)
    version = record.selected_version or (record.offered_versions or [record.legacy_version])[0]
    return {
        "timestamp": _ts(record.timestamp_ns),
        "event_type": "tls.handshake",
        "action": "client_hello",
        "actor": _ip(ends.client),
        "target": target,
        "message": f"TLS ClientHello from {ends.client} to {record.sni or ends.server} "
        f"({_authority(ends.server, ends.server_port)}, {version})",
        "attributes": _compact(
            {
                "sni": record.sni,
                "alpn": list(record.alpn),
                "src_ip": ends.client,
                "dst_ip": ends.server,
                "dst_port": ends.server_port,
                "tls_version": version,
                "offered_versions": list(record.offered_versions),
                "cipher_suites_offered": record.cipher_suites_offered,
                "cipher_suite": record.selected_cipher,
                "selected_alpn": record.selected_alpn,
                "encrypted_client_hello": record.encrypted_client_hello or None,
                "hello_retry_request": record.hello_retry or None,
                "flow_id": record.flow_id,
            }
        ),
    }
