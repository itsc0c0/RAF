"""Result models for ``raf protocol`` (CLI ``--json`` and API) and the builders that fill them."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import datetime
from typing import Any

from pydantic import Field

from raf.core.objects.models import RafModel
from raf.products.protocol.analysis import CaptureAnalysis, DnsTransaction, HttpRequest, TlsHandshake
from raf.products.protocol.decoders.tables import LINK_TYPES
from raf.products.protocol.flows import Flow
from raf.products.protocol.model import endpoint_text, ns_to_datetime
from raf.products.protocol.reader import CaptureInfo

_PROTOCOL_ORDER = ("eth", "vlan", "sll", "loop", "ip", "ipv6", "tcp", "udp", "icmp", "icmpv6", "dns", "http", "tls")
_LIST_CAP = 10


class CaptureFile(RafModel):
    name: str
    path: str | None = None
    size: int | None = None
    sha256: str | None = None
    format: str
    version: str
    byte_order: str
    snaplen: int | None = None
    link_types: list[str] = Field(default_factory=list)
    interfaces: list[dict[str, Any]] = Field(default_factory=list)


class PacketTotals(RafModel):
    total: int
    matched: int
    bytes: int
    first: datetime | None = None
    last: datetime | None = None
    duration_s: float | None = None
    malformed: int = 0


class ProtocolCount(RafModel):
    protocol: str
    packets: int
    bytes: int


class FlowSummary(RafModel):
    id: int
    protocol: str
    client: str
    client_port: int | None
    server: str
    server_port: int | None
    server_reason: str
    app: str
    app_evidence: str
    packets: int
    packets_out: int
    packets_in: int
    bytes_out: int
    bytes_in: int
    payload_out: int
    payload_in: int
    first: datetime | None
    last: datetime | None
    duration_s: float | None
    tcp_flags: list[str]
    community_id: str | None


class DnsSummary(RafModel):
    name: str
    type: str
    answers: list[str]
    rcodes: list[str]
    queries: int
    responses: int
    clients: list[str]
    servers: list[str]


class TlsSummary(RafModel):
    sni: str | None
    servers: list[str]
    alpn: list[str]
    versions: list[str]
    ciphers: list[str]
    handshakes: int
    clients: list[str]
    flows: list[int]
    encrypted_client_hello: bool


class HttpSummary(RafModel):
    host: str
    servers: list[str]
    requests: int
    methods: list[str]
    paths: list[str]
    user_agents: list[str]
    statuses: list[int]
    clients: list[str]
    flows: list[int]


class InspectResult(RafModel):
    file: CaptureFile
    filters: dict[str, Any]
    packets: PacketTotals
    protocols: list[ProtocolCount]
    flows: list[FlowSummary]
    flows_total: int
    dns: list[DnsSummary]
    dns_total: int
    tls: list[TlsSummary]
    tls_total: int
    http: list[HttpSummary]
    http_total: int
    warnings: list[str]
    truncated: bool
    limit_reached: bool


class FlowsResult(RafModel):
    file: CaptureFile
    packets: PacketTotals
    flows: list[FlowSummary]
    flows_total: int
    sort: str
    warnings: list[str]
    truncated: bool
    limit_reached: bool


class PacketDetail(RafModel):
    file: CaptureFile
    number: int
    timestamp: datetime | None
    captured_length: int
    original_length: int
    interface: int
    link_type: str
    flow_id: int | None
    flow: str | None
    protocols: list[str]
    info: str
    tree: list[str]
    layers: dict[str, Any]
    malformed: list[str]


class GenerateResult(RafModel):
    path: str
    scenario: str
    seed: int
    packets: int
    bytes: int
    sha256: str


class UploadInfo(RafModel):
    id: str
    name: str
    size: int
    sha256: str


# --------------------------------------------------------------------------- builders


def capture_file(
    info: CaptureInfo, *, name: str, path: str | None, size: int | None, sha256: str | None
) -> CaptureFile:
    link_types = sorted({LINK_TYPES.get(i.link_type, f"link type {i.link_type}") for i in info.interfaces})
    return CaptureFile(
        name=name,
        path=path,
        size=size,
        sha256=sha256,
        format=info.format,
        version=info.version,
        byte_order=info.byte_order,
        snaplen=info.snaplen,
        link_types=link_types,
        interfaces=[i.to_dict() for i in info.interfaces],
    )


def packet_totals(analysis: CaptureAnalysis) -> PacketTotals:
    return PacketTotals(
        total=analysis.packets_total,
        matched=analysis.packets_matched,
        bytes=analysis.bytes_matched,
        first=ns_to_datetime(analysis.first_ns),
        last=ns_to_datetime(analysis.last_ns),
        duration_s=analysis.duration_s,
        malformed=analysis.malformed_packets,
    )


def protocol_counts(analysis: CaptureAnalysis) -> list[ProtocolCount]:
    order = {key: index for index, key in enumerate(_PROTOCOL_ORDER)}
    keys = sorted(analysis.protocols, key=lambda k: (order.get(k, len(order)), k))
    return [ProtocolCount(protocol=k, packets=analysis.protocols[k][0], bytes=analysis.protocols[k][1]) for k in keys]


def flow_summary(flow: Flow) -> FlowSummary:
    client, server, reason = flow.orientation()
    app, evidence = flow.application()
    has_ports = flow.proto in (6, 17, 132)
    return FlowSummary(
        id=flow.id,
        protocol=flow.protocol,
        client=client.ip,
        client_port=client.port if has_ports else None,
        server=server.ip,
        server_port=server.port if has_ports else None,
        server_reason=reason,
        app=app,
        app_evidence=evidence,
        packets=flow.packets,
        packets_out=client.packets,
        packets_in=server.packets,
        bytes_out=client.ip_bytes,
        bytes_in=server.ip_bytes,
        payload_out=client.payload_bytes,
        payload_in=server.payload_bytes,
        first=ns_to_datetime(flow.first_ns),
        last=ns_to_datetime(flow.last_ns),
        duration_s=flow.duration_s,
        tcp_flags=flow.tcp_flag_names,
        community_id=flow.community_id(),
    )


FLOW_SORTS: dict[str, Callable[[Flow], tuple[int | float, int]]] = {
    "id": lambda f: (f.id, 0),
    "bytes": lambda f: (-(f.a.ip_bytes + f.b.ip_bytes), f.id),
    "packets": lambda f: (-f.packets, f.id),
    "duration": lambda f: (-(f.duration_s or 0.0), f.id),
}


def flow_rows(flows: Iterable[Flow], limit: int, sort: str = "id") -> list[FlowSummary]:
    return [flow_summary(f) for f in sorted(flows, key=FLOW_SORTS[sort])[:limit]]


def dns_rows(records: list[DnsTransaction]) -> list[DnsSummary]:
    groups = _group(records, lambda r: (r.name.lower(), r.qtype))
    rows = [
        DnsSummary(
            name=items[0].name,
            type=items[0].qtype,
            answers=_unique(a for r in items for a in r.answers),
            rcodes=sorted({r.rcode for r in items if r.rcode}),
            queries=sum(r.queries for r in items),
            responses=sum(1 for r in items if r.responded),
            clients=_unique(r.endpoints.client for r in items),
            servers=_unique(r.endpoints.server for r in items),
        )
        for items in groups
    ]
    return sorted(rows, key=lambda row: (-(row.queries or row.responses), row.name))


def tls_rows(records: list[TlsHandshake]) -> list[TlsSummary]:
    rows = [
        TlsSummary(
            sni=items[0].sni,
            servers=_unique(endpoint_text(r.endpoints.server, r.endpoints.server_port) for r in items),
            alpn=_unique(p for r in items for p in ([r.selected_alpn] if r.selected_alpn else r.alpn)),
            versions=_unique(r.selected_version or (r.offered_versions or [r.legacy_version])[0] for r in items),
            ciphers=_unique(r.selected_cipher for r in items if r.selected_cipher),
            handshakes=len(items),
            clients=_unique(r.endpoints.client for r in items),
            flows=sorted({r.flow_id for r in items if r.flow_id is not None})[:_LIST_CAP],
            encrypted_client_hello=any(r.encrypted_client_hello for r in items),
        )
        for items in _group(records, lambda r: (r.sni or "").lower())
    ]
    return sorted(rows, key=lambda row: (-row.handshakes, row.sni or ""))


def http_rows(records: list[HttpRequest]) -> list[HttpSummary]:
    rows = [
        HttpSummary(
            host=items[0].host or items[0].endpoints.server,
            servers=_unique(endpoint_text(r.endpoints.server, r.endpoints.server_port) for r in items),
            requests=len(items),
            methods=_unique(r.method for r in items),
            paths=_unique(r.target for r in items),
            user_agents=_unique(r.user_agent for r in items if r.user_agent),
            statuses=sorted({r.status for r in items if r.status is not None}),
            clients=_unique(r.endpoints.client for r in items),
            flows=sorted({r.flow_id for r in items if r.flow_id is not None})[:_LIST_CAP],
        )
        for items in _group(records, lambda r: (r.host or r.endpoints.server).lower())
    ]
    return sorted(rows, key=lambda row: (-row.requests, row.host))


def _group[T](records: Iterable[T], key: Callable[[T], Any]) -> list[list[T]]:
    groups: dict[Any, list[T]] = {}
    for record in records:
        groups.setdefault(key(record), []).append(record)
    return list(groups.values())


def _unique(values: Iterable[str | None]) -> list[str]:
    return list(dict.fromkeys(v for v in values if v))[:_LIST_CAP]
