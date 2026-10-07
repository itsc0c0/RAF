"""Streaming capture analysis: protocol counters, flows and DNS / HTTP / TLS records.

One pass over the capture, bounded memory: packets are decoded and discarded;
only aggregates (and at most ``CaptureLimits.max_records`` application records
of each kind) are kept.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from raf.products.protocol.decoders.packet import decode_packet
from raf.products.protocol.filters import PacketFilter
from raf.products.protocol.flows import Flow, FlowTable
from raf.products.protocol.model import DecodedPacket
from raf.products.protocol.reader import ByteSource, CaptureInfo, CaptureLimits, Diagnostics, open_capture

MAX_ANSWERS = 20
MAX_PENDING_HTTP = 64  # unanswered requests remembered per flow (pipelining)


@dataclass(slots=True)
class Endpoints:
    client: str
    client_port: int
    server: str
    server_port: int


@dataclass(slots=True)
class DnsTransaction:
    flow_id: int | None
    packet: int  # the query (or the response when the query was not captured)
    timestamp_ns: int | None
    endpoints: Endpoints
    transport: str
    transaction_id: int
    name: str
    qtype: str
    queries: int = 0
    responded: bool = False
    rcode: str | None = None
    answers: list[str] = field(default_factory=list)


@dataclass(slots=True)
class HttpRequest:
    flow_id: int | None
    packet: int
    timestamp_ns: int | None
    endpoints: Endpoints
    method: str
    target: str
    version: str
    host: str | None
    user_agent: str | None
    content_length: str | None
    status: int | None = None


@dataclass(slots=True)
class TlsHandshake:
    flow_id: int | None
    packet: int
    timestamp_ns: int | None
    endpoints: Endpoints
    sni: str | None
    alpn: list[str]
    offered_versions: list[str]
    legacy_version: str
    cipher_suites_offered: int
    encrypted_client_hello: bool
    selected_version: str | None = None
    selected_cipher: str | None = None
    selected_alpn: str | None = None
    hello_retry: bool = False


@dataclass(slots=True)
class CaptureAnalysis:
    info: CaptureInfo
    filter: PacketFilter
    packets_total: int = 0
    packets_matched: int = 0
    bytes_matched: int = 0
    first_ns: int | None = None
    last_ns: int | None = None
    protocols: dict[str, list[int]] = field(default_factory=dict)  # key -> [packets, bytes]
    flows: list[Flow] = field(default_factory=list)
    matched_flow_ids: set[int] = field(default_factory=set)
    dns: list[DnsTransaction] = field(default_factory=list)
    http: list[HttpRequest] = field(default_factory=list)
    tls: list[TlsHandshake] = field(default_factory=list)
    malformed_packets: int = 0
    internal_errors: int = 0
    warnings: list[str] = field(default_factory=list)
    truncated: bool = False
    limit_reached: bool = False

    @property
    def duration_s(self) -> float | None:
        if self.first_ns is None or self.last_ns is None:
            return None
        return round((self.last_ns - self.first_ns) / 1e9, 6)


class CaptureAnalyzer:
    def __init__(self, info: CaptureInfo, limits: CaptureLimits, packet_filter: PacketFilter | None = None) -> None:
        self.limits = limits
        self.result = CaptureAnalysis(info=info, filter=packet_filter or PacketFilter())
        self.table = FlowTable(limits.max_flows)
        self.notes = Diagnostics(limit=60)
        self._dns_index: dict[tuple[str, int, str, int, int, str, str], DnsTransaction] = {}
        self._pending_http: dict[int, deque[HttpRequest]] = {}
        self._pending_tls: dict[int, TlsHandshake] = {}
        self._full: set[str] = set()

    def add(self, pkt: DecodedPacket) -> Flow | None:
        result = self.result
        result.packets_total += 1
        flow = self.table.add(pkt)
        if pkt.malformed:
            result.malformed_packets += 1
            self.notes.add(f"packet {pkt.number}: " + "; ".join(pkt.malformed[:2]))
        if pkt.internal_error:
            result.internal_errors += 1
        if not result.filter.matches(pkt, flow.id if flow else None):
            return flow
        self._count(pkt)
        if flow is not None:
            result.matched_flow_ids.add(flow.id)
        if pkt.dns is not None and pkt.dns.questions:
            self._dns(pkt, flow)
        if pkt.http is not None:
            self._http(pkt, flow)
        if pkt.tls:
            self._tls(pkt, flow)
        return flow

    def finish(self, warnings: list[str], *, truncated: bool, limit_reached: bool) -> CaptureAnalysis:
        result = self.result
        result.flows = self.table.flows
        result.truncated, result.limit_reached = truncated, limit_reached
        extra = []
        if self.table.overflow:
            extra.append(
                f"flow table limit reached ({self.limits.max_flows:,} flows); "
                f"{self.table.untracked_packets:,} packets of later flows are not in the flow table"
            )
        extra += [
            f"more than {self.limits.max_records:,} {kind} records; later ones were not kept"
            for kind in sorted(self._full)
        ]
        if result.internal_errors:
            extra.append(f"{result.internal_errors} packets hit an internal decoder error (logged); please report it")
        result.warnings = warnings + extra + self.notes.to_list()
        return result

    # ------------------------------------------------------------------ counters
    def _count(self, pkt: DecodedPacket) -> None:
        result = self.result
        result.packets_matched += 1
        result.bytes_matched += pkt.original_length
        if pkt.timestamp_ns is not None:
            ts = pkt.timestamp_ns
            result.first_ns = ts if result.first_ns is None else min(result.first_ns, ts)
            result.last_ns = ts if result.last_ns is None else max(result.last_ns, ts)
        for key in dict.fromkeys(pkt.protocols):
            counter = result.protocols.setdefault(key, [0, 0])
            counter[0] += 1
            counter[1] += pkt.original_length

    def _room(self, kind: str, records: list[DnsTransaction] | list[HttpRequest] | list[TlsHandshake]) -> bool:
        if len(records) < self.limits.max_records:
            return True
        self._full.add(kind)
        return False

    # ------------------------------------------------------------------ application records
    def _dns(self, pkt: DecodedPacket, flow: Flow | None) -> None:
        message = pkt.dns
        assert message is not None
        name, qtype = message.questions[0]
        ends = _endpoints(pkt, reverse=message.is_response)
        key = (
            ends.client,
            ends.client_port,
            ends.server,
            ends.server_port,
            message.transaction_id,
            name.lower(),
            qtype,
        )
        record = self._dns_index.get(key)
        if record is None:
            if not self._room("DNS", self.result.dns):
                return
            transport = "tcp" if "tcp" in pkt.protocols else "udp"
            record = DnsTransaction(
                flow.id if flow else None,
                pkt.number,
                pkt.timestamp_ns,
                ends,
                transport,
                message.transaction_id,
                name,
                qtype,
            )
            self._dns_index[key] = record
            self.result.dns.append(record)
        if not message.is_response:
            record.queries += 1
            return
        record.responded, record.rcode = True, message.rcode
        record.answers = [a.data for a in message.answers if a.rtype != "OPT"][:MAX_ANSWERS]

    def _http(self, pkt: DecodedPacket, flow: Flow | None) -> None:
        message = pkt.http
        assert message is not None
        if not message.is_request:
            pending = self._pending_http.get(flow.id) if flow else None
            if pending:
                pending.popleft().status = message.status
            return
        if not self._room("HTTP", self.result.http):
            return
        request = HttpRequest(
            flow.id if flow else None,
            pkt.number,
            pkt.timestamp_ns,
            _endpoints(pkt),
            message.method or "",
            message.target or "/",
            message.version,
            message.host,
            message.user_agent,
            message.content_length,
        )
        self.result.http.append(request)
        if flow is not None:
            self._pending_http.setdefault(flow.id, deque(maxlen=MAX_PENDING_HTTP)).append(request)

    def _tls(self, pkt: DecodedPacket, flow: Flow | None) -> None:
        for hello in pkt.tls:
            if hello.client:
                if not self._room("TLS", self.result.tls):
                    return
                handshake = TlsHandshake(
                    flow.id if flow else None,
                    pkt.number,
                    pkt.timestamp_ns,
                    _endpoints(pkt),
                    hello.sni,
                    list(hello.alpn),
                    list(hello.versions),
                    hello.legacy_version,
                    len(hello.cipher_suites),
                    hello.encrypted_client_hello,
                )
                self.result.tls.append(handshake)
                if flow is not None:
                    self._pending_tls[flow.id] = handshake
                continue
            pending = self._pending_tls.get(flow.id) if flow else None
            if pending is None:
                continue
            pending.selected_version = hello.version
            pending.selected_cipher = hello.cipher_suites[0] if hello.cipher_suites else None
            pending.selected_alpn = hello.alpn[0] if hello.alpn else None
            pending.hello_retry = pending.hello_retry or hello.hello_retry_request


def _endpoints(pkt: DecodedPacket, *, reverse: bool = False) -> Endpoints:
    src, dst = pkt.src_ip or "?", pkt.dst_ip or "?"
    sport, dport = pkt.src_port or 0, pkt.dst_port or 0
    if reverse:
        return Endpoints(dst, dport, src, sport)
    return Endpoints(src, sport, dst, dport)


def analyze_stream(
    stream: ByteSource, limits: CaptureLimits | None = None, packet_filter: PacketFilter | None = None
) -> CaptureAnalysis:
    """Read, decode and aggregate a whole capture in one streaming pass."""
    limits = limits or CaptureLimits()
    reader = open_capture(stream, limits)
    analyzer = CaptureAnalyzer(reader.info, limits, packet_filter)
    for raw in reader.packets():
        analyzer.add(decode_packet(raw))
    return analyzer.finish(reader.warnings, truncated=reader.truncated, limit_reached=reader.limit_reached)
