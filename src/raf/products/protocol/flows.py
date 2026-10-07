"""Bidirectional flows keyed by the 5-tuple, with an explained client/server inference.

Flow IDs are assigned in order of first appearance (1, 2, 3 ...), so the same
file always yields the same IDs, whatever filter is applied afterwards. Each
flow also carries its Community ID (https://github.com/corelight/community-id-spec),
the hash Zeek, Suricata and Arkime use for the same 5-tuple, to pivot across tools.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import struct
from dataclasses import dataclass, field

from raf.products.protocol.decoders.tables import IP_PROTOCOL_KEYS, SERVICE_PORTS, TCP_FLAG_BITS
from raf.products.protocol.model import DecodedPacket, endpoint_text

FlowKey = tuple[int, str, int, str, int]  # protocol, lower endpoint (ip, port), higher endpoint (ip, port)

MAX_FRAGMENT_TRACKING = 4096
_SYN, _ACK = 0x02, 0x10
_ECHO_REQUESTS = frozenset({8, 128})
_PORT_APPS = {53: "dns", 5353: "dns", 80: "http", 8000: "http", 8080: "http", 443: "tls", 853: "tls", 8443: "tls"}
_APPS = ("dns", "http", "tls")


@dataclass(slots=True)
class FlowSide:
    """Traffic sent by one endpoint of a flow."""

    ip: str
    port: int
    packets: int = 0
    ip_bytes: int = 0
    payload_bytes: int = 0
    sent_syn: bool = False  # SYN without ACK: opened the connection
    sent_syn_ack: bool = False
    requests: int = 0  # DNS queries, HTTP requests, TLS ClientHellos, ICMP echo requests

    @property
    def endpoint(self) -> str:
        return endpoint_text(self.ip, self.port or None)


@dataclass(slots=True)
class Flow:
    id: int
    proto: int
    a: FlowSide
    b: FlowSide
    first_sender_is_a: bool
    first_ns: int | None = None
    last_ns: int | None = None
    tcp_flags: int = 0
    apps: list[str] = field(default_factory=list)

    @property
    def protocol(self) -> str:
        return IP_PROTOCOL_KEYS.get(self.proto, f"ip-{self.proto}")

    @property
    def packets(self) -> int:
        return self.a.packets + self.b.packets

    @property
    def duration_s(self) -> float | None:
        if self.first_ns is None or self.last_ns is None:
            return None
        return round((self.last_ns - self.first_ns) / 1e9, 6)

    @property
    def tcp_flag_names(self) -> list[str]:
        return [name for bit, name in TCP_FLAG_BITS if self.tcp_flags & bit]

    def observe(self, pkt: DecodedPacket, from_a: bool) -> None:
        side = self.a if from_a else self.b
        side.packets += 1
        side.ip_bytes += pkt.ip_bytes
        side.payload_bytes += pkt.payload_length
        if pkt.timestamp_ns is not None:
            self.first_ns = pkt.timestamp_ns if self.first_ns is None else min(self.first_ns, pkt.timestamp_ns)
            self.last_ns = pkt.timestamp_ns if self.last_ns is None else max(self.last_ns, pkt.timestamp_ns)
        if pkt.tcp_flags is not None:
            self.tcp_flags |= pkt.tcp_flags
            if pkt.tcp_flags & _SYN:
                side.sent_syn_ack = side.sent_syn_ack or bool(pkt.tcp_flags & _ACK)
                side.sent_syn = side.sent_syn or not pkt.tcp_flags & _ACK
        if _is_request(pkt):
            side.requests += 1
        for app in _APPS:
            if app in pkt.protocols and app not in self.apps:
                self.apps.append(app)

    def orientation(self) -> tuple[FlowSide, FlowSide, str]:
        """(client, server, why): the evidence used, strongest first."""
        a, b = self.a, self.b
        if a.sent_syn != b.sent_syn:
            client = a if a.sent_syn else b
            return client, _other(self, client), "the client sent the TCP SYN"
        if a.sent_syn_ack != b.sent_syn_ack:
            server = a if a.sent_syn_ack else b
            return _other(self, server), server, "the server answered with SYN-ACK"
        if bool(a.requests) != bool(b.requests):
            client = a if a.requests else b
            return client, _other(self, client), "the client sent the requests (DNS query, HTTP request, ClientHello)"
        if _service_port(a.port) != _service_port(b.port):
            server = a if _service_port(a.port) else b
            return _other(self, server), server, f"port {server.port} is a well-known service port"
        client = a if self.first_sender_is_a else b
        return client, _other(self, client), "the client sent the first packet seen"

    def application(self) -> tuple[str, str]:
        """(dns|http|tls|other, evidence): decoded payload wins over the server port."""
        if self.apps:
            return self.apps[0], "payload"
        _client, server, _why = self.orientation()
        app = _PORT_APPS.get(server.port) if self.proto in (6, 17) else None
        return (app, "port") if app else ("other", "none")

    def community_id(self) -> str | None:
        return community_id(self.proto, self.a.ip, self.a.port, self.b.ip, self.b.port)


def _other(flow: Flow, side: FlowSide) -> FlowSide:
    return flow.b if side is flow.a else flow.a


def _service_port(port: int) -> bool:
    return port in SERVICE_PORTS or 0 < port < 1024


def _is_request(pkt: DecodedPacket) -> bool:
    if pkt.dns is not None and not pkt.dns.is_response:
        return True
    if pkt.http is not None and pkt.http.is_request:
        return True
    if any(hello.client for hello in pkt.tls):
        return True
    return pkt.icmp_type in _ECHO_REQUESTS


def community_id(proto: int, src: str, sport: int, dst: str, dport: int, seed: int = 0) -> str | None:
    """Community ID v1 for TCP, UDP and SCTP flows (None for other protocols)."""
    if proto not in (6, 17, 132):
        return None
    a, b = ipaddress.ip_address(src).packed, ipaddress.ip_address(dst).packed
    if (a, sport) > (b, dport):
        a, b, sport, dport = b, a, dport, sport
    data = struct.pack("!H", seed) + a + b + struct.pack("!BBHH", proto, 0, sport, dport)
    return "1:" + base64.b64encode(hashlib.sha1(data, usedforsecurity=False).digest()).decode("ascii")


class FlowTable:
    """Assigns every IP packet to a flow (bounded: at most ``max_flows`` flows are tracked)."""

    def __init__(self, max_flows: int) -> None:
        self.max_flows = max_flows
        self.flows: list[Flow] = []
        self.untracked_packets = 0
        self.overflow = False
        self._index: dict[FlowKey, Flow] = {}
        self._fragments: dict[tuple[str, str, int, int], tuple[int, int]] = {}

    def __len__(self) -> int:
        return len(self.flows)

    def get(self, flow_id: int) -> Flow | None:
        return self.flows[flow_id - 1] if 0 < flow_id <= len(self.flows) else None

    def add(self, pkt: DecodedPacket) -> Flow | None:
        resolved = self._key(pkt)
        if resolved is None:
            return None
        key, from_a = resolved
        flow = self._index.get(key)
        if flow is None:
            if len(self.flows) >= self.max_flows:
                self.overflow = True
                self.untracked_packets += 1
                return None
            flow = Flow(len(self.flows) + 1, key[0], FlowSide(key[1], key[2]), FlowSide(key[3], key[4]), from_a)
            self._index[key] = flow
            self.flows.append(flow)
        flow.observe(pkt, from_a)
        return flow

    def _key(self, pkt: DecodedPacket) -> tuple[FlowKey, bool] | None:
        if pkt.src_ip is None or pkt.dst_ip is None or pkt.ip_proto is None:
            return None
        ports = self._ports(pkt)
        if ports is None:
            return None
        src, dst = (pkt.src_ip, ports[0]), (pkt.dst_ip, ports[1])
        if src <= dst:
            return (pkt.ip_proto, *src, *dst), True
        return (pkt.ip_proto, *dst, *src), False

    def _ports(self, pkt: DecodedPacket) -> tuple[int, int] | None:
        """Ports of the packet; non-first IP fragments borrow them from their first fragment."""
        assert pkt.src_ip is not None and pkt.dst_ip is not None and pkt.ip_proto is not None
        fragment = (pkt.src_ip, pkt.dst_ip, pkt.ip_proto, pkt.ip_id or 0)
        if pkt.fragment_offset:
            return self._fragments.get(fragment)
        if pkt.ip_proto in (6, 17) and (pkt.src_port is None or pkt.dst_port is None):
            return None  # transport header too damaged to identify the flow
        ports = (pkt.src_port or 0, pkt.dst_port or 0)
        if pkt.more_fragments:
            if len(self._fragments) >= MAX_FRAGMENT_TRACKING:
                self._fragments.pop(next(iter(self._fragments)))
            self._fragments[fragment] = ports
        return ports
