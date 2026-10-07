"""R$F Protocol: capture readers, decoders, flows, filters, ingestion, CLI and API."""

from __future__ import annotations

import hashlib
import io
import random
import re
import struct
import warnings
from collections import Counter
from datetime import UTC
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from raf.core.context.app import RafContext, open_context
from raf.core.errors import InvalidInputError, NotFoundError, RafError, ResourceLimitExceeded
from raf.core.ingestion.base import ParseContext, SourceInfo
from raf.core.storage.repos.events import EventQuery
from raf.data import raven
from raf.products.protocol import synthetic
from raf.products.protocol.analysis import CaptureAnalysis, Endpoints, HttpRequest, analyze_stream
from raf.products.protocol.decoders.base import DecodeError
from raf.products.protocol.decoders.dns import read_name
from raf.products.protocol.decoders.packet import decode_packet
from raf.products.protocol.events import request_url
from raf.products.protocol.filters import PacketFilter
from raf.products.protocol.flows import community_id
from raf.products.protocol.model import DecodedPacket, Layer, RawPacket, tree_lines
from raf.products.protocol.parser import PcapParser
from raf.products.protocol.reader import CaptureLimits, open_capture
from raf.products.protocol.service import ProtocolService
from raf.products.protocol.synthetic import ethernet, ipv4, ipv6, tcp, udp
from tests.conftest import FIXTURES

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from fastapi.testclient import TestClient

from raf.apps.api.app import create_app

FIXTURE = FIXTURES / "pcap" / "raven-inc001.pcap"
APP, RESOLVER, EXFIL_IP, EXFIL = "10.30.0.5", "10.10.0.5", "198.51.100.23", "files.exfil-test.example"
MAC_A, MAC_B = bytes.fromhex("020000000002"), bytes.fromhex("020000000001")


# --------------------------------------------------------------------------- helpers


def decode(frame: bytes, link_type: int = 1) -> DecodedPacket:
    return decode_packet(RawPacket(1, 0, len(frame), len(frame), link_type, 0, frame))


def decode_all(data: bytes) -> list[DecodedPacket]:
    return [decode_packet(raw) for raw in open_capture(io.BytesIO(data)).packets()]


def analyze(data: bytes, packet_filter: PacketFilter | None = None, **limits: int) -> CaptureAnalysis:
    return analyze_stream(io.BytesIO(data), CaptureLimits(**limits), packet_filter)


def names(pkt: DecodedPacket) -> list[str]:
    assert pkt.root is not None
    return [layer.name for layer in pkt.root.walk()]


def layer(pkt: DecodedPacket, name: str) -> Layer:
    assert pkt.root is not None
    return next(item for item in pkt.root.walk() if item.name == name)


def udp_frame(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    return ethernet(MAC_A, MAC_B, 0x0800, ipv4(src, dst, 17, udp(src, dst, sport, dport, payload)))


def tcp_frame(payload: bytes, *, dport: int = 443, flags: int = 0x18) -> bytes:
    src, dst = "10.0.0.1", "10.0.0.2"
    segment = tcp(src, dst, 40000, dport, seq=1, ack=1, flags=flags, payload=payload)
    return ethernet(MAC_A, MAC_B, 0x0800, ipv4(src, dst, 6, segment))


def all_text(pkt: DecodedPacket) -> list[str]:
    assert pkt.root is not None
    out = [pkt.info, *tree_lines(pkt.root)]
    for item in pkt.root.walk():
        for field in item.fields:
            values = field.value if isinstance(field.value, list) else [field.value]
            out.extend(str(v) for v in values)
    return out


def pcap_bytes(magic: bytes, order: str, frames: list[tuple[int, int, bytes]], link_type: int = 1) -> bytes:
    """A classic pcap written independently of the product's writer: (seconds, fraction, frame)."""
    out = magic + struct.pack(order + "HHiIII", 2, 4, 0, 0, 65535, link_type)
    for seconds, fraction, frame in frames:
        out += struct.pack(order + "IIII", seconds, fraction, len(frame), len(frame)) + frame
    return out


def ng_block(order: str, block_type: int, body: bytes) -> bytes:
    body += b"\x00" * (-len(body) % 4)
    total = 12 + len(body)
    return struct.pack(order + "II", block_type, total) + body + struct.pack(order + "I", total)


def ng_option(order: str, code: int, value: bytes) -> bytes:
    return struct.pack(order + "HH", code, len(value)) + value + b"\x00" * (-len(value) % 4)


def ng_shb(order: str) -> bytes:
    return ng_block(order, 0x0A0D0D0A, struct.pack(order + "IHHq", 0x1A2B3C4D, 1, 0, -1))


def ng_idb(order: str, link_type: int, options: bytes = b"") -> bytes:
    end = ng_option(order, 0, b"") if options else b""
    return ng_block(order, 1, struct.pack(order + "HHI", link_type, 0, 65535) + options + end)


def ng_epb(order: str, interface: int, ticks: int, data: bytes) -> bytes:
    head = struct.pack(order + "IIIII", interface, ticks >> 32, ticks & 0xFFFFFFFF, len(data), len(data))
    return ng_block(order, 6, head + data)


def shape(lines: list[str]) -> list[str]:
    """Tree lines without the per-layer summaries: guides and layer names only."""
    out = []
    for line in lines:
        match = re.match(r"^[ │├└─]*\S+", line)
        assert match is not None
        out.append(match.group(0))
    return out


SPEC_TREE = ["Ethernet", "└── IPv4", "    └── TCP", "        └── TLS"]


def checksum_ok(data: bytes) -> bool:
    if len(data) % 2:
        data += b"\x00"
    total: int = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total == 0xFFFF


# --------------------------------------------------------------------------- synthetic captures


def test_fixture_matches_generator_and_generation_is_deterministic() -> None:
    data = synthetic.raven_inc001_capture(seed=1)
    assert FIXTURE.read_bytes() == data, (
        "fixtures/pcap/raven-inc001.pcap is stale: "
        "raf protocol generate fixtures/pcap/raven-inc001.pcap --scenario raven-inc001 --seed 1 --yes"
    )
    assert synthetic.raven_inc001_capture(seed=2) != data
    for build in synthetic.SCENARIOS.values():
        assert build(7) == build(7)


def test_raven_capture_round_trip() -> None:
    packets = decode_all(FIXTURE.read_bytes())
    assert len(packets) == 50
    assert not any(p.malformed or p.internal_error for p in packets)
    first = packets[0].timestamp
    assert first is not None and first.isoformat().startswith("2026-10-06T23:14:01")

    dns = [p for p in packets if p.dns and p.dns.is_response and p.dns.questions[0][0] == EXFIL]
    assert len(dns) == 1 and (dns[0].src_ip, dns[0].dst_ip) == (RESOLVER, APP)
    assert [(a.rtype, a.data, a.ttl) for a in dns[0].dns.answers] == [("A", EXFIL_IP, 300)]  # type: ignore[union-attr]

    hello = next(p for p in packets if any(h.client for h in p.tls))
    client_hello = hello.tls[0]
    assert (hello.src_ip, hello.dst_ip, hello.dst_port) == (APP, EXFIL_IP, 443)
    assert client_hello.sni == EXFIL and client_hello.alpn == ["h2", "http/1.1"]
    assert client_hello.versions == ["TLS 1.3", "TLS 1.2"] and client_hello.legacy_version == "TLS 1.2"
    assert len(client_hello.cipher_suites) == 12
    assert hello.root is not None and shape(tree_lines(hello.root)) == SPEC_TREE

    server_hello = next(h for p in packets for h in p.tls if not h.client)
    assert server_hello.version == "TLS 1.3" and server_hello.cipher_suites == ["TLS_AES_128_GCM_SHA256"]

    requests = [p.http for p in packets if p.http and p.http.is_request]
    assert [(r.method, r.target, r.host) for r in requests] == [
        ("GET", "/", "intranet.raven.example"),
        ("GET", "/news", "intranet.raven.example"),
    ]
    assert all(r.user_agent and r.user_agent.startswith("Mozilla/5.0") for r in requests)
    statuses = [p.http.status for p in packets if p.http and not p.http.is_request]
    assert statuses == [200, 200]


def test_synthetic_packets_carry_valid_checksums() -> None:
    """Checked independently of the decoders: IPv4 header, TCP and UDP checksums (pseudo-header included)."""
    data = synthetic.raven_inc001_capture(1) + synthetic.benign_capture(3)[24:]
    checked = 0
    for raw in open_capture(io.BytesIO(data)).packets():
        frame = raw.data
        offset = 18 if frame[12:14] == b"\x81\x00" else 14
        if frame[offset - 2 : offset] != b"\x08\x00":
            continue
        ihl = (frame[offset] & 0x0F) * 4
        total = struct.unpack("!H", frame[offset + 2 : offset + 4])[0]
        header, payload = frame[offset : offset + ihl], frame[offset + ihl : offset + total]
        assert checksum_ok(header)
        proto = header[9]
        if proto in (6, 17):
            pseudo = header[12:20] + struct.pack("!BBH", 0, proto, len(payload))
            assert checksum_ok(pseudo + payload)
            checked += 1
    assert checked > 40


def test_benign_capture_covers_vlan_ipv6_and_icmp() -> None:
    packets = decode_all(synthetic.benign_capture(1))
    assert not any(p.malformed for p in packets)
    vlan = next(p for p in packets if "vlan" in p.protocols)
    assert layer(vlan, "802.1Q").value("vlan_id") == 10 and vlan.icmp_type in (0, 8)
    assert layer(vlan, "ICMP").summary.startswith(("Echo Request", "Echo Reply"))
    v6_dns = next(p for p in packets if p.ip_version == 6 and p.dns is not None and p.dns.is_response)
    assert v6_dns.dns.answers[0].rtype == "AAAA" and v6_dns.dns.answers[0].data == "2001:db8:ff::80"  # type: ignore[union-attr]
    assert any("icmpv6" in p.protocols for p in packets)


# --------------------------------------------------------------------------- readers


@pytest.mark.parametrize(
    ("magic", "order", "fraction", "expected_ns"),
    [
        (b"\xd4\xc3\xb2\xa1", "<", 123456, 123_456_000),
        (b"\xa1\xb2\xc3\xd4", ">", 123456, 123_456_000),
        (b"\x4d\x3c\xb2\xa1", "<", 123456789, 123_456_789),
        (b"\xa1\xb2\x3c\x4d", ">", 123456789, 123_456_789),
    ],
)
def test_classic_pcap_byte_orders_and_resolutions(magic: bytes, order: str, fraction: int, expected_ns: int) -> None:
    frame = udp_frame("10.0.0.1", "10.0.0.2", 5000, 53, synthetic.dns_query(1, "a.example"))
    reader = open_capture(io.BytesIO(pcap_bytes(magic, order, [(1_791_328_442, fraction, frame)])))
    packets = list(reader.packets())
    assert len(packets) == 1 and packets[0].data == frame and packets[0].link_type == 1
    assert packets[0].timestamp_ns == 1_791_328_442 * 1_000_000_000 + expected_ns
    assert reader.info.byte_order == ("little-endian" if order == "<" else "big-endian")
    assert reader.warnings == [] and decode_packet(packets[0]).dns is not None


def test_pcapng_sections_interfaces_and_blocks() -> None:
    frame = udp_frame("10.0.0.1", "10.0.0.2", 5000, 53, synthetic.dns_query(1, "ng.example"))
    raw_ip = frame[14:]
    le, be = "<", ">"
    ns_options = ng_option(le, 9, b"\x09") + ng_option(le, 2, b"eth0\x1b[1m")
    data = b"".join(
        [
            ng_shb(le),
            ng_idb(le, 1, ns_options),  # interface 0: Ethernet, nanosecond timestamps, a hostile name
            ng_idb(le, 228, ng_option(le, 9, bytes([0x80 | 20]))),  # interface 1: raw IPv4, 2^-20 s ticks
            ng_block(le, 4, b"\x01\x00\x08\x00garbage!"),  # name resolution block: skipped
            ng_block(le, 0x00000BAD, b"custom block payload"),  # unknown block: skipped
            ng_epb(le, 0, 1_791_328_442_123_456_789, frame),
            ng_epb(le, 1, 3 << 20, raw_ip),
            ng_block(le, 3, struct.pack(le + "I", len(frame)) + frame),  # simple packet block (no timestamp)
            ng_shb(be),  # second section, big-endian, interfaces start again
            ng_idb(be, 1),
            ng_epb(be, 0, 1_000_000, frame),
        ]
    )
    reader = open_capture(io.BytesIO(data))
    packets = list(reader.packets())
    assert reader.warnings == []
    assert [(p.number, p.link_type, p.interface) for p in packets] == [(1, 1, 0), (2, 228, 1), (3, 1, 0), (4, 1, 0)]
    assert packets[0].timestamp_ns == 1_791_328_442_123_456_789
    assert packets[1].timestamp_ns == 3_000_000_000
    assert packets[2].timestamp_ns is None
    assert packets[3].timestamp_ns == 1_000_000_000
    assert all(p.data in (frame, raw_ip) for p in packets)
    assert reader.info.format == "pcapng" and reader.info.sections == 2 and reader.info.byte_order == "little-endian"
    assert reader.info.interfaces[0].name == "eth0\\x1b[1m"
    assert [names(decode_packet(p))[:2] for p in packets[:2]] == [["Ethernet", "IPv4"], ["IPv4", "UDP"]]


def test_pcapng_corruption_is_reported_not_raised() -> None:
    le = "<"
    frame = udp_frame("10.0.0.1", "10.0.0.2", 5000, 53, synthetic.dns_query(1, "a.example"))
    good = ng_shb(le) + ng_idb(le, 1) + ng_epb(le, 0, 1, frame)
    undefined_interface = good + ng_epb(le, 5, 1, frame) + ng_epb(le, 0, 2, frame)
    reader = open_capture(io.BytesIO(undefined_interface))
    assert len(list(reader.packets())) == 2 and "undefined interface 5" in reader.warnings[0]

    bad_trailer = bytearray(good + ng_epb(le, 0, 2, frame))
    bad_trailer[-1] ^= 0xFF
    reader = open_capture(io.BytesIO(bytes(bad_trailer)))
    assert len(list(reader.packets())) == 1 and reader.truncated and "trailing length" in reader.warnings[0]

    reader = open_capture(io.BytesIO((good + ng_epb(le, 0, 2, frame))[:-30]))
    assert len(list(reader.packets())) == 1 and "ends inside a block" in reader.warnings[0]

    lying = good + ng_block(le, 6, struct.pack(le + "IIIII", 0, 0, 0, 5000, 5000) + frame)
    reader = open_capture(io.BytesIO(lying))
    assert len(list(reader.packets())) == 1 and "impossible or too large" in reader.warnings[0]


def test_truncated_classic_capture_stops_with_a_warning() -> None:
    data = FIXTURE.read_bytes()
    for cut in range(0, len(data), 97):
        try:
            analysis = analyze(data[:cut])
        except InvalidInputError:
            assert cut < 4  # only an incomplete magic number is "not a capture"
            continue
        assert analysis.packets_total <= 50 and analysis.internal_errors == 0
        if analysis.truncated:
            assert any(word in analysis.warnings[0] for word in ("ends inside", "truncated"))
    complete = analyze(data)
    assert complete.packets_total == 50 and not complete.truncated and complete.warnings == []


def test_reader_limits() -> None:
    data = FIXTURE.read_bytes()
    limited = analyze(data, max_packets=10)
    assert limited.packets_total == 10 and limited.limit_reached
    assert "stopped after 10 packets" in limited.warnings[0]

    frame = b"\x00" * 64
    corrupt = pcap_bytes(b"\xd4\xc3\xb2\xa1", "<", [(1, 0, frame)]) + struct.pack("<IIII", 2, 0, 10**9, 10**9)
    analysis = analyze(corrupt)
    assert analysis.packets_total == 1 and analysis.truncated and "probably corrupt" in analysis.warnings[0]

    with pytest.raises(InvalidInputError, match="not a pcap or pcapng"):
        open_capture(io.BytesIO(b"GET / HTTP/1.1\r\n"))
    with pytest.raises(InvalidInputError, match="empty"):
        open_capture(io.BytesIO(b""))


# --------------------------------------------------------------------------- decoders


def test_dns_name_decompression_is_bounded() -> None:
    header = struct.pack("!HHHHHH", 1, 0x8180, 1, 0, 0, 0)
    message = header + b"\x03www\x07example\x00" + b"\x00\x01\x00\x01" + b"\x03api\xc0\x10"
    assert read_name(message, 12) == ("www.example", 25)
    assert read_name(message, 29) == ("api.example", 35)
    cases = {
        "compression pointer loop": header + b"\xc0\x0c",
        "loop": header + b"\xc0\x0e\xc0\x0c",
        "past the end": header + b"\xc0\xff",
        "longer than 255": header + (b"\x3f" + b"a" * 63) * 4 + b"\x00",
        "reserved label type": header + b"\x41abc\x00",
        "truncated": header + b"\xc0",
    }
    for expected, data in cases.items():
        with pytest.raises(DecodeError, match=expected):
            read_name(data, 12)
    chain, target = bytearray(header + b"\x00"), 12  # 40 pointers, each to the previous one: no loop, too many
    for _ in range(40):
        position = len(chain)
        chain += struct.pack("!H", 0xC000 | target)
        target = position
    with pytest.raises(DecodeError, match="more than 32 compression pointers"):
        read_name(bytes(chain), target)


def test_dns_message_fields_and_malformed_responses() -> None:
    response = synthetic.dns_response(0x1A2B, "mail.example", 15, [(15, b"\x00\x0a\x04mx01\xc0\x0c")])
    pkt = decode(udp_frame("10.0.0.53", "10.0.0.9", 53, 40000, response))
    dns = layer(pkt, "DNS")
    assert dns.value("transaction_id") == "0x1a2b" and dns.value("type") == "response"
    assert dns.value("answers") == ["mail.example MX ttl=300 10 mx01.mail.example"]
    assert "RD (recursion desired)" in dns.value("flags")  # type: ignore[operator]

    looping = struct.pack("!HHHHHH", 9, 0x8180, 1, 1, 0, 0) + b"\xc0\x0c\x00\x01\x00\x01"
    pkt = decode(udp_frame("10.0.0.53", "10.0.0.9", 53, 40000, looping))
    assert layer(pkt, "DNS").malformed == "compression pointer loop" and pkt.internal_error is None

    over_tcp = struct.pack("!H", 500) + synthetic.dns_query(3, "split.example")
    pkt = decode(tcp_frame(over_tcp, dport=53))
    assert layer(pkt, "DNS").value("segment") is not None and pkt.dns is not None


def test_tls_hello_details_grease_ech_and_heartbeat() -> None:
    hello = synthetic.tls_client_hello("grease.example", random.Random(1))
    # add GREASE to the cipher suite list and an ECH extension, keeping all lengths consistent
    body = bytearray(hello[9:])
    suites_at = 2 + 32 + 1 + body[34]
    count = struct.unpack("!H", body[suites_at : suites_at + 2])[0]
    body[suites_at : suites_at + 2] = struct.pack("!H", count + 2)
    body[suites_at + 2 : suites_at + 2] = b"\x3a\x3a"
    body += struct.pack("!HH", 65037, 4) + b"\x00\x01\x02\x03"
    ext_at = suites_at + 2 + count + 2 + 2
    ext_len = struct.unpack("!H", body[ext_at : ext_at + 2])[0]
    body[ext_at : ext_at + 2] = struct.pack("!H", ext_len + 8)
    record = synthetic.tls_record(22, b"\x01" + len(body).to_bytes(3, "big") + bytes(body), 0x0301)
    pkt = decode(tcp_frame(record))
    client = pkt.tls[0]
    assert (
        client.sni == "grease.example"
        and client.encrypted_client_hello
        and client.cipher_suites[0] == "GREASE (0x3a3a)"
    )
    assert not pkt.malformed

    heartbeat = synthetic.tls_record(24, b"\x01\x40\x00" + b"\x00" * 16)
    assert "Heartbleed" in (layer(decode(tcp_frame(heartbeat)), "TLS").malformed or "")

    multi = synthetic.tls_record(20, b"\x01") + synthetic.tls_record(23, b"\x00" * 40) + b"\x17\x03"
    pkt = decode(tcp_frame(multi))
    records = [item for item in pkt.root.walk() if item.name == "TLS"]  # type: ignore[union-attr]
    assert [r.summary for r in records] == ["ChangeCipherSpec", "Application Data (40 bytes, encrypted)"]
    assert records[-1].value("trailing_bytes") == 2 and "ChangeCipherSpec; Application Data" in pkt.info


def test_http_heads_and_urls() -> None:
    request = (
        b"POST http://proxy.example:8080/x?y=1 HTTP/1.0\r\nhost: proxy.example:8080\r\nContent-Length: 12\r\n\r\nbody"
    )
    pkt = decode(tcp_frame(request, dport=8080))
    assert pkt.http is not None and pkt.http.method == "POST" and pkt.http.content_length == "12"
    assert layer(pkt, "HTTP").value("body_bytes") == 4
    partial = decode(tcp_frame(b"GET /a HTTP/1.1\r\nHost: x.example\r\nUser-Ag", dport=80))
    assert layer(partial, "HTTP").value("headers_complete") is False
    bad = decode(tcp_frame(b"GET /only-two-parts\r\n\r\n", dport=80))
    assert "request line" in (layer(bad, "HTTP").malformed or "")

    def url(method: str, target: str, host: str | None, port: int = 80) -> str:
        ends = Endpoints("10.0.0.1", 40000, "10.0.0.2", port)
        return request_url(HttpRequest(1, 1, 0, ends, method, target, "HTTP/1.1", host, None, None))

    assert url("GET", "/a?b=c", "site.example") == "http://site.example/a?b=c"
    assert url("GET", "http://abs.example/p", "other.example") == "http://abs.example/p"
    assert url("GET", "/", None, 8080) == "http://10.0.0.2:8080/"
    assert url("CONNECT", "files.example:443", "files.example:443") == "http://files.example:443"
    assert url("GET", "/x", "\\x1b[31mx") == "http://10.0.0.2/x"  # hostile Host header: the server address is used
    assert url("GET", "http://[broken/x", None) == "http://10.0.0.2/"


def test_link_types_and_ipv6_extension_headers() -> None:
    packet = ipv4(
        "10.0.0.1", "10.0.0.2", 17, udp("10.0.0.1", "10.0.0.2", 5000, 53, synthetic.dns_query(1, "a.example"))
    )
    sll = struct.pack("!HHH8sH", 0, 1, 6, MAC_A + b"\x00\x00", 0x0800) + packet
    sll2 = struct.pack("!HHIHBB8s", 0x0800, 0, 3, 1, 4, 6, MAC_A + b"\x00\x00") + packet
    cases = {
        113: (sll, ["Linux SLL", "IPv4", "UDP", "DNS"]),
        276: (sll2, ["Linux SLL2", "IPv4", "UDP", "DNS"]),
        101: (packet, ["IPv4", "UDP", "DNS"]),
        228: (packet, ["IPv4", "UDP", "DNS"]),
        0: (struct.pack("<I", 2) + packet, ["Loopback", "IPv4", "UDP", "DNS"]),
        108: (struct.pack(">I", 2) + packet, ["Loopback", "IPv4", "UDP", "DNS"]),
        147: (packet, ["Link type 147"]),
    }
    for link_type, (data, expected) in cases.items():
        pkt = decode(data, link_type)
        assert names(pkt) == expected and not pkt.malformed, link_type
    assert names(decode(struct.pack(">I", 2) + packet, 0)) == ["Loopback", "IPv4", "UDP", "DNS"]  # big-endian writer

    src, dst = "2001:db8::1", "2001:db8::53"
    dns_udp = udp(src, dst, 5000, 53, synthetic.dns_query(2, "v6.example"))
    hop_by_hop = bytes([60, 0]) + b"\x01\x04\x00\x00\x00\x00"  # next: destination options; PadN
    dest_opts = bytes([44, 0]) + b"\x01\x04\x00\x00\x00\x00"  # next: fragment
    first_fragment = bytes([17, 0]) + struct.pack("!HI", 0x0001, 77)  # offset 0, more fragments
    pkt = decode(ipv6(src, dst, 0, hop_by_hop + dest_opts + first_fragment + dns_udp), 229)
    assert names(pkt) == ["IPv6", "UDP", "DNS"] and pkt.more_fragments and pkt.ip_id == 77
    assert len(layer(pkt, "IPv6").value("extension_headers")) == 3  # type: ignore[arg-type]
    later = bytes([17, 0]) + struct.pack("!HI", (185 << 3), 77)
    pkt = decode(ipv6(src, dst, 44, later + b"\x00" * 30), 229)
    assert names(pkt) == ["IPv6"] and pkt.fragment_offset == 1480 and not pkt.malformed
    stacked = MAC_B + MAC_A + b"".join(struct.pack("!HH", 0x8100, i) for i in range(6)) + b"\x08\x00" + packet
    assert "more than 4 stacked VLAN tags" in decode(stacked).malformed[0]


def test_ip_tcp_udp_icmp_fields() -> None:
    pkt = decode(tcp_frame(b"", flags=0x03))
    tcp_layer = layer(pkt, "TCP")
    assert tcp_layer.value("flags") == ["FIN", "SYN"] and tcp_layer.value("anomaly") == "SYN and FIN both set"
    ip_layer = layer(pkt, "IPv4")
    assert ip_layer.value("ttl") == 64 and ip_layer.value("flags") == ["DF"] and ip_layer.value("protocol") == "TCP (6)"
    assert any(f.name == "ttl" and "hop limit" in f.explanation for f in ip_layer.fields)

    unreachable = struct.pack("!BBHI", 3, 3, 0, 0) + b"\x45" + b"\x00" * 27
    pkt = decode(ethernet(MAC_A, MAC_B, 0x0800, ipv4("10.0.0.2", "10.0.0.1", 1, unreachable)))
    assert layer(pkt, "ICMP").summary == "Destination Unreachable: port unreachable"
    ns = struct.pack("!BBHI", 135, 0, 0, 0) + bytes(15) + b"\x01"
    pkt = decode(ipv6("fe80::1", "ff02::1:ff00:1", 58, ns), 229)
    assert layer(pkt, "ICMPv6").value("target_address") == "::1"

    short_udp = ethernet(MAC_A, MAC_B, 0x0800, ipv4("10.0.0.1", "10.0.0.2", 17, struct.pack("!HHHH", 1, 2, 4, 0)))
    assert "below the 8-byte header" in (layer(decode(short_udp), "UDP").malformed or "")
    plain = ipv4("10.0.0.1", "10.0.0.2", 17, udp("10.0.0.1", "10.0.0.2", 1, 2, b"x"))
    with_options = (
        b"\x46" + plain[1:2] + struct.pack("!H", len(plain) + 4) + plain[4:20] + b"\x94\x04\x00\x00" + plain[20:]
    )
    pkt = decode(ethernet(MAC_A, MAC_B, 0x0800, with_options))
    assert layer(pkt, "IPv4").value("options") == ["Router Alert"] and names(pkt)[-1] == "UDP" and not pkt.malformed


def test_malformed_capture_never_raises_and_text_is_sanitized() -> None:
    for seed in (1, 2, 3):
        data = synthetic.malformed_capture(seed)
        analysis = analyze(data)
        assert analysis.malformed_packets >= 20 and analysis.internal_errors == 0 and analysis.truncated
        assert "ends inside packet" in analysis.warnings[0]
        for pkt in decode_all(data):
            assert pkt.internal_error is None
            for text in all_text(pkt):
                assert not any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in text), text
    packets = decode_all(synthetic.malformed_capture(1))
    assert any("\\x1b]0;pwn\\x07" in (h.sni or "") for p in packets for h in p.tls)
    assert any(q[0] == "\\027[31mred\\007" for p in packets if p.dns for q in p.dns.questions)


# --------------------------------------------------------------------------- fuzzing

_KINDS = ("tls", "tls-hello", "http", "dns-udp", "dns-tcp", "dns-v6", "raw")


def _fuzz_frame(kind: str, payload: bytes) -> bytes:
    if kind == "tls":
        return tcp_frame(b"\x16\x03\x01" + struct.pack("!H", len(payload)) + payload)
    if kind == "tls-hello":
        body = b"\x01" + len(payload).to_bytes(3, "big") + payload
        return tcp_frame(synthetic.tls_record(22, body))
    if kind == "http":
        return tcp_frame(b"GET " + payload, dport=80)
    if kind == "dns-udp":
        return udp_frame("10.0.0.1", "10.0.0.53", 4000, 53, payload)
    if kind == "dns-tcp":
        return tcp_frame(struct.pack("!H", len(payload)) + payload, dport=53)
    if kind == "dns-v6":
        return ethernet(MAC_A, MAC_B, 0x86DD, ipv6("::1", "::2", 17, udp("::1", "::2", 53, 4000, payload)))
    return payload


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.binary(max_size=1600), st.sampled_from([0, 1, 12, 101, 108, 113, 228, 229, 276, 9999]))
def test_fuzz_packet_decoder_random_bytes(data: bytes, link_type: int) -> None:
    pkt = decode(data, link_type)
    assert pkt.internal_error is None and pkt.root is not None
    tree_lines(pkt.root)
    pkt.root.to_dict()
    assert isinstance(pkt.info, str)


@settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.sampled_from(_KINDS), st.binary(max_size=700))
def test_fuzz_application_decoders(kind: str, payload: bytes) -> None:
    pkt = decode(_fuzz_frame(kind, payload))
    assert pkt.internal_error is None
    assert all(not any(ord(ch) < 0x20 for ch in text) for text in all_text(pkt))


_HEADS = (
    b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 8 + b"\xff\xff\x00\x00\x01\x00\x00\x00",
    b"\xa1\xb2\x3c\x4d\x00\x02\x00\x04" + b"\x00" * 8 + b"\x00\x00\xff\xff\x00\x00\x00\x71",
    b"\x0a\x0d\x0d\x0a\x1c\x00\x00\x00\x4d\x3c\x2b\x1a\x01\x00\x00\x00" + b"\xff" * 8 + b"\x1c\x00\x00\x00",
    b"\x0a\x0d\x0d\x0a",
)


def _drain(data: bytes) -> None:
    try:
        analysis = analyze(data, max_packets=500)
    except RafError:
        return
    assert analysis.internal_errors == 0


@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.binary(max_size=4000))
def test_fuzz_reader_random_bytes(data: bytes) -> None:
    _drain(data)


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.sampled_from(_HEADS), st.binary(max_size=4000))
def test_fuzz_reader_after_valid_headers(head: bytes, tail: bytes) -> None:
    _drain(head + tail)


_FIXTURE_BYTES = FIXTURE.read_bytes()


@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.integers(0, len(_FIXTURE_BYTES) - 1), st.binary(min_size=1, max_size=8))
def test_fuzz_mutated_capture(offset: int, patch: bytes) -> None:
    _drain(_FIXTURE_BYTES[:offset] + patch + _FIXTURE_BYTES[offset + len(patch) :])


# --------------------------------------------------------------------------- flows and filters


def _flow_ids(analysis: CaptureAnalysis) -> list[int]:
    return sorted(analysis.matched_flow_ids)


def test_flow_statistics_and_inference() -> None:
    analysis = analyze(FIXTURE.read_bytes())
    flows = {f.id: f for f in analysis.flows}
    assert len(flows) == 4
    exfil = flows[4]
    client, server, reason = exfil.orientation()
    assert (client.ip, server.ip, server.port, exfil.protocol) == (APP, EXFIL_IP, 443, "tcp")
    assert reason == "the client sent the TCP SYN" and exfil.application() == ("tls", "payload")
    assert (client.packets, server.packets) == (20, 12)
    assert client.payload_bytes == 244 + 6 + 58 + 12 * 1448 and server.payload_bytes > 1100
    assert client.ip_bytes == client.payload_bytes + 20 * (20 + 32) + 8  # IP + TCP headers (the SYN's is 40 bytes)
    assert client.ip_bytes > 5 * server.ip_bytes
    assert exfil.tcp_flag_names == ["FIN", "SYN", "PSH", "ACK"]
    assert exfil.duration_s is not None and 0.2 < exfil.duration_s < 0.5
    assert exfil.community_id() == community_id(6, APP, client.port, EXFIL_IP, 443)
    assert exfil.community_id() == community_id(6, EXFIL_IP, 443, APP, client.port)
    dns_flow = flows[3]
    assert dns_flow.orientation()[1].port == 53 and dns_flow.application() == ("dns", "payload")
    assert community_id(6, "128.232.110.120", 34855, "66.35.250.204", 80) == "1:LQU9qZlK+B5F3KDmev6m5PMibrg="


def test_flow_inference_without_handshake() -> None:
    response = synthetic.dns_response(5, "late.example", 1, [synthetic.dns_answer("192.0.2.1")])
    mid_stream = tcp(EXFIL_IP, APP, 443, 51000, seq=9, ack=9, flags=0x10, payload=b"\x17\x03\x03\x00\x01x")
    frames = [
        (1_000, udp_frame(RESOLVER, APP, 53, 41000, response)),  # only the response was captured
        (2_000, ethernet(MAC_B, MAC_A, 0x0800, ipv4(EXFIL_IP, APP, 6, mid_stream))),  # server speaks first
    ]
    analysis = analyze(synthetic.write_pcap(frames))
    dns_flow, tls_flow = analysis.flows
    assert dns_flow.orientation()[1].ip == RESOLVER and "well-known" in dns_flow.orientation()[2]
    assert tls_flow.orientation()[0].ip == APP and tls_flow.orientation()[1].port == 443
    assert analysis.dns[0].endpoints.client == APP and analysis.dns[0].queries == 0 and analysis.dns[0].responded


def test_ip_fragments_join_their_flow() -> None:
    src, dst = "10.0.0.1", "10.0.0.2"
    datagram = udp(src, dst, 5000, 9999, b"x" * 40)
    first = ipv4(src, dst, 17, datagram[:24])
    first = first[:6] + b"\x20\x00" + first[8:]  # MF, offset 0 (checksum not recomputed: not validated)
    second = ipv4(src, dst, 17, datagram[24:])
    second = second[:6] + b"\x00\x03" + second[8:]  # offset 24
    frames = [(1, ethernet(MAC_A, MAC_B, 0x0800, first)), (2, ethernet(MAC_A, MAC_B, 0x0800, second))]
    analysis = analyze(synthetic.write_pcap(frames))
    assert len(analysis.flows) == 1 and analysis.flows[0].packets == 2


def test_filters() -> None:
    data = FIXTURE.read_bytes()
    assert analyze(data, PacketFilter.build(protocol="dns")).packets_matched == 4
    assert _flow_ids(analyze(data, PacketFilter.build(protocol="dns"))) == [1, 3]
    by_host = analyze(data, PacketFilter.build(host=APP))
    assert _flow_ids(by_host) == [3, 4] and not by_host.http and [d.name for d in by_host.dns] == [EXFIL]
    assert _flow_ids(analyze(data, PacketFilter.build(port=80))) == [2]
    one_flow = analyze(data, PacketFilter.build(flow_id=4))
    assert one_flow.packets_matched == 32 and len(one_flow.tls) == 1 and one_flow.packets_total == 50
    window = PacketFilter.build(start=raven.BASE_DAY.replace(hour=23, minute=14, second=2))
    assert _flow_ids(analyze(data, window)) == [3, 4]
    assert analyze(data, PacketFilter.build(protocol="tls", host="10.10.1.21")).packets_matched == 0
    v6 = PacketFilter.build(host="2001:DB8:10:0::21")
    assert v6.host == "2001:db8:10::21" and analyze(synthetic.benign_capture(1), v6).packets_matched >= 2
    with pytest.raises(InvalidInputError, match="Unknown protocol"):
        PacketFilter.build(protocol="smtp")
    with pytest.raises(InvalidInputError, match="not an IP address"):
        PacketFilter.build(host="app-01")
    with pytest.raises(InvalidInputError, match="--from is after --to"):
        PacketFilter.build(start=raven.BASE_DAY.replace(hour=2), end=raven.BASE_DAY)


# --------------------------------------------------------------------------- service, parser, ingestion


def test_service_limits_and_errors(ctx: RafContext, tmp_path: Path) -> None:
    service = ProtocolService(ctx)
    big = synthetic.PcapWriter()
    for index in range(800):
        big.add(index * 1000, b"\x00" * 1514)
    path = tmp_path / "big.pcap"
    path.write_bytes(big.to_bytes())
    ctx.settings = ctx.settings.with_overrides({"ingest.max_file_mb": 1})
    with pytest.raises(ResourceLimitExceeded, match="above the configured limit"):
        service.inspect(path)
    with pytest.raises(NotFoundError):
        service.inspect(tmp_path / "missing.pcap")
    text = tmp_path / "notes.pcap"
    text.write_text("not a capture")
    with pytest.raises(InvalidInputError, match=r"notes\.pcap: This is not a pcap"):
        service.flows(text)
    with pytest.raises(NotFoundError, match="has 50 readable packets"):
        service.packet(FIXTURE, 51)
    with pytest.raises(InvalidInputError, match="Cannot write"):
        service.generate(text / "inside-a-file.pcap", "benign", 1)  # parent is a regular file
    assert not list(tmp_path.glob("*.partial"))

    ctx.settings = ctx.settings.with_overrides({"api.max_upload_mb": 1})
    with pytest.raises(ResourceLimitExceeded):
        service.uploads.save(io.BytesIO(b"\xd4\xc3\xb2\xa1" + b"\x00" * (2 << 20)), "big.pcap")
    with pytest.raises(InvalidInputError, match="Invalid upload ID"):
        service.uploads.get("../../etc/passwd")
    assert sorted(p.name for p in service.uploads.directory.iterdir()) == []


def test_parser_sniff_records_and_warnings() -> None:
    head = FIXTURE.read_bytes()[:64]
    assert PcapParser.sniff(FIXTURE, head) == 1.0
    assert PcapParser.sniff(Path("x.log"), b"Oct  7 09:14:11 host sshd[1]: x") == 0.0
    assert PcapParser.sniff(Path("x.pcap"), b"\xd4\xc3\xb2\xa1\x09\x00") == 0.0

    def parse_context() -> ParseContext:
        return ParseContext(SourceInfo("x.pcap"), UTC, None, 1 << 20, 2048, True)

    ctx = parse_context()
    with FIXTURE.open("rb") as stream:
        records = list(PcapParser().records(stream, ctx))
    locators = [r.locator for r in records]
    assert locators[:4] == ["flow 1", "flow 2", "flow 3", "flow 4"] and len(locators) == len(set(locators)) == 9
    assert {r.parser_label for r in records} == {"pcap/1.0"} and ctx.warnings == []
    tls = next(r.data for r in records if r.data and r.data["event_type"] == "tls.handshake")
    assert tls["target"] == {"type": "domain", "name": EXFIL} and tls["attributes"]["dst_port"] == 443

    ctx = parse_context()
    records = list(PcapParser().records(io.BytesIO(synthetic.malformed_capture(1)), ctx))
    assert records and ctx.warnings[0].startswith("pcap: ") and "malformed packets" in ctx.warnings[0]


def test_raf_import_relates_app01_to_the_exfil_destination(cli: Any, raven_home: Path) -> None:
    result = cli("import", str(FIXTURE), "--json")
    assert result.exit_code == 0, result.stderr
    report = result.json()
    assert report["format"] == "pcap" and report["parser"] == "pcap/1.0" and report["rejected"] == 0
    # the demo already holds this capture as INC-001 evidence: same content, same event IDs
    assert report["events_created"] + report["events_duplicate"] == 9
    again = cli("import", str(FIXTURE), "--json").json()
    assert again["events_created"] == 0 and again["events_duplicate"] == 9

    ctx = open_context(env={"RAF_HOME": str(raven_home)})
    try:
        events = ctx.store.events.query(EventQuery(source="raven-inc001.pcap"), limit=100).items
        assert Counter(e.event_type for e in events) == {
            "network.flow": 4,
            "dns.query": 2,
            "http.request": 2,
            "tls.handshake": 1,
        }
        assert {e.parser for e in events} == {"pcap/1.0"}
        flow = next(e for e in events if e.event_type == "network.flow" and e.target == f"ip:{EXFIL_IP}")
        assert flow.actor == f"ip:{APP}" and flow.record == "flow 4" and flow.attributes["dst_port"] == 443
        assert flow.attributes["bytes_out"] > 5 * flow.attributes["bytes_in"]

        edges = {
            (r.relationship_type, r.target_object)
            for r in ctx.store.relationships.edges([f"ip:{APP}"], direction="out")
        }
        assert ("RESOLVED", f"domain:{EXFIL}") in edges
        assert ("CONNECTED_TO", f"ip:{EXFIL_IP}") in edges
        assert ("CONNECTED_TO", f"domain:{EXFIL}") in edges
        resolves = ctx.store.relationships.list(source=f"domain:{EXFIL}", types=["RESOLVES_TO"])
        assert f"ip:{EXFIL_IP}" in {r.target_object for r in resolves}
        assert ctx.store.relationships.between("host:app-01", f"ip:{APP}")  # APP-01 owns the address
        resolved = next(
            r
            for r in ctx.store.relationships.edges([f"ip:{APP}"], direction="out")
            if r.relationship_type == "RESOLVED"
        )
        assert any(p.source == "raven-inc001.pcap" for p in ctx.store.provenance.for_subject(resolved.id))
    finally:
        ctx.close()
    path = cli("graph", "path", "host:app-01", f"ip:{EXFIL_IP}", "--json").json()
    assert path["found"] and path["length"] <= 3


def test_import_of_hostile_and_ipv6_captures(cli: Any, tmp_path: Path) -> None:
    for scenario in ("malformed", "benign"):
        path = tmp_path / f"{scenario}.pcapng.cap"
        path.write_bytes(synthetic.SCENARIOS[scenario](4))
        report = cli("import", str(path), "--json").json()
        assert report["format"] == "pcap" and report["rejected"] == 0 and report["events_created"] > 10, report
    timeline = cli("timeline", "workspace", "--type", "tls.handshake", "--json").json()
    assert all("\x1b" not in (item["message"] or "") for item in timeline["items"])


# --------------------------------------------------------------------------- CLI


def test_cli_inspect(cli: Any) -> None:
    result = cli("protocol", "inspect", str(FIXTURE), "--json")
    assert result.exit_code == 0, result.stderr
    data = result.json()
    assert data["schema"] == "raf.protocol.inspect/v1"
    assert data["packets"]["total"] == 50 and data["packets"]["malformed"] == 0 and data["flows_total"] == 4
    assert data["file"]["format"] == "pcap" and len(data["file"]["sha256"]) == 64
    protocols = {p["protocol"]: p["packets"] for p in data["protocols"]}
    assert protocols == {"eth": 50, "ip": 50, "tcp": 46, "udp": 4, "dns": 4, "http": 4, "tls": 16}
    assert {(d["name"], tuple(d["answers"])) for d in data["dns"]} == {
        (EXFIL, (EXFIL_IP,)),
        ("intranet.raven.example", ("10.40.0.5",)),
    }
    assert data["tls"][0]["sni"] == EXFIL and data["tls"][0]["versions"] == ["TLS 1.3"]
    assert data["http"][0]["host"] == "intranet.raven.example" and data["http"][0]["paths"] == ["/", "/news"]
    exfil = next(f for f in data["flows"] if f["server"] == EXFIL_IP)
    assert exfil["client"] == APP and exfil["server_port"] == 443 and exfil["app"] == "tls"

    filtered = cli("protocol", "inspect", str(FIXTURE), "--host", APP, "--from", "23:14:02", "--limit", "1", "--json")
    body = filtered.json()
    assert body["filters"]["host"] == APP and body["flows_total"] == 2 and len(body["flows"]) == 1
    human = cli("protocol", "inspect", str(FIXTURE), "--protocol", "tls")
    assert human.exit_code == 0 and EXFIL in human.stdout and "intranet.raven.example" not in human.stdout
    assert cli("protocol", "inspect", str(FIXTURE), "--protocol", "smtp").exit_code == 4
    assert cli("protocol", "inspect", str(FIXTURE), "--to", "+0.5s", "--json").json()["packets"]["matched"] == 16


def test_cli_packet_and_flows(cli: Any) -> None:
    detail = cli("protocol", "packet", str(FIXTURE), "22", "--json").json()
    assert detail["schema"] == "raf.protocol.packet/v1" and detail["flow_id"] == 4
    assert shape(detail["tree"]) == SPEC_TREE
    tls = detail["layers"]["children"][0]["children"][0]["children"][0]
    sni = next(f for f in tls["fields"] if f["name"] == "server_name")
    assert sni["value"] == EXFIL and "clear text" in sni["explanation"]
    human = cli("protocol", "packet", str(FIXTURE), "22")
    assert "└── TLS  Handshake: ClientHello (SNI files.exfil-test.example)" in human.stdout
    assert "TTL: hop limit" in human.stdout
    assert cli("protocol", "packet", str(FIXTURE), "999").exit_code == 3

    flows = cli("protocol", "flows", str(FIXTURE), "--sort", "bytes", "--json").json()
    assert flows["schema"] == "raf.protocol.flows/v1" and flows["flows_total"] == 4
    top = flows["flows"][0]
    assert top["id"] == 4 and top["server_reason"] == "the client sent the TCP SYN"
    assert top["community_id"].startswith("1:") and top["tcp_flags"] == ["FIN", "SYN", "PSH", "ACK"]
    assert cli("protocol", "flows", str(FIXTURE), "--sort", "weird").exit_code == 4


def test_cli_generate_and_errors(cli: Any, tmp_path: Path) -> None:
    out = tmp_path / "gen.pcap"
    created = cli("protocol", "generate", str(out), "--scenario", "raven-inc001", "--seed", "1", "--json").json()
    assert created["schema"] == "raf.protocol.generate/v1" and created["packets"] == 50
    assert out.read_bytes() == FIXTURE.read_bytes()
    assert cli("protocol", "generate", str(out), "--scenario", "benign").exit_code == 4  # needs --yes
    replaced = cli("protocol", "generate", str(out), "--scenario", "malformed", "--seed", "2", "--yes", "--json")
    assert replaced.json()["scenario"] == "malformed"
    assert cli("protocol", "generate", str(tmp_path / "x.pcap"), "--scenario", "nope").exit_code == 4

    inspected = cli("protocol", "inspect", str(out))
    assert inspected.exit_code == 0 and "\x1b" not in inspected.stdout and "Warnings" in inspected.stdout
    assert cli("protocol", "inspect", str(tmp_path / "missing.pcap")).exit_code == 3
    junk = tmp_path / "junk.pcap"
    junk.write_bytes(b"MZ\x90\x00" * 10)
    failure = cli("protocol", "inspect", str(junk), "--json")
    assert failure.exit_code == 4 and failure.json()["error"]["code"] == "raf.invalid_input"
    assert "raf protocol" in cli("help", "protocol").stdout


# --------------------------------------------------------------------------- API


@pytest.fixture
def client(raf_home: Path) -> Any:
    app = create_app(env={"RAF_HOME": str(raf_home), "RAF_API_MAX_UPLOAD_MB": "1"})
    with TestClient(app) as c:
        yield c


def test_api_upload_inspect_packet_and_flows(client: Any, raf_home: Path) -> None:
    files = {"file": ("../evil name.pcap", FIXTURE.read_bytes(), "application/vnd.tcpdump.pcap")}
    response = client.post("/api/v1/protocol/inspect", files=files, params={"host": APP})
    assert response.status_code == 200, response.text
    data = response.json()
    upload = data["upload"]["id"]
    assert len(upload) == 32 and data["upload"]["name"] == "evil name.pcap" and data["file"]["path"] is None
    assert data["filters"]["host"] == APP and data["flows_total"] == 2 and data["tls"][0]["sni"] == EXFIL
    stored = raf_home / "workspaces" / "default" / "uploads" / "protocol" / f"{upload}.cap"
    assert stored.read_bytes() == FIXTURE.read_bytes()

    packet = client.get("/api/v1/protocol/packet", params={"upload": upload, "n": 22}).json()
    assert packet["flow_id"] == 4 and packet["tree"][-1].endswith("(SNI files.exfil-test.example)")
    assert packet["upload"]["name"] == "evil name.pcap" and packet["file"]["path"] is None
    assert packet["file"]["sha256"] == packet["upload"]["sha256"] == hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
    flows = client.get("/api/v1/protocol/flows", params={"upload": upload, "sort": "bytes"}).json()
    assert flows["flows"][0]["server"] == EXFIL_IP
    again = client.get("/api/v1/protocol/inspect", params={"upload": upload, "protocol": "dns"}).json()
    assert again["packets"]["matched"] == 4

    assert client.get("/api/v1/protocol/packet", params={"upload": "../../etc/passwd", "n": 1}).status_code == 422
    missing = client.get("/api/v1/protocol/packet", params={"upload": "0" * 32, "n": 1})
    assert missing.status_code == 404 and missing.json()["error"]["code"] == "raf.not_found"
    assert client.get("/api/v1/protocol/packet", params={"upload": upload, "n": 999}).status_code == 404
    bad_filter = client.post("/api/v1/protocol/inspect", files=files, params={"protocol": "smtp"})
    assert bad_filter.status_code == 422


def test_api_rejects_non_captures_and_oversized_uploads(client: Any, raf_home: Path) -> None:
    text = client.post("/api/v1/protocol/inspect", files={"file": ("a.pcap", b"hello world", "text/plain")})
    assert text.status_code == 422 and "not a pcap" in text.json()["error"]["message"]
    big = b"\xd4\xc3\xb2\xa1" + b"\x00" * (2 << 20)
    too_big = client.post("/api/v1/protocol/inspect", files={"file": ("big.pcap", big, "application/octet-stream")})
    # refused by the API body limit before the upload is buffered (api.max_upload_mb)
    assert too_big.status_code == 413 and too_big.json()["error"]["code"] == "raf.request_too_large"
    uploads = raf_home / "workspaces" / "default" / "uploads" / "protocol"
    assert not uploads.exists() or list(uploads.iterdir()) == []
