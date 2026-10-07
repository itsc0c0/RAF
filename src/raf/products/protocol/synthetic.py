"""Deterministic synthetic packet captures (classic pcap) for demos, tests and R$F Lab experiments.

Everything generated here is synthetic. Addresses come from the Raven Industries
dataset and documentation ranges (RFC 5737, RFC 3849); "encrypted" TLS payloads
are seeded random filler (there is no key and nothing to decrypt); the malformed
scenario only contains broken headers for parser-robustness experiments.
The same seed always produces byte-identical output.
"""

from __future__ import annotations

import ipaddress
import random
import struct
from collections.abc import Callable, Sequence
from datetime import UTC, datetime

from raf.data import raven
from raf.products.protocol.model import datetime_to_ns

LINKTYPE_ETHERNET = 1
SNAPLEN = 262_144
ROUTER_MAC = bytes.fromhex("020000000001")
_INTERNAL = (ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("2001:db8:10::/48"))

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10
_BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) RavenBrowser/126.0"
_CLIENT_SUITES = (0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C)


# --------------------------------------------------------------------------- pcap writer


class PcapWriter:
    """Classic libpcap writer: little-endian, microsecond timestamps."""

    def __init__(self, link_type: int = LINKTYPE_ETHERNET, snaplen: int = SNAPLEN) -> None:
        self._parts = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, link_type)]
        self.packets = 0

    def add(self, timestamp_ns: int, frame: bytes, *, original_length: int | None = None) -> None:
        seconds, rest = divmod(timestamp_ns, 1_000_000_000)
        wire = len(frame) if original_length is None else original_length
        self._parts.append(struct.pack("<IIII", seconds, rest // 1000, len(frame), wire) + frame)
        self.packets += 1

    def add_raw(self, data: bytes) -> None:
        """Append raw bytes, e.g. a record header whose data is cut short."""
        self._parts.append(data)

    def to_bytes(self) -> bytes:
        return b"".join(self._parts)


def write_pcap(frames: Sequence[tuple[int, bytes]], link_type: int = LINKTYPE_ETHERNET) -> bytes:
    writer = PcapWriter(link_type)
    for timestamp, frame in frames:
        writer.add(timestamp, frame)
    return writer.to_bytes()


# --------------------------------------------------------------------------- packet builders


def internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total: int = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ethernet(
    src_mac: bytes, dst_mac: bytes, ethertype: int, payload: bytes, *, vlan: int | None = None, pad: bool = True
) -> bytes:
    """An Ethernet II frame (without FCS), padded to the 60-byte minimum like frames seen on a wire."""
    tag = struct.pack("!HH", 0x8100, vlan & 0x0FFF) if vlan is not None else b""
    frame = dst_mac + src_mac + tag + struct.pack("!H", ethertype) + payload
    return frame.ljust(60, b"\x00") if pad else frame


def ipv4(src: str, dst: str, proto: int, payload: bytes, *, ttl: int = 64, ident: int = 0) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        ident & 0xFFFF,
        0x4000,
        ttl,
        proto,
        0,
        ipaddress.IPv4Address(src).packed,
        ipaddress.IPv4Address(dst).packed,
    )
    return header[:10] + struct.pack("!H", internet_checksum(header)) + header[12:] + payload


def ipv6(src: str, dst: str, next_header: int, payload: bytes, *, hop_limit: int = 64) -> bytes:
    addresses = ipaddress.IPv6Address(src).packed + ipaddress.IPv6Address(dst).packed
    return struct.pack("!IHBB", 0x60000000, len(payload), next_header, hop_limit) + addresses + payload


def ip_packet(src: str, dst: str, proto: int, payload: bytes, *, ttl: int = 64, ident: int = 0) -> bytes:
    if ":" in src:
        return ipv6(src, dst, proto, payload, hop_limit=ttl)
    return ipv4(src, dst, proto, payload, ttl=ttl, ident=ident)


def _pseudo_header(src: str, dst: str, proto: int, length: int) -> bytes:
    a, b = ipaddress.ip_address(src), ipaddress.ip_address(dst)
    if a.version == 4:
        return a.packed + b.packed + struct.pack("!BBH", 0, proto, length)
    return a.packed + b.packed + struct.pack("!I3xB", length, proto)


def tcp(
    src: str,
    dst: str,
    sport: int,
    dport: int,
    *,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes = b"",
    window: int = 64240,
    options: bytes = b"",
) -> bytes:
    options = options + b"\x00" * (-len(options) % 4)
    offset = (20 + len(options)) // 4
    header = struct.pack("!HHIIHHHH", sport, dport, seq, ack, (offset << 12) | flags, window, 0, 0) + options
    checksum = internet_checksum(_pseudo_header(src, dst, 6, len(header) + len(payload)) + header + payload)
    return header[:16] + struct.pack("!H", checksum) + header[18:] + payload


def udp(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    header = struct.pack("!HHHH", sport, dport, length, 0)
    checksum = internet_checksum(_pseudo_header(src, dst, 17, length) + header + payload) or 0xFFFF
    return header[:6] + struct.pack("!H", checksum) + payload


def icmp_echo(icmp_type: int, ident: int, seq: int, payload: bytes, *, v6: tuple[str, str] | None = None) -> bytes:
    body = struct.pack("!BBHHH", icmp_type, 0, 0, ident, seq) + payload
    prefix = _pseudo_header(v6[0], v6[1], 58, len(body)) if v6 else b""
    return body[:2] + struct.pack("!H", internet_checksum(prefix + body)) + body[4:]


def dns_name(name: str) -> bytes:
    return b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.split(".") if part) + b"\x00"


def dns_query(txid: int, name: str, qtype: int = 1) -> bytes:
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + dns_name(name) + struct.pack("!HH", qtype, 1)


def dns_response(txid: int, name: str, qtype: int, answers: Sequence[tuple[int, bytes]], ttl: int = 300) -> bytes:
    """A response whose answers point back at the question name (compression pointer 0xc00c)."""
    header = struct.pack("!HHHHHH", txid, 0x8180, 1, len(answers), 0, 0)
    question = dns_name(name) + struct.pack("!HH", qtype, 1)
    records = b"".join(b"\xc0\x0c" + struct.pack("!HHIH", rtype, 1, ttl, len(data)) + data for rtype, data in answers)
    return header + question + records


def dns_answer(value: str) -> tuple[int, bytes]:
    """(type, rdata) for an IP address (A / AAAA) or a host name (CNAME)."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return 5, dns_name(value)
    return (1 if address.version == 4 else 28), address.packed


def tls_record(content_type: int, body: bytes, version: int = 0x0303) -> bytes:
    return struct.pack("!BHH", content_type, version, len(body)) + body


def _extension(ext_type: int, data: bytes) -> bytes:
    return struct.pack("!HH", ext_type, len(data)) + data


def _handshake(msg_type: int, body: bytes) -> bytes:
    return bytes([msg_type]) + len(body).to_bytes(3, "big") + body


def tls_client_hello(sni: str, rng: random.Random, alpn: Sequence[str] = ("h2", "http/1.1")) -> bytes:
    host = sni.encode("ascii")
    protocols = b"".join(bytes([len(p)]) + p.encode("ascii") for p in alpn)
    extensions = b"".join(
        (
            _extension(0, struct.pack("!HBH", len(host) + 3, 0, len(host)) + host),
            _extension(10, struct.pack("!HHHH", 6, 0x001D, 0x0017, 0x0018)),
            _extension(13, struct.pack("!H6H", 12, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501)),
            _extension(16, struct.pack("!H", len(protocols)) + protocols),
            _extension(43, bytes([4]) + struct.pack("!HH", 0x0304, 0x0303)),
            _extension(45, b"\x01\x01"),
            _extension(51, struct.pack("!HHH", 36, 0x001D, 32) + rng.randbytes(32)),
        )
    )
    suites = struct.pack(f"!H{len(_CLIENT_SUITES)}H", 2 * len(_CLIENT_SUITES), *_CLIENT_SUITES)
    body = struct.pack("!H", 0x0303) + rng.randbytes(32) + b"\x20" + rng.randbytes(32) + suites + b"\x01\x00"
    body += struct.pack("!H", len(extensions)) + extensions
    return tls_record(22, _handshake(1, body), version=0x0301)


def tls_server_hello(rng: random.Random, cipher: int = 0x1301) -> bytes:
    extensions = _extension(43, struct.pack("!H", 0x0304)) + _extension(
        51, struct.pack("!HH", 0x001D, 32) + rng.randbytes(32)
    )
    body = struct.pack("!H", 0x0303) + rng.randbytes(32) + b"\x20" + rng.randbytes(32) + struct.pack("!HB", cipher, 0)
    body += struct.pack("!H", len(extensions)) + extensions
    return tls_record(22, _handshake(2, body))


def http_request(method: str, path: str, host: str, user_agent: str = _BROWSER_UA) -> bytes:
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}", f"User-Agent: {user_agent}", "Accept: */*", "", ""]
    return "\r\n".join(lines).encode("ascii")


def http_response(status: int, reason: str, body: bytes, content_type: str = "text/html; charset=utf-8") -> bytes:
    head = f"HTTP/1.1 {status} {reason}\r\nServer: nginx\r\nContent-Type: {content_type}\r\n"
    return (head + f"Content-Length: {len(body)}\r\n\r\n").encode("ascii") + body


# --------------------------------------------------------------------------- conversations


def _mac_for(ip: str) -> bytes:
    return b"\x02\x00" + ipaddress.ip_address(ip).packed[-4:]


def _internal(ip: str) -> bool:
    address = ipaddress.ip_address(ip)
    return any(address.version == net.version and address in net for net in _INTERNAL)


class Capture:
    """Timestamped Ethernet frames; internal hosts talk through one router (as seen on a core switch tap)."""

    def __init__(self, start: datetime, rng: random.Random) -> None:
        self.rng = rng
        self.now = datetime_to_ns(start)
        self.frames: list[tuple[int, bytes]] = []
        self._ip_ids: dict[str, int] = {}

    def wait(self, ms: float, *, jitter: float = 0.15) -> None:
        self.now += int(ms * self.rng.uniform(1 - jitter, 1 + jitter) * 1_000_000)

    def ident(self, host: str) -> int:
        current = self._ip_ids.get(host)
        if current is None:
            current = self.rng.randrange(1, 0xFFFF)
        self._ip_ids[host] = (current + 1) & 0xFFFF
        return current

    def send(self, src: str, dst: str, proto: int, payload: bytes, *, ttl: int = 64, vlan: int | None = None) -> None:
        src_mac, dst_mac = (_mac_for(src), ROUTER_MAC) if _internal(src) else (ROUTER_MAC, _mac_for(dst))
        packet = ip_packet(src, dst, proto, payload, ttl=ttl, ident=self.ident(src))
        ethertype = 0x86DD if ":" in src else 0x0800
        self.frames.append((self.now, ethernet(src_mac, dst_mac, ethertype, packet, vlan=vlan)))

    def ephemeral_port(self) -> int:
        return self.rng.randrange(49152, 65535)


class TcpSession:
    """A TCP conversation with consistent sequence/acknowledgment numbers and timestamps."""

    def __init__(self, cap: Capture, client: str, server: str, server_port: int, *, rtt_ms: float = 20.0) -> None:
        self.cap, self.client, self.server = cap, client, server
        self.client_port, self.server_port = cap.ephemeral_port(), server_port
        self.rtt_ms = rtt_ms
        self._next = {True: cap.rng.getrandbits(32), False: cap.rng.getrandbits(32)}
        self._ts = {True: cap.rng.randrange(10**6, 10**9), False: cap.rng.randrange(10**6, 10**9)}
        self._started = cap.now

    def _timestamps(self, from_client: bool) -> bytes:
        elapsed = (self.cap.now - self._started) // 1_000_000
        return struct.pack("!BBII", 8, 10, (self._ts[from_client] + elapsed) & 0xFFFFFFFF, self._ts[not from_client])

    def segment(self, from_client: bool, flags: int, payload: bytes = b"", *, window: int = 502) -> None:
        src, dst = (self.client, self.server) if from_client else (self.server, self.client)
        sport, dport = (self.client_port, self.server_port) if from_client else (self.server_port, self.client_port)
        options = b"\x01\x01" + self._timestamps(from_client)
        if flags & SYN:
            options = (
                struct.pack("!BBH", 2, 4, 1460) + b"\x04\x02" + self._timestamps(from_client) + b"\x01\x03\x03\x07"
            )
            window = 64240 if from_client else 65160
        seq = self._next[from_client]
        ack = self._next[not from_client] if flags & ACK else 0
        segment = tcp(
            src, dst, sport, dport, seq=seq, ack=ack, flags=flags, payload=payload, window=window, options=options
        )
        self.cap.send(src, dst, 6, segment, ttl=64 if _internal(src) else 52)
        self._next[from_client] = (seq + len(payload) + (1 if flags & (SYN | FIN) else 0)) & 0xFFFFFFFF

    def handshake(self) -> None:
        self.segment(True, SYN)
        self.cap.wait(self.rtt_ms / 2)
        self.segment(False, SYN | ACK)
        self.cap.wait(self.rtt_ms / 2)
        self.segment(True, ACK)

    def send(self, from_client: bool, payload: bytes, *, ack: bool = True, gap_ms: float = 1.0) -> None:
        self.cap.wait(gap_ms)
        self.segment(from_client, PSH | ACK, payload)
        if ack:
            self.cap.wait(self.rtt_ms / 2)
            self.segment(not from_client, ACK)

    def close(self) -> None:
        self.cap.wait(2.0)
        self.segment(True, FIN | ACK)
        self.cap.wait(self.rtt_ms / 2)
        self.segment(False, FIN | ACK)
        self.cap.wait(self.rtt_ms / 2)
        self.segment(True, ACK)


def dns_lookup(cap: Capture, client: str, server: str, name: str, answers: Sequence[str], *, qtype: int = 1) -> None:
    txid, port = cap.rng.getrandbits(16), cap.ephemeral_port()
    cap.send(client, server, 17, udp(client, server, port, 53, dns_query(txid, name, qtype)))
    cap.wait(2.0)
    response = dns_response(txid, name, qtype, [dns_answer(a) for a in answers])
    cap.send(server, client, 17, udp(server, client, 53, port, response))


def tls_session(cap: Capture, client: str, server: str, sni: str, uploads: Sequence[int], *, rtt_ms: float) -> None:
    """Handshake, client hello with SNI, server hello, then encrypted records (random filler)."""
    session = TcpSession(cap, client, server, 443, rtt_ms=rtt_ms)
    session.handshake()
    session.send(True, tls_client_hello(sni, cap.rng))
    cap.wait(rtt_ms / 2)
    server_flight = tls_server_hello(cap.rng) + tls_record(20, b"\x01") + tls_record(23, cap.rng.randbytes(1100))
    session.send(False, server_flight, gap_ms=0.5)
    session.send(True, tls_record(20, b"\x01") + tls_record(23, cap.rng.randbytes(53)))
    for index, size in enumerate(uploads):
        session.send(True, tls_record(23, cap.rng.randbytes(size - 5)), ack=index % 2 == 1, gap_ms=0.3)
    cap.wait(rtt_ms)
    session.send(False, tls_record(23, cap.rng.randbytes(150)))
    session.close()


def http_session(cap: Capture, client: str, server: str, host: str, paths: Sequence[str], *, rtt_ms: float) -> None:
    session = TcpSession(cap, client, server, 80, rtt_ms=rtt_ms)
    session.handshake()
    for path in paths:
        session.send(True, http_request("GET", path, host))
        cap.wait(3.0)
        title = path.strip("/") or "home"
        body = f"<html><head><title>Raven intranet: {title}</title></head><body>synthetic</body></html>"
        session.send(False, http_response(200, "OK", body.encode("ascii")))
    session.close()


def _host_ip(name: str) -> str:
    return str(next(h["ip"] for h in raven.HOSTS if h["name"] == name))


def _merge(*captures: Capture) -> bytes:
    frames = sorted((frame for cap in captures for frame in cap.frames), key=lambda item: item[0])
    return write_pcap(frames)


# --------------------------------------------------------------------------- scenarios


def raven_inc001_capture(seed: int = 1) -> bytes:
    """INC-001 excerpt: APP-01 resolves the exfil domain and uploads over TLS; WS-01 browses the intranet."""
    rng = random.Random(seed)
    start = raven.BASE_DAY.replace(hour=23, minute=14)
    exfil = Capture(start, rng)
    exfil.wait(2000, jitter=0)
    app, resolver = _host_ip("APP-01"), _host_ip("DC-01")
    dns_lookup(exfil, app, resolver, raven.EXFIL_DOMAIN, [raven.EXFIL_IP])
    exfil.wait(15)
    tls_session(exfil, app, raven.EXFIL_IP, raven.EXFIL_DOMAIN, [1448] * 12, rtt_ms=38.0)
    benign = Capture(start, rng)
    benign.wait(1200, jitter=0)
    workstation, intranet = _host_ip("WS-01"), raven.DOMAINS["intranet.raven.example"]
    dns_lookup(benign, workstation, resolver, "intranet.raven.example", [intranet])
    benign.wait(5)
    http_session(benign, workstation, intranet, "intranet.raven.example", ["/", "/news"], rtt_ms=1.2)
    return _merge(exfil, benign)


def benign_capture(seed: int = 1) -> bytes:
    """Ordinary office traffic: DNS, HTTPS, intranet HTTP, ICMP, IPv6 and a VLAN-tagged ping."""
    rng = random.Random(seed)
    start = datetime(2026, 10, 7, 9, 0, tzinfo=UTC)
    resolver = _host_ip("DC-01")
    workstations = [h["ip"] for h in raven.HOSTS if h.get("role") == "workstation"]
    captures: list[Capture] = []
    for index, client in enumerate(rng.sample(workstations, k=rng.randint(3, min(5, len(workstations))))):
        cap = Capture(start, rng)
        cap.wait(400.0 * index + rng.uniform(0, 300))
        name, address = rng.choice(sorted(raven.EXTERNAL_DOMAINS.items()))
        dns_lookup(cap, str(client), resolver, name, [address])
        if index % 2 == 0:
            tls_session(cap, str(client), address, name, [rng.randint(200, 1448)], rtt_ms=rng.uniform(15, 60))
        else:
            intranet = raven.DOMAINS["intranet.raven.example"]
            dns_lookup(cap, str(client), resolver, "intranet.raven.example", [intranet])
            http_session(cap, str(client), intranet, "intranet.raven.example", ["/"], rtt_ms=1.5)
        captures.append(cap)
    captures.append(_icmp_and_ipv6(Capture(start, rng)))
    return _merge(*captures)


def _icmp_and_ipv6(cap: Capture) -> Capture:
    cap.wait(250)
    client, gateway = _host_ip("WS-02"), "10.10.0.1"
    ident = cap.rng.getrandbits(16)
    for seq in range(1, 3):
        payload = bytes(range(48))
        cap.send(client, gateway, 1, icmp_echo(8, ident, seq, payload), vlan=10)
        cap.wait(0.4)
        cap.send(gateway, client, 1, icmp_echo(0, ident, seq, payload), vlan=10)
        cap.wait(1000)
    v6_client, v6_resolver, v6_server = "2001:db8:10::21", "2001:db8:10::53", "2001:db8:ff::80"
    dns_lookup(cap, v6_client, v6_resolver, "updates.vendor.example", [v6_server], qtype=28)
    cap.wait(5)
    ping = icmp_echo(128, 7, 1, b"raven-v6-ping", v6=(v6_client, v6_server))
    cap.send(v6_client, v6_server, 58, ping)
    cap.wait(30)
    cap.send(v6_server, v6_client, 58, icmp_echo(129, 7, 1, b"raven-v6-ping", v6=(v6_server, v6_client)))
    return cap


def malformed_capture(seed: int = 1) -> bytes:
    """Broken and fuzzed packets for parser-robustness experiments; ends with a truncated record."""
    rng = random.Random(seed)
    base = Capture(datetime(2026, 10, 7, 12, 0, tzinfo=UTC), rng)
    crafted = [frame for builder in _CRAFTED for frame in builder(rng)]
    valid = [frame for _ts, frame in _frames_of(benign_capture(seed))]
    mutated = [_mutate(rng, rng.choice(valid)) for _ in range(40)]
    writer = PcapWriter()
    for frame in [*valid[:4], *crafted, *mutated]:
        base.wait(10)
        writer.add(base.now, frame)
    base.wait(10)
    seconds, rest = divmod(base.now, 1_000_000_000)
    writer.add_raw(struct.pack("<IIII", seconds, rest // 1000, 1514, 1514) + rng.randbytes(100))
    return writer.to_bytes()


def _frames_of(capture: bytes) -> list[tuple[int, bytes]]:
    frames: list[tuple[int, bytes]] = []
    pos = 24
    while pos + 16 <= len(capture):
        seconds, micros, length, _wire = struct.unpack_from("<IIII", capture, pos)
        frames.append((seconds * 10**9 + micros * 1000, capture[pos + 16 : pos + 16 + length]))
        pos += 16 + length
    return frames


def _mutate(rng: random.Random, frame: bytes) -> bytes:
    data = bytearray(frame)
    choice = rng.randrange(3)
    if choice == 0:
        return bytes(data[: rng.randrange(1, len(data))])
    if choice == 1:
        for _ in range(rng.randint(1, 8)):
            data[rng.randrange(len(data))] = rng.randrange(256)
        return bytes(data)
    position = rng.randrange(14, max(15, len(data) - 2))
    data[position : position + 2] = rng.choice((b"\xff\xff", b"\x00\x00", b"\x00\x05"))
    return bytes(data[: len(frame)])


def _eth(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return ethernet(_mac_for("10.10.1.21"), ROUTER_MAC, ethertype, payload, pad=False)


def _udp_frame(payload: bytes, dport: int = 53, sport: int = 53000) -> bytes:
    src, dst = "10.10.1.21", "10.10.0.5"
    return _eth(ipv4(src, dst, 17, udp(src, dst, sport, dport, payload)))


def _tcp_frame(payload: bytes, dport: int = 443, flags: int = PSH | ACK) -> bytes:
    src, dst = "10.10.1.21", "198.51.100.80"
    return _eth(ipv4(src, dst, 6, tcp(src, dst, 50000, dport, seq=1, ack=1, flags=flags, payload=payload)))


def _crafted_link(rng: random.Random) -> list[bytes]:
    stacked_vlans = b"".join(struct.pack("!HH", 0x8100, i) for i in range(10))
    return [
        rng.randbytes(9),  # shorter than an Ethernet header
        _mac_for("10.0.0.1") + ROUTER_MAC + stacked_vlans + b"\x08\x00" + rng.randbytes(20),
        _eth(b"\x45\x00", 0x0800),  # IPv4 header cut after two bytes
    ]


def _crafted_ip(rng: random.Random) -> list[bytes]:
    good = ipv4("10.10.1.21", "10.10.0.5", 17, udp("10.10.1.21", "10.10.0.5", 1, 2, b"x"))
    v6 = ipv6("2001:db8:10::21", "2001:db8:10::53", 0, b"\x3c\xff" + b"\x00" * 6)  # hop-by-hop then huge dest-opts
    return [
        _eth(bytes([0x43]) + good[1:]),  # IHL 3 (12 bytes)
        _eth(bytes([0x65]) + good[1:]),  # version 6 inside an IPv4 EtherType
        _eth(good[:2] + struct.pack("!H", 4000) + good[4:]),  # total length beyond the capture
        _eth(good[:2] + struct.pack("!H", 12) + good[4:]),  # total length below the header length
        _eth(bytes([0x4F]) + good[1:] + rng.randbytes(8)),  # 40 bytes of options, garbage
        _eth(v6, 0x86DD),
        _eth(
            ipv6("2001:db8:10::21", "2001:db8:10::53", 44, b"\x11\x00\x00\x08" + b"\x00" * 4 + rng.randbytes(16)),
            0x86DD,
        ),
    ]


def _crafted_transport(rng: random.Random) -> list[bytes]:
    src, dst = "10.10.1.21", "198.51.100.80"
    bad_offset = tcp(src, dst, 1, 2, seq=0, ack=0, flags=SYN)[:12] + b"\xf0\x02" + b"\x00" * 6
    bad_options = tcp(src, dst, 1, 2, seq=0, ack=0, flags=SYN, options=b"\x02\x00\x08\x0a\x00\x00")
    return [
        _eth(ipv4(src, dst, 6, bad_offset)),  # data offset 60 with a 20-byte segment
        _eth(ipv4(src, dst, 6, bad_options)),  # option length 0
        _eth(ipv4(src, dst, 6, tcp(src, dst, 1, 2, seq=0, ack=0, flags=SYN | FIN))),  # impossible flag combination
        _eth(ipv4(src, dst, 17, struct.pack("!HHHH", 53000, 53, 4, 0) + rng.randbytes(12))),  # UDP length 4
        _eth(ipv4(src, dst, 1, b"\x08")),  # one-byte ICMP
    ]


def _crafted_dns(rng: random.Random) -> list[bytes]:
    header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    loop_self = header + b"\xc0\x0c\x00\x01\x00\x01"
    loop_pair = header + b"\xc0\x14\x00\x01\x00\x01" + b"\x00" * 2 + b"\xc0\x0c"
    long_name = header + (b"\x3f" + b"a" * 63) * 4 + b"\x00\x00\x01\x00\x01"
    reserved = header + b"\x41abc\x00\x00\x01\x00\x01"
    many = struct.pack("!HHHHHH", 1, 0x0100, 65535, 65535, 65535, 65535) + dns_name("x.example") + b"\x00\x01\x00\x01"
    bad_rdata = dns_response(7, "a.example", 1, [(1, b"\x0a\x00\x00")])
    label = b"\x1b[31mred\x07"  # terminal escape sequence inside a DNS label
    escape = dns_query(9, "x.example")[:12] + bytes([len(label)]) + label + b"\x00\x00\x01\x00\x01"
    return [
        _udp_frame(m) for m in (loop_self, loop_pair, long_name, reserved, many, bad_rdata, escape, rng.randbytes(11))
    ] + [_tcp_frame(struct.pack("!H", 900) + dns_query(3, "tcp.example"), dport=53)]


def _crafted_tls(rng: random.Random) -> list[bytes]:
    hello = tls_client_hello("ok.example", rng)
    bad_sni = hello[:113] + b"\xff\xff" + hello[115:]  # server name length overflows the extension
    evil_sni = tls_client_hello("evil.example", rng).replace(b"evil.example", b"\x1b]0;pwn\x07abcd")
    heartbeat = tls_record(24, b"\x01\x40\x00" + rng.randbytes(16))
    return [
        _tcp_frame(tls_record(22, b"\x01\x00\xff\xff") + b"\x00" * 3),  # handshake longer than the record
        _tcp_frame(struct.pack("!BHH", 23, 0x0303, 65535) + rng.randbytes(40)),  # record above the TLS maximum
        _tcp_frame(bad_sni),
        _tcp_frame(evil_sni),  # control characters in the server name
        _tcp_frame(heartbeat),  # heartbeat claiming 16 KB of payload
        _tcp_frame(b"GET /\x00\x1b[2J HTTP/1.1\r\nHost: \x1b[31mx\r\n", dport=80),
    ]


_CRAFTED: tuple[Callable[[random.Random], list[bytes]], ...] = (
    _crafted_link,
    _crafted_ip,
    _crafted_transport,
    _crafted_dns,
    _crafted_tls,
)

SCENARIOS: dict[str, Callable[[int], bytes]] = {
    "raven-inc001": raven_inc001_capture,
    "benign": benign_capture,
    "malformed": malformed_capture,
}
