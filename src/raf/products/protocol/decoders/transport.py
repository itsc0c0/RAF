"""Transport layer: TCP, UDP, ICMP and ICMPv6, plus dispatch to DNS / HTTP / TLS."""

from __future__ import annotations

from raf.products.protocol.decoders.base import Cursor, DecodeError, ipv4_text, ipv6_text, label, mark_malformed
from raf.products.protocol.decoders.dns import decode_dns
from raf.products.protocol.decoders.http import decode_http, looks_like_http
from raf.products.protocol.decoders.tables import (
    ICMP_CODES,
    ICMP_TYPES,
    ICMPV6_CODES,
    ICMPV6_TYPES,
    IP_PROTOCOLS,
    TCP_FLAG_BITS,
    TCP_OPTIONS,
)
from raf.products.protocol.decoders.tls import decode_tls, looks_like_tls
from raf.products.protocol.model import DecodedPacket, Layer

DNS_PORTS = frozenset({53, 5353, 5355})
MAX_TCP_OPTIONS = 40


def tcp_flag_names(flags: int) -> list[str]:
    return [name for bit, name in TCP_FLAG_BITS if flags & bit]


def attach_transport(parent: Layer, proto: int, payload: bytes, pkt: DecodedPacket) -> None:
    """Decode the payload of an IP packet whose next protocol is ``proto``."""
    pkt.ip_proto = proto
    decoder = _DECODERS.get(proto)
    if decoder is None:
        name = IP_PROTOCOLS.get(proto, f"IP protocol {proto}")
        parent.add("payload", f"{len(payload)} bytes of {name}", "Carried protocol that R$F does not decode")
        return
    parent.children.append(decoder(payload, pkt))


# --------------------------------------------------------------------------- TCP


def decode_tcp(data: bytes, pkt: DecodedPacket) -> Layer:
    layer = Layer("TCP")
    pkt.protocols.append("tcp")
    cur = Cursor(data)
    try:
        _tcp_header(cur, layer, pkt)
    except DecodeError as exc:
        return mark_malformed(layer, pkt, exc.message)
    payload = cur.rest()
    pkt.payload_length = len(payload)
    layer.add("payload_length", len(payload), "Bytes of application data carried by this segment")
    if payload:
        _attach_application(layer, "tcp", payload, pkt)
    return layer


def _tcp_header(cur: Cursor, layer: Layer, pkt: DecodedPacket) -> None:
    sport, dport = cur.u16("TCP source port"), cur.u16("TCP destination port")
    pkt.src_port, pkt.dst_port = sport, dport
    layer.add("source_port", sport, "Source port: the sending application's port (clients use ephemeral ports)")
    layer.add("destination_port", dport, "Destination port: the receiving service (443 HTTPS, 80 HTTP, 22 SSH ...)")
    seq, ack = cur.u32("TCP sequence number"), cur.u32("TCP acknowledgment number")
    layer.add("sequence_number", seq, "Sequence number: position of this segment's first byte in the sender's stream")
    layer.add("acknowledgment_number", ack, "Acknowledgment: next byte expected from the peer (valid when ACK is set)")
    offset_flags = cur.u16("TCP data offset and flags")
    header_length, flags = (offset_flags >> 12) * 4, offset_flags & 0x1FF
    pkt.tcp_flags = flags
    names = tcp_flag_names(flags)
    layer.add("header_length", header_length, "Data offset: TCP header length in bytes (20 without options)")
    layer.add("flags", names, "Control flags: SYN opens, ACK acknowledges, PSH pushes data, FIN closes, RST aborts")
    window = cur.u16("TCP window")
    layer.add("window", window, "Receive window: bytes the sender can accept (before window scaling)")
    layer.add(
        "checksum",
        f"0x{cur.u16('TCP checksum'):04x}",
        "Checksum over header, data and IP pseudo-header (not validated)",
    )
    urgent = cur.u16("TCP urgent pointer")
    if urgent or flags & 0x20:
        layer.add("urgent_pointer", urgent, "Urgent pointer: end of urgent data when URG is set (rarely legitimate)")
    layer.summary = f"{sport} → {dport} [{', '.join(names) or 'no flags'}] seq={seq}"
    if header_length < 20:
        raise DecodeError(f"data offset {header_length} bytes is below the 20-byte minimum")
    options = cur.take(header_length - 20, "TCP options")
    if options:
        layer.add(
            "options", _tcp_options(options), "Options negotiated by the endpoints: MSS, window scale, SACK, timestamps"
        )
    if flags & 0x02 and flags & 0x01:
        layer.add("anomaly", "SYN and FIN both set", "Never sent by a normal TCP stack: typical of scanners or evasion")


def _tcp_options(raw: bytes) -> list[str]:
    cur = Cursor(raw)
    out: list[str] = []
    while cur.remaining and len(out) < MAX_TCP_OPTIONS:
        kind = cur.u8("option kind")
        if kind == 0:
            out.append("EOL")
            break
        if kind == 1:
            out.append("NOP")
            continue
        try:
            length = cur.u8("option length")
            if length < 2:
                raise DecodeError(f"option {kind} has invalid length {length}")
            value = cur.take(length - 2, f"option {kind}")
        except DecodeError as exc:
            out.append(f"malformed ({exc.message})")
            break
        out.append(_tcp_option_text(kind, value))
    return out


def _tcp_option_text(kind: int, value: bytes) -> str:
    if kind == 2 and len(value) == 2:
        return f"MSS={int.from_bytes(value, 'big')}"
    if kind == 3 and len(value) == 1:
        return f"WS={value[0]} (x{1 << min(value[0], 14)})"
    if kind == 4 and not value:
        return "SACK_PERM"
    if kind == 5:
        return f"SACK ({len(value) // 8} block(s))"
    if kind == 8 and len(value) == 8:
        return f"TS val={int.from_bytes(value[:4], 'big')} ecr={int.from_bytes(value[4:], 'big')}"
    return TCP_OPTIONS.get(kind, f"kind {kind}") + (f" ({len(value)} bytes)" if value else "")


# --------------------------------------------------------------------------- UDP


def decode_udp(data: bytes, pkt: DecodedPacket) -> Layer:
    layer = Layer("UDP")
    pkt.protocols.append("udp")
    cur = Cursor(data)
    try:
        sport, dport = cur.u16("UDP source port"), cur.u16("UDP destination port")
        pkt.src_port, pkt.dst_port = sport, dport
        layer.add("source_port", sport, "Source port of the sending application")
        layer.add("destination_port", dport, "Destination port: the receiving service (53 DNS, 123 NTP, 443 QUIC ...)")
        length = cur.u16("UDP length")
        layer.add("length", length, "Length of UDP header plus payload in bytes")
        layer.add(
            "checksum",
            f"0x{cur.u16('UDP checksum'):04x}",
            "Checksum (0 = not computed, allowed over IPv4); not validated",
        )
        layer.summary = f"{sport} → {dport} len={length}"
        if 0 < length < 8:
            raise DecodeError(f"length field {length} is below the 8-byte header size")
    except DecodeError as exc:
        return mark_malformed(layer, pkt, exc.message)
    end = len(data) if length == 0 else min(length, len(data))
    payload = data[8:end]
    if length > len(data):
        layer.add("captured", f"{len(data)} of {length} bytes", "Datagram is cut short in the capture (snap length)")
    pkt.payload_length = len(payload)
    layer.add("payload_length", len(payload), "Bytes of application data in this datagram")
    if payload:
        _attach_application(layer, "udp", payload, pkt)
    return layer


# --------------------------------------------------------------------------- ICMP


def decode_icmp(data: bytes, pkt: DecodedPacket) -> Layer:
    return _icmp(data, pkt, version=4)


def decode_icmpv6(data: bytes, pkt: DecodedPacket) -> Layer:
    return _icmp(data, pkt, version=6)


def _icmp(data: bytes, pkt: DecodedPacket, *, version: int) -> Layer:
    name, types, codes = ("ICMP", ICMP_TYPES, ICMP_CODES) if version == 4 else ("ICMPv6", ICMPV6_TYPES, ICMPV6_CODES)
    layer = Layer(name)
    pkt.protocols.append(name.lower())
    cur = Cursor(data)
    try:
        icmp_type, code = cur.u8(f"{name} type"), cur.u8(f"{name} code")
        pkt.icmp_type = icmp_type
        type_name = types.get(icmp_type, f"type {icmp_type}")
        layer.add("type", label(types, icmp_type), f"Message type ({_TYPE_HINT[version]})")
        code_name = codes.get(icmp_type, {}).get(code)
        layer.add("code", f"{code_name} ({code})" if code_name else str(code), "Subtype of the message type")
        layer.add("checksum", f"0x{cur.u16(f'{name} checksum'):04x}", "Checksum (shown as captured, not validated)")
        layer.summary = type_name + (f": {code_name}" if code_name else "")
        _icmp_body(icmp_type, cur, layer, version)
    except DecodeError as exc:
        return mark_malformed(layer, pkt, exc.message)
    return layer


_TYPE_HINT = {
    4: "8 echo request, 0 echo reply, 3 destination unreachable, 11 time exceeded",
    6: "128 echo request, 129 echo reply, 1 unreachable, 135/136 neighbor discovery",
}
_ECHO = {4: frozenset({0, 8, 13, 14}), 6: frozenset({128, 129})}
_ERRORS = {4: frozenset({3, 4, 5, 11, 12}), 6: frozenset({1, 2, 3, 4})}


def _icmp_body(icmp_type: int, cur: Cursor, layer: Layer, version: int) -> None:
    if icmp_type in _ECHO[version]:
        ident, seq = cur.u16("echo identifier"), cur.u16("echo sequence number")
        layer.add("identifier", ident, "Identifier: matches echo replies to requests (often the sender's process)")
        layer.add("sequence", seq, "Sequence number of this echo")
        layer.add("payload_length", cur.remaining, "Echo payload bytes (large or patterned payloads can hide data)")
        layer.summary += f" id={ident} seq={seq}"
    elif icmp_type in _ERRORS[version]:
        word = cur.u32("ICMP error header")
        if version == 4 and icmp_type == 5:
            layer.add("gateway", ipv4_text(word.to_bytes(4, "big")), "Gateway the sender should use instead")
        elif version == 6 and icmp_type == 2:
            layer.add("mtu", word, "MTU of the next hop link (path MTU discovery)")
        layer.add(
            "original_datagram",
            f"{cur.remaining} bytes",
            "Start of the packet that triggered this error (headers of the offending flow)",
        )
    elif version == 6 and icmp_type in (135, 136):
        cur.skip(4, "neighbor discovery flags")
        target = ipv6_text(cur.take(16, "neighbor discovery target"))
        layer.add("target_address", target, "Address being resolved (NS) or announced (NA), like ARP for IPv6")
        layer.summary += f" {target}"


_DECODERS = {6: decode_tcp, 17: decode_udp, 1: decode_icmp, 58: decode_icmpv6}


# --------------------------------------------------------------------------- application dispatch


def _attach_application(parent: Layer, transport: str, payload: bytes, pkt: DecodedPacket) -> None:
    sport, dport = pkt.src_port or 0, pkt.dst_port or 0
    dns_port = sport in DNS_PORTS or dport in DNS_PORTS
    if dns_port and (transport == "udp" or 53 in (sport, dport)):
        parent.children.append(decode_dns(payload, pkt, over_tcp=transport == "tcp"))
        return
    if transport != "tcp":
        return
    if looks_like_tls(payload):
        parent.children.extend(decode_tls(payload, pkt))
    elif looks_like_http(payload):
        parent.children.append(decode_http(payload, pkt))
    else:
        parent.add(
            "application",
            "not recognized",
            "No DNS/HTTP/TLS header at the start of this segment (other protocol, or a continuation)",
        )
