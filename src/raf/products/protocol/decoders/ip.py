"""Network layer: IPv4 (options, fragments) and IPv6 (extension headers skipped safely)."""

from __future__ import annotations

from raf.products.protocol.decoders.base import Cursor, DecodeError, ipv4_text, ipv6_text, label, mark_malformed
from raf.products.protocol.decoders.tables import IP_PROTOCOLS, IPV4_OPTIONS
from raf.products.protocol.decoders.transport import attach_transport
from raf.products.protocol.model import DecodedPacket, Layer

MAX_EXTENSION_HEADERS = 8
_IPV6_EXTENSIONS = {
    0: "Hop-by-Hop Options",
    43: "Routing",
    44: "Fragment",
    51: "Authentication Header",
    60: "Destination Options",
}


# --------------------------------------------------------------------------- IPv4


def decode_ipv4(data: bytes, pkt: DecodedPacket) -> Layer:
    layer = Layer("IPv4")
    pkt.protocols.append("ip")
    cur = Cursor(data)
    try:
        proto, header_length, total_length = _ipv4_header(cur, layer, pkt)
    except DecodeError as exc:
        return mark_malformed(layer, pkt, exc.message)
    end = len(data) if total_length == 0 else min(total_length, len(data))
    if total_length > len(data):
        layer.add(
            "captured", f"{len(data)} of {total_length} bytes", "Packet is cut short in the capture (snap length)"
        )
    pkt.ip_bytes = total_length or len(data)
    payload = data[header_length:end]
    if pkt.fragment_offset:
        layer.add(
            "fragment_data",
            f"{len(payload)} bytes",
            "Non-first fragment: continues an earlier fragment's data; R$F does not reassemble IP fragments",
        )
        return layer
    attach_transport(layer, proto, payload, pkt)
    return layer


def _ipv4_header(cur: Cursor, layer: Layer, pkt: DecodedPacket) -> tuple[int, int, int]:
    first = cur.u8("IPv4 version / header length")
    version, header_length = first >> 4, (first & 0x0F) * 4
    layer.add("version", version, "IP version (4)")
    if version != 4:
        raise DecodeError(f"version field is {version}, expected 4")
    layer.add("header_length", header_length, "IHL: header length in bytes (20 without options)")
    if header_length < 20:
        raise DecodeError(f"header length {header_length} bytes is below the 20-byte minimum")
    tos = cur.u8("IPv4 DSCP/ECN")
    layer.add("dscp", tos >> 2, "DSCP: quality-of-service class requested by the sender (0 = best effort)")
    layer.add("ecn", tos & 0x03, "ECN: explicit congestion notification bits")
    total_length = cur.u16("IPv4 total length")
    layer.add("total_length", total_length, "Total length of the IP packet (header + payload) in bytes")
    ident = cur.u16("IPv4 identification")
    layer.add("identification", f"0x{ident:04x}", "Identification: groups the fragments of one original datagram")
    flags_offset = cur.u16("IPv4 flags / fragment offset")
    flags = [name for bit, name in ((0x8000, "reserved"), (0x4000, "DF"), (0x2000, "MF")) if flags_offset & bit]
    layer.add("flags", flags, "Flags: DF = don't fragment, MF = more fragments follow (reserved must be 0)")
    offset = (flags_offset & 0x1FFF) * 8
    layer.add("fragment_offset", offset, "Fragment offset: where this fragment's data sits in the original datagram")
    ttl = cur.u8("IPv4 TTL")
    layer.add("ttl", ttl, "TTL: hop limit, decremented by each router; the packet is dropped at 0")
    proto = cur.u8("IPv4 protocol")
    pkt.ip_proto = proto
    layer.add("protocol", label(IP_PROTOCOLS, proto), "Protocol carried in the payload (6 TCP, 17 UDP, 1 ICMP)")
    layer.add(
        "checksum", f"0x{cur.u16('IPv4 header checksum'):04x}", "Header checksum (shown as captured, not validated)"
    )
    src, dst = ipv4_text(cur.take(4, "IPv4 source address")), ipv4_text(cur.take(4, "IPv4 destination address"))
    layer.add("source", src, "Source IPv4 address (can be spoofed for connectionless traffic)")
    layer.add("destination", dst, "Destination IPv4 address")
    _set_addresses(pkt, 4, src, dst)
    pkt.ip_id, pkt.fragment_offset, pkt.more_fragments = ident, offset, bool(flags_offset & 0x2000)
    layer.summary = f"{src} → {dst} ttl={ttl} {IP_PROTOCOLS.get(proto, f'proto {proto}')}"
    if offset or pkt.more_fragments:
        layer.summary += f" fragment offset={offset}" + (" MF" if pkt.more_fragments else "")
    if header_length > 20:
        options = cur.take(header_length - 20, "IPv4 options")
        layer.add("options_length", len(options), "Bytes of IP options (rare today; source routing is a red flag)")
        layer.add("options", _ipv4_options(options), "IP options present")
    if 0 < total_length < header_length:
        raise DecodeError(f"total length {total_length} is smaller than the header length {header_length}")
    return proto, header_length, total_length


def _ipv4_options(raw: bytes) -> list[str]:
    out: list[str] = []
    pos = 0
    while pos < len(raw) and len(out) < 40:
        kind = raw[pos]
        if kind in (0, 1):
            out.append(IPV4_OPTIONS[kind])
            pos += 1
            if kind == 0:
                break
            continue
        if pos + 1 >= len(raw) or raw[pos + 1] < 2 or pos + raw[pos + 1] > len(raw):
            out.append(f"malformed option {kind}")
            break
        out.append(IPV4_OPTIONS.get(kind, f"option {kind}"))
        pos += raw[pos + 1]
    return out


def _set_addresses(pkt: DecodedPacket, version: int, src: str, dst: str) -> None:
    if pkt.src_ip is None:  # the outermost IP header describes the packet
        pkt.ip_version, pkt.src_ip, pkt.dst_ip = version, src, dst


# --------------------------------------------------------------------------- IPv6


def decode_ipv6(data: bytes, pkt: DecodedPacket) -> Layer:
    layer = Layer("IPv6")
    pkt.protocols.append("ipv6")
    cur = Cursor(data)
    try:
        next_header, payload_length = _ipv6_header(cur, layer, pkt)
        end = len(data) if payload_length == 0 else min(40 + payload_length, len(data))
        if 40 + payload_length > len(data):
            layer.add("captured", f"{len(data)} of {40 + payload_length} bytes", "Packet is cut short in the capture")
        pkt.ip_bytes = 40 + payload_length if payload_length else len(data)
        body = Cursor(data, 40, end)
        next_header, decode_upper = _ipv6_extensions(body, next_header, layer, pkt)
    except DecodeError as exc:
        return mark_malformed(layer, pkt, exc.message)
    if decode_upper:
        attach_transport(layer, next_header, body.rest(), pkt)
    return layer


def _ipv6_header(cur: Cursor, layer: Layer, pkt: DecodedPacket) -> tuple[int, int]:
    word = cur.u32("IPv6 version / traffic class / flow label")
    version = word >> 28
    layer.add("version", version, "IP version (6)")
    if version != 6:
        raise DecodeError(f"version field is {version}, expected 6")
    layer.add("traffic_class", (word >> 20) & 0xFF, "Traffic class: quality of service (DSCP + ECN), like IPv4 TOS")
    layer.add("flow_label", f"0x{word & 0xFFFFF:05x}", "Flow label: lets routers keep the packets of one flow together")
    payload_length = cur.u16("IPv6 payload length")
    layer.add("payload_length", payload_length, "Bytes after the 40-byte fixed header (extension headers included)")
    next_header = cur.u8("IPv6 next header")
    layer.add("next_header", label(IP_PROTOCOLS, next_header), "Type of the header that follows the fixed header")
    hop_limit = cur.u8("IPv6 hop limit")
    layer.add("hop_limit", hop_limit, "Hop limit: like IPv4 TTL, decremented by each router")
    src, dst = ipv6_text(cur.take(16, "IPv6 source address")), ipv6_text(cur.take(16, "IPv6 destination address"))
    layer.add("source", src, "Source IPv6 address")
    layer.add("destination", dst, "Destination IPv6 address")
    _set_addresses(pkt, 6, src, dst)
    layer.summary = f"{src} → {dst} hop_limit={hop_limit}"
    return next_header, payload_length


def _ipv6_extensions(body: Cursor, next_header: int, layer: Layer, pkt: DecodedPacket) -> tuple[int, bool]:
    """Skip extension headers; returns (upper-layer protocol, whether its header is in this packet)."""
    seen: list[str] = []
    decode_upper = True
    try:
        for _ in range(MAX_EXTENSION_HEADERS):
            if next_header not in _IPV6_EXTENSIONS:
                break
            name = _IPV6_EXTENSIONS[next_header]
            following = body.u8(f"IPv6 {name} next header")
            if next_header == 44:
                body.skip(1, "IPv6 fragment reserved byte")
                offset_flags, ident = body.u16("IPv6 fragment offset"), body.u32("IPv6 fragment identification")
                pkt.ip_id, pkt.fragment_offset = ident, (offset_flags >> 3) * 8
                pkt.more_fragments = bool(offset_flags & 1)
                seen.append(f"Fragment (offset {pkt.fragment_offset}{', more follow' if pkt.more_fragments else ''})")
                decode_upper = pkt.fragment_offset == 0
            else:
                length = body.u8(f"IPv6 {name} length")
                size = (length + 2) * 4 if next_header == 51 else (length + 1) * 8
                body.skip(size - 2, f"IPv6 {name} header")
                seen.append(f"{name} ({size} bytes)")
            next_header = following
        else:
            if next_header in _IPV6_EXTENSIONS:
                raise DecodeError(f"more than {MAX_EXTENSION_HEADERS} extension headers")
    finally:
        if seen:
            layer.add("extension_headers", seen, "Extension headers between the fixed header and the payload")
    if seen:
        layer.add("upper_layer", label(IP_PROTOCOLS, next_header), "Protocol after the extension headers")
    pkt.ip_proto = next_header
    layer.summary += f" {IP_PROTOCOLS.get(next_header, f'proto {next_header}')}"
    if not decode_upper:
        layer.add("fragment_data", f"{body.remaining} bytes", "Non-first fragment: no upper-layer header to decode")
    return next_header, decode_upper
