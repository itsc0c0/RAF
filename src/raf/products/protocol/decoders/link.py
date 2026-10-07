"""Link layer: Ethernet II (+ 802.1Q/802.1ad tags), Linux cooked capture v1/v2, raw IP and loopback."""

from __future__ import annotations

from collections.abc import Callable

from raf.products.protocol.decoders.base import Cursor, DecodeError, hex16, label, mac_text, mark_malformed
from raf.products.protocol.decoders.ip import decode_ipv4, decode_ipv6
from raf.products.protocol.decoders.tables import ETHERTYPES, LINK_TYPES, VLAN_ETHERTYPES
from raf.products.protocol.model import DecodedPacket, Layer

MAX_VLAN_TAGS = 4
_SLL_PACKET_TYPES = {
    0: "unicast to this host",
    1: "broadcast",
    2: "multicast",
    3: "unicast to another host",
    4: "sent by this host",
}
_BSD_AF_INET = 2
_BSD_AF_INET6 = frozenset({10, 24, 28, 30})  # Linux, NetBSD/OpenBSD, FreeBSD, macOS


def decode_link(link_type: int, data: bytes, pkt: DecodedPacket) -> Layer:
    decoder = _LINK_DECODERS.get(link_type)
    if decoder is not None:
        return decoder(data, pkt)
    layer = Layer(f"Link type {link_type}")
    layer.add("link_type", label(LINK_TYPES, link_type), "Link-layer header type declared by the capture file")
    layer.add("payload", f"{len(data)} bytes", "R$F does not decode this link type")
    layer.summary = "not decoded"
    return layer


def attach_ethertype(parent: Layer, ethertype: int, payload: bytes, pkt: DecodedPacket, vlan_depth: int = 0) -> None:
    """Decode what an EtherType announces (VLAN tag, IPv4, IPv6) as a child of ``parent``."""
    if ethertype in VLAN_ETHERTYPES:
        parent.children.append(_decode_vlan(payload, pkt, vlan_depth + 1))
    elif ethertype == 0x0800:
        parent.children.append(decode_ipv4(payload, pkt))
    elif ethertype == 0x86DD:
        parent.children.append(decode_ipv6(payload, pkt))
    else:
        name = ETHERTYPES.get(ethertype, f"EtherType {hex16(ethertype)}")
        parent.add("payload", f"{len(payload)} bytes of {name}", "Carried protocol that R$F does not decode")


# --------------------------------------------------------------------------- Ethernet


def _decode_ethernet(data: bytes, pkt: DecodedPacket) -> Layer:
    layer = Layer("Ethernet")
    pkt.protocols.append("eth")
    cur = Cursor(data)
    try:
        dst, src = mac_text(cur.take(6, "Ethernet destination")), mac_text(cur.take(6, "Ethernet source"))
        layer.add("destination", dst, "Destination MAC: the interface on this link that should accept the frame")
        layer.add("source", src, "Source MAC: the interface that sent the frame on this link (not the original host)")
        ethertype = cur.u16("EtherType")
    except DecodeError as exc:
        return mark_malformed(layer, pkt, exc.message)
    layer.summary = f"{src} → {dst}"
    if ethertype <= 1500:
        layer.add("length", ethertype, "IEEE 802.3 length field: an 802.3/LLC frame (STP, CDP ...), not decoded")
        return layer
    layer.add("ethertype", _ethertype_text(ethertype), "EtherType: protocol carried (0x0800 IPv4, 0x86dd IPv6)")
    attach_ethertype(layer, ethertype, cur.rest(), pkt)
    return layer


def _decode_vlan(data: bytes, pkt: DecodedPacket, depth: int) -> Layer:
    layer = Layer("802.1Q")
    pkt.protocols.append("vlan")
    cur = Cursor(data)
    try:
        if depth > MAX_VLAN_TAGS:
            raise DecodeError(f"more than {MAX_VLAN_TAGS} stacked VLAN tags")
        tci = cur.u16("802.1Q tag control information")
        layer.add("priority", tci >> 13, "PCP: 802.1p priority (0 = best effort .. 7 = network control)")
        layer.add("drop_eligible", bool(tci & 0x1000), "DEI: frame may be dropped first under congestion")
        layer.add("vlan_id", tci & 0x0FFF, "VLAN ID: the virtual LAN (network segment) the frame belongs to")
        ethertype = cur.u16("802.1Q EtherType")
        layer.add("ethertype", _ethertype_text(ethertype), "EtherType of the encapsulated protocol")
    except DecodeError as exc:
        return mark_malformed(layer, pkt, exc.message)
    layer.summary = f"VLAN {tci & 0x0FFF}"
    attach_ethertype(layer, ethertype, cur.rest(), pkt, depth)
    return layer


def _ethertype_text(value: int) -> str:
    name = ETHERTYPES.get(value)
    return f"{name} ({hex16(value)})" if name else hex16(value)


# --------------------------------------------------------------------------- Linux cooked capture


def _decode_sll(data: bytes, pkt: DecodedPacket) -> Layer:
    layer = Layer("Linux SLL")
    pkt.protocols.append("sll")
    cur = Cursor(data)
    try:
        packet_type = cur.u16("SLL packet type")
        layer.add("packet_type", _SLL_PACKET_TYPES.get(packet_type, str(packet_type)), _PACKET_TYPE_HELP)
        layer.add("hardware_type", cur.u16("SLL ARPHRD type"), "ARPHRD type of the capturing interface (1 = Ethernet)")
        address_length = cur.u16("SLL address length")
        address = cur.take(8, "SLL address")[: min(address_length, 8)]
        layer.add("source_address", mac_text(address) or "-", "Link-layer source address (when the interface has one)")
        protocol = cur.u16("SLL protocol")
        layer.add("protocol", _ethertype_text(protocol), "EtherType of the captured packet")
    except DecodeError as exc:
        return mark_malformed(layer, pkt, exc.message)
    layer.summary = _SLL_PACKET_TYPES.get(packet_type, "")
    attach_ethertype(layer, protocol, cur.rest(), pkt)
    return layer


def _decode_sll2(data: bytes, pkt: DecodedPacket) -> Layer:
    layer = Layer("Linux SLL2")
    pkt.protocols.append("sll")
    cur = Cursor(data)
    try:
        protocol = cur.u16("SLL2 protocol")
        layer.add("protocol", _ethertype_text(protocol), "EtherType of the captured packet")
        cur.skip(2, "SLL2 reserved field")
        layer.add("interface_index", cur.u32("SLL2 interface index"), "Index of the capturing interface (ip link)")
        layer.add("hardware_type", cur.u16("SLL2 ARPHRD type"), "ARPHRD type of the capturing interface (1 = Ethernet)")
        packet_type = cur.u8("SLL2 packet type")
        layer.add("packet_type", _SLL_PACKET_TYPES.get(packet_type, str(packet_type)), _PACKET_TYPE_HELP)
        address_length = cur.u8("SLL2 address length")
        address = cur.take(8, "SLL2 address")[: min(address_length, 8)]
        layer.add("source_address", mac_text(address) or "-", "Link-layer source address (when the interface has one)")
    except DecodeError as exc:
        return mark_malformed(layer, pkt, exc.message)
    layer.summary = _SLL_PACKET_TYPES.get(packet_type, "")
    attach_ethertype(layer, protocol, cur.rest(), pkt)
    return layer


_PACKET_TYPE_HELP = "Direction as seen by the capturing Linux host (sent by us, to us, broadcast ...)"


# --------------------------------------------------------------------------- raw IP and loopback


def _decode_raw(data: bytes, pkt: DecodedPacket) -> Layer:
    if data and data[0] >> 4 == 4:
        return decode_ipv4(data, pkt)
    if data and data[0] >> 4 == 6:
        return decode_ipv6(data, pkt)
    layer = Layer("Raw IP")
    reason = f"IP version nibble is {data[0] >> 4}" if data else "empty packet"
    return mark_malformed(layer, pkt, reason)


def _decode_loopback(data: bytes, pkt: DecodedPacket, *, network_order: bool) -> Layer:
    layer = Layer("Loopback")
    pkt.protocols.append("loop")
    cur = Cursor(data)
    try:
        raw = cur.take(4, "loopback address family")
    except DecodeError as exc:
        return mark_malformed(layer, pkt, exc.message)
    family = int.from_bytes(raw, "big" if network_order else "little")
    if not network_order and family > 0xFFFF:  # written by a big-endian host
        family = int.from_bytes(raw, "big")
    layer.add("family", family, "Address family of the looped-back packet (2 = IPv4; 10/24/28/30 = IPv6)")
    if family == _BSD_AF_INET:
        layer.children.append(decode_ipv4(cur.rest(), pkt))
    elif family in _BSD_AF_INET6:
        layer.children.append(decode_ipv6(cur.rest(), pkt))
    else:
        layer.add("payload", f"{cur.remaining} bytes", "Address family that R$F does not decode")
    return layer


def _decode_null(data: bytes, pkt: DecodedPacket) -> Layer:
    return _decode_loopback(data, pkt, network_order=False)


def _decode_loop(data: bytes, pkt: DecodedPacket) -> Layer:
    return _decode_loopback(data, pkt, network_order=True)


def _decode_ipv4_only(data: bytes, pkt: DecodedPacket) -> Layer:
    return decode_ipv4(data, pkt)


def _decode_ipv6_only(data: bytes, pkt: DecodedPacket) -> Layer:
    return decode_ipv6(data, pkt)


_LINK_DECODERS: dict[int, Callable[[bytes, DecodedPacket], Layer]] = {
    0: _decode_null,
    1: _decode_ethernet,
    12: _decode_raw,
    14: _decode_raw,
    101: _decode_raw,
    108: _decode_loop,
    113: _decode_sll,
    228: _decode_ipv4_only,
    229: _decode_ipv6_only,
    276: _decode_sll2,
}

SUPPORTED_LINK_TYPES = frozenset(_LINK_DECODERS)
