"""IP address classification shared by ingestion and detections.

``internal`` means an address of the organization's own networks: RFC 1918, carrier-grade NAT,
loopback, link-local and IPv6 unique-local ranges, plus any extra networks a workspace declares
(``detect.internal_networks``). Everything else that is a unicast address is ``public``. The IETF
documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) count as public:
examples and synthetic data use them to stand for Internet addresses. (Python's ``is_private``
calls them private, which is why it is not used here.)
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from functools import lru_cache

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

INTERNAL_NETWORKS: tuple[IPNetwork, ...] = tuple(
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)


def parse_ip(text: object) -> IPAddress | None:
    """The address in ``text`` (brackets and an IPv6 zone are ignored), or None."""
    if not isinstance(text, str) or not text or len(text) > 64:
        return None
    candidate = text.strip().strip("[]").split("%", 1)[0]
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        return None


def is_ip(text: object) -> bool:
    return parse_ip(text) is not None


def parse_networks(values: Iterable[str]) -> tuple[IPNetwork, ...]:
    """CIDR strings to networks; invalid entries are ignored (configuration is validated elsewhere)."""
    networks: list[IPNetwork] = []
    for value in values:
        text = value.strip()
        if not text:
            continue
        try:
            networks.append(ipaddress.ip_network(text, strict=False))
        except ValueError:
            continue
    return tuple(networks)


@lru_cache(maxsize=65536)
def _scope(address: IPAddress, extra: tuple[IPNetwork, ...]) -> str:
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        address = mapped
    if address.is_unspecified:
        return "unspecified"
    if address.is_multicast:
        return "multicast"
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link-local"
    for network in (*INTERNAL_NETWORKS, *extra):
        if address.version == network.version and address in network:
            return "internal"
    if address.version == 4 and int(address) >= int(ipaddress.IPv4Address("240.0.0.0")):
        return "reserved"
    return "public"


def ip_scope(text: object, extra: tuple[IPNetwork, ...] = ()) -> str | None:
    """``internal``, ``public``, ``loopback``, ``link-local``, ``multicast``, ``unspecified``,
    ``reserved``, or None when ``text`` is not an IP address."""
    address = parse_ip(text)
    return None if address is None else _scope(address, extra)


def is_public(text: object, extra: tuple[IPNetwork, ...] = ()) -> bool:
    return ip_scope(text, extra) == "public"


def is_internal(text: object, extra: tuple[IPNetwork, ...] = ()) -> bool:
    return ip_scope(text, extra) in ("internal", "loopback", "link-local")


__all__ = ["INTERNAL_NETWORKS", "ip_scope", "is_internal", "is_ip", "is_public", "parse_ip", "parse_networks"]
