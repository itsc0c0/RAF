"""Packet filters for ``raf protocol inspect`` (and the API): protocol, host, port, flow and time window."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from raf.core.errors import InvalidInputError
from raf.core.timeutil import format_ts
from raf.products.protocol.model import DecodedPacket, datetime_to_ns, ns_to_datetime

#: protocol keys accepted by ``--protocol`` (``ip`` is IPv4, ``icmp`` matches ICMP and ICMPv6)
PROTOCOLS = ("eth", "vlan", "sll", "ip", "ipv6", "tcp", "udp", "icmp", "icmpv6", "dns", "http", "tls")
_ALIASES = {"ethernet": "eth", "ipv4": "ip", "802.1q": "vlan", "https": "tls", "ssl": "tls"}


@dataclass(frozen=True, slots=True)
class PacketFilter:
    protocol: str | None = None
    host: str | None = None
    port: int | None = None
    flow_id: int | None = None
    start_ns: int | None = None
    end_ns: int | None = None

    @classmethod
    def build(
        cls,
        *,
        protocol: str | None = None,
        host: str | None = None,
        port: int | None = None,
        flow_id: int | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> PacketFilter:
        """Validate user input (CLI options or API parameters) into a filter."""
        start_ns = datetime_to_ns(start) if start else None
        end_ns = datetime_to_ns(end) if end else None
        if start_ns is not None and end_ns is not None and start_ns > end_ns:
            raise InvalidInputError("The time window is empty: --from is after --to.")
        if port is not None and not 0 <= port <= 65535:
            raise InvalidInputError(f"Port {port} is out of range.", hint="Ports are 0-65535.")
        if flow_id is not None and flow_id < 1:
            raise InvalidInputError("Flow IDs start at 1.", hint="List them with: raf protocol flows <file>")
        return cls(_protocol(protocol), _host(host), port, flow_id, start_ns, end_ns)

    @property
    def active(self) -> bool:
        return any(
            v is not None for v in (self.protocol, self.host, self.port, self.flow_id, self.start_ns, self.end_ns)
        )

    def matches(self, pkt: DecodedPacket, flow_id: int | None) -> bool:
        if self.protocol is not None and not self._protocol_matches(pkt):
            return False
        if self.host is not None and self.host not in (pkt.src_ip, pkt.dst_ip):
            return False
        if self.port is not None and self.port not in (pkt.src_port, pkt.dst_port):
            return False
        if self.flow_id is not None and flow_id != self.flow_id:
            return False
        return self._in_window(pkt.timestamp_ns)

    def _protocol_matches(self, pkt: DecodedPacket) -> bool:
        if self.protocol == "icmp":
            return "icmp" in pkt.protocols or "icmpv6" in pkt.protocols
        return self.protocol in pkt.protocols

    def _in_window(self, timestamp: int | None) -> bool:
        if self.start_ns is None and self.end_ns is None:
            return True
        if timestamp is None:
            return False
        if self.start_ns is not None and timestamp < self.start_ns:
            return False
        return self.end_ns is None or timestamp <= self.end_ns

    def describe(self) -> list[str]:
        terms = []
        if self.protocol:
            terms.append(f"protocol {self.protocol}")
        if self.host:
            terms.append(f"host {self.host}")
        if self.port is not None:
            terms.append(f"port {self.port}")
        if self.flow_id is not None:
            terms.append(f"flow {self.flow_id}")
        if self.start_ns is not None:
            terms.append(f"from {format_ts(ns_to_datetime(self.start_ns))}")
        if self.end_ns is not None:
            terms.append(f"to {format_ts(ns_to_datetime(self.end_ns))}")
        return terms

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol": self.protocol,
            "host": self.host,
            "port": self.port,
            "flow": self.flow_id,
            "from": format_ts(ns_to_datetime(self.start_ns)),
            "to": format_ts(ns_to_datetime(self.end_ns)),
        }


def _protocol(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    key = value.strip().lower()
    key = _ALIASES.get(key, key)
    if key not in PROTOCOLS:
        raise InvalidInputError(f"Unknown protocol '{value}'.", hint="Use one of: " + ", ".join(PROTOCOLS))
    return key


def _host(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    try:
        return ipaddress.ip_address(value.strip().strip("[]")).compressed
    except ValueError:
        raise InvalidInputError(
            f"'{value}' is not an IP address.",
            hint="Captures contain addresses, not names: pass an IPv4 or IPv6 address (DNS answers are in inspect).",
        ) from None
