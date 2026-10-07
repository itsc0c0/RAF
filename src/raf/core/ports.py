"""Port and protocol sets with exact interval arithmetic (union, intersection, difference).

Used wherever R$F reasons about network flows: policy evaluation, Ghost what-if edits of
reachability, and exposure explanations. Labels: ``any``, ``tcp/443``, ``tcp/1000-2000``,
``udp/53``, ``icmp``, ``tcp/all``; well-known service names (``ssh``, ``https`` ...) are accepted.
"""

from __future__ import annotations

import json
import re
from typing import Any

from raf.core.errors import InvalidInputError

PROTOCOLS = ("tcp", "udp", "icmp")
_PROTO_MAX = {"tcp": 65535, "udp": 65535, "icmp": 255}
ANY = "any"

_PORT_RE = re.compile(r"^(?:(tcp|udp|icmp|any)\s*/\s*)?(\d{1,5})(?:\s*-\s*(\d{1,5}))?$")
_WELL_KNOWN = {
    "ssh": "tcp/22",
    "rdp": "tcp/3389",
    "http": "tcp/80",
    "https": "tcp/443",
    "dns": "udp/53",
    "ldap": "tcp/389",
    "ldaps": "tcp/636",
    "smb": "tcp/445",
    "postgres": "tcp/5432",
    "mysql": "tcp/3306",
    "openvpn": "udp/1194",
    "winrm": "tcp/5985",
}


# --------------------------------------------------------------------------- ports


class PortSet:
    """An immutable set of (protocol, port) values stored as merged inclusive ranges."""

    __slots__ = ("ranges",)

    def __init__(self, ranges: dict[str, list[tuple[int, int]]] | None = None) -> None:
        merged: dict[str, list[tuple[int, int]]] = {}
        for proto, items in (ranges or {}).items():
            spans = sorted((lo, hi) for lo, hi in items if lo <= hi)
            out: list[tuple[int, int]] = []
            for lo, hi in spans:
                if out and lo <= out[-1][1] + 1:
                    out[-1] = (out[-1][0], max(out[-1][1], hi))
                else:
                    out.append((lo, hi))
            if out:
                merged[proto] = out
        self.ranges = merged

    @classmethod
    def everything(cls) -> PortSet:
        return cls({p: [(0, _PROTO_MAX[p])] for p in PROTOCOLS})

    @classmethod
    def empty(cls) -> PortSet:
        return cls({})

    @classmethod
    def parse(cls, values: list[str]) -> PortSet:
        result: dict[str, list[tuple[int, int]]] = {}
        for value in values:
            text = value.strip().lower()
            if text in (ANY, "*", "all"):
                return cls.everything()
            if text in PROTOCOLS:
                result.setdefault(text, []).append((0, _PROTO_MAX[text]))
                continue
            text = _WELL_KNOWN.get(text, text)
            match = _PORT_RE.match(text)
            if not match:
                raise InvalidInputError(
                    f"Invalid port specification '{value}'.",
                    hint="Use any, tcp/443, udp/53, tcp/1000-2000, icmp or a service name.",
                )
            proto = match.group(1) or "tcp"
            lo = int(match.group(2))
            hi = int(match.group(3) or lo)
            if hi < lo or hi > 65535:
                raise InvalidInputError(f"Invalid port range '{value}'.")
            for p in PROTOCOLS if proto == ANY else (proto,):
                result.setdefault(p, []).append((lo, min(hi, _PROTO_MAX[p])))
        return cls(result)

    def is_empty(self) -> bool:
        return not self.ranges

    def is_everything(self) -> bool:
        return self.subtract_from(PortSet.everything()).is_empty()

    def size(self) -> int:
        return sum(hi - lo + 1 for spans in self.ranges.values() for lo, hi in spans)

    def union(self, other: PortSet) -> PortSet:
        combined = {
            p: list(self.ranges.get(p, [])) + list(other.ranges.get(p, []))
            for p in set(self.ranges) | set(other.ranges)
        }
        return PortSet(combined)

    def intersect(self, other: PortSet) -> PortSet:
        result: dict[str, list[tuple[int, int]]] = {}
        for proto in set(self.ranges) & set(other.ranges):
            for alo, ahi in self.ranges[proto]:
                for blo, bhi in other.ranges[proto]:
                    lo, hi = max(alo, blo), min(ahi, bhi)
                    if lo <= hi:
                        result.setdefault(proto, []).append((lo, hi))
        return PortSet(result)

    def subtract(self, other: PortSet) -> PortSet:
        result: dict[str, list[tuple[int, int]]] = {}
        for proto, spans in self.ranges.items():
            cuts = other.ranges.get(proto, [])
            for lo, hi in spans:
                pieces = [(lo, hi)]
                for clo, chi in cuts:
                    nxt = []
                    for plo, phi in pieces:
                        if chi < plo or clo > phi:
                            nxt.append((plo, phi))
                            continue
                        if plo < clo:
                            nxt.append((plo, clo - 1))
                        if chi < phi:
                            nxt.append((chi + 1, phi))
                    pieces = nxt
                result.setdefault(proto, []).extend(pieces)
        return PortSet(result)

    def subtract_from(self, other: PortSet) -> PortSet:
        return other.subtract(self)

    def covers(self, other: PortSet) -> bool:
        return other.subtract(self).is_empty()

    def overlaps(self, other: PortSet) -> bool:
        return not self.intersect(other).is_empty()

    def labels(self) -> list[str]:
        if self.is_empty():
            return []
        if self.is_everything():
            return [ANY]
        out = []
        for proto in PROTOCOLS:
            for lo, hi in self.ranges.get(proto, []):
                if proto == "icmp" and (lo, hi) == (0, 255):
                    out.append("icmp")
                elif (lo, hi) == (0, _PROTO_MAX[proto]):
                    out.append(f"{proto}/all")
                else:
                    out.append(f"{proto}/{lo}" if lo == hi else f"{proto}/{lo}-{hi}")
        return out

    def __eq__(self, other: object) -> bool:
        return isinstance(other, PortSet) and self.ranges == other.ranges

    def __hash__(self) -> int:
        return hash(json.dumps(self.ranges, sort_keys=True))

    def __repr__(self) -> str:
        return f"PortSet({', '.join(self.labels()) or 'empty'})"


def normalize_ports(values: Any) -> list[str]:
    if values is None or values == "":
        return [ANY]
    items = [values] if isinstance(values, str | int) else list(values)
    labels = PortSet.parse([str(v) for v in items]).labels()
    return labels or [ANY]


def remaining_ports(have: list[str], remove: list[str]) -> list[str]:
    """Labels of ``have`` minus ``remove`` (empty list when nothing is left)."""
    return PortSet.parse(have).subtract(PortSet.parse(remove)).labels()
