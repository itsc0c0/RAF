"""Decoded packet model: layers made of explained fields, plus the facts analysis needs.

A decoded packet is a tree of :class:`Layer` objects (Ethernet carries IPv4,
IPv4 carries TCP, TCP carries one or more TLS records ...). Every field keeps a
short explanation so the output teaches what the bytes mean. Decoders also
record a flat set of facts (addresses, ports, flags, DNS/HTTP/TLS metadata) on
:class:`DecodedPacket` so flows and summaries never re-walk the tree.

Every text value in this model has already been sanitized: bytes taken from a
packet never reach a terminal or a JSON document unescaped.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

FieldValue = str | int | float | bool | None | list[str]

_NS = 1_000_000_000


@dataclass(slots=True)
class Field:
    """One decoded header field with a short, human-readable explanation."""

    name: str
    value: FieldValue
    explanation: str = ""

    def to_dict(self) -> dict[str, Any]:
        value = list(self.value) if isinstance(self.value, list) else self.value
        return {"name": self.name, "value": value, "explanation": self.explanation}

    def display(self) -> str:
        if isinstance(self.value, list):
            return ", ".join(self.value) if self.value else "-"
        if isinstance(self.value, bool):
            return "yes" if self.value else "no"
        return "-" if self.value is None else str(self.value)


@dataclass(slots=True)
class Layer:
    """A protocol layer: its fields, the layers it carries and why decoding stopped (``malformed``)."""

    name: str
    fields: list[Field] = field(default_factory=list)
    children: list[Layer] = field(default_factory=list)
    malformed: str | None = None
    summary: str = ""

    def add(self, name: str, value: FieldValue, explanation: str = "") -> None:
        self.fields.append(Field(name, value, explanation))

    def value(self, name: str) -> FieldValue:
        for item in self.fields:
            if item.name == name:
                return item.value
        return None

    def walk(self) -> Iterator[Layer]:
        """Depth-first iteration over this layer and everything it carries."""
        stack = [self]
        while stack:
            layer = stack.pop()
            yield layer
            stack.extend(reversed(layer.children))

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "summary": self.summary,
            "malformed": self.malformed,
            "fields": [f.to_dict() for f in self.fields],
            "children": [c.to_dict() for c in self.children],
        }


def tree_lines(root: Layer) -> list[str]:
    """Render a layer tree with box-drawing guides::

    Ethernet
    └── IPv4
        └── TCP
            └── TLS
    """
    lines = [_tree_label(root)]
    _tree_branch(root.children, "", lines)
    return lines


def _tree_branch(children: list[Layer], prefix: str, lines: list[str]) -> None:
    for index, child in enumerate(children):
        last = index == len(children) - 1
        lines.append(prefix + ("└── " if last else "├── ") + _tree_label(child))
        _tree_branch(child.children, prefix + ("    " if last else "│   "), lines)


def _tree_label(layer: Layer) -> str:
    label = layer.name
    if layer.summary:
        label += f"  {layer.summary}"
    if layer.malformed:
        label += f"  [malformed: {layer.malformed}]"
    return label


# --------------------------------------------------------------------------- application facts


@dataclass(slots=True)
class DnsAnswer:
    name: str
    rtype: str
    ttl: int
    data: str


@dataclass(slots=True)
class DnsMessage:
    transaction_id: int
    is_response: bool
    opcode: str
    rcode: str
    truncated: bool = False
    questions: list[tuple[str, str]] = field(default_factory=list)  # (name, type)
    answers: list[DnsAnswer] = field(default_factory=list)


@dataclass(slots=True)
class HttpMessage:
    is_request: bool
    version: str
    method: str | None = None
    target: str | None = None
    status: int | None = None
    reason: str | None = None
    host: str | None = None
    user_agent: str | None = None
    content_length: str | None = None
    server: str | None = None


@dataclass(slots=True)
class TlsHello:
    """Facts from a ClientHello (``client=True``) or ServerHello."""

    client: bool
    legacy_version: str
    versions: list[str] = field(default_factory=list)  # offered (client) or selected (server)
    sni: str | None = None
    alpn: list[str] = field(default_factory=list)
    cipher_suites: list[str] = field(default_factory=list)  # offered (client) or selected (server)
    encrypted_client_hello: bool = False
    hello_retry_request: bool = False

    @property
    def version(self) -> str:
        """The negotiated (server) or highest offered (client) version."""
        return self.versions[0] if self.versions else self.legacy_version


# --------------------------------------------------------------------------- packets


@dataclass(frozen=True, slots=True)
class RawPacket:
    """One captured packet as stored in the file (before decoding)."""

    number: int  # 1-based position in the capture
    timestamp_ns: int | None  # None for pcapng simple packet blocks (no timestamp)
    captured_length: int
    original_length: int
    link_type: int
    interface: int
    data: bytes


@dataclass(slots=True)
class DecodedPacket:
    number: int
    timestamp_ns: int | None
    captured_length: int
    original_length: int
    interface: int
    link_type: int
    root: Layer | None = None
    protocols: list[str] = field(default_factory=list)
    ip_version: int | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    ip_proto: int | None = None
    ip_bytes: int = 0
    ip_id: int | None = None
    fragment_offset: int = 0
    more_fragments: bool = False
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: int | None = None
    icmp_type: int | None = None
    payload_length: int = 0
    dns: DnsMessage | None = None
    http: HttpMessage | None = None
    tls: list[TlsHello] = field(default_factory=list)
    malformed: list[str] = field(default_factory=list)
    internal_error: str | None = None

    @property
    def timestamp(self) -> datetime | None:
        return ns_to_datetime(self.timestamp_ns)

    @property
    def is_fragment(self) -> bool:
        return self.fragment_offset > 0 or self.more_fragments

    @property
    def info(self) -> str:
        """One-line description from the innermost layer (or its sibling records, e.g. several TLS records)."""
        layer = self.root
        if layer is None:
            return ""
        while len(layer.children) == 1:
            layer = layer.children[0]
        if len(layer.children) > 1:
            first = layer.children[0].name
            return f"{first} " + "; ".join(_layer_info(child) for child in layer.children)
        return f"{layer.name} {_layer_info(layer)}".strip()

    def note_malformed(self, layer: str, reason: str) -> None:
        if len(self.malformed) < 16:
            self.malformed.append(reason if reason.startswith(layer) else f"{layer}: {reason}")


def _layer_info(layer: Layer) -> str:
    text = layer.summary or ("" if layer.malformed else layer.name)
    return f"{text} [malformed]".strip() if layer.malformed else text


def endpoint_text(ip: str, port: int | None) -> str:
    """``ip:port`` (IPv6 addresses in brackets), or just the address when there is no port."""
    if port is None:
        return ip
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def ns_to_datetime(value: int | None) -> datetime | None:
    """Convert integer nanoseconds since the epoch to an aware UTC datetime (None if unrepresentable)."""
    if value is None:
        return None
    seconds, rest = divmod(value, _NS)
    try:
        return datetime.fromtimestamp(seconds, tz=UTC).replace(microsecond=rest // 1000)
    except (OverflowError, OSError, ValueError):
        return None


def datetime_to_ns(value: datetime) -> int:
    """Exact integer nanoseconds since the epoch (naive values are taken as UTC)."""
    aware = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    delta = aware - _EPOCH
    return (delta.days * 86_400 + delta.seconds) * _NS + delta.microseconds * 1000


_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
