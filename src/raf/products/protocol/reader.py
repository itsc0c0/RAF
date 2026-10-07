"""Streaming readers for libpcap (classic) and pcapng capture files.

Both readers pull exact-size chunks from a byte stream, so memory stays bounded
by the largest accepted block regardless of the file size. Every length read
from the file is checked before it is used. A truncated or corrupt file ends the
iteration with a warning instead of an exception; only input that is not a
capture at all raises :class:`~raf.core.errors.InvalidInputError`.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any, Protocol

from raf.core.errors import InvalidInputError
from raf.products.protocol.decoders.base import printable
from raf.products.protocol.decoders.tables import LINK_TYPES
from raf.products.protocol.model import RawPacket

DEFAULT_MAX_PACKETS = 1_000_000
MAX_CAPLEN = 262_144  # largest packet accepted (libpcap's MAXIMUM_SNAPLEN)
DEFAULT_MAX_FLOWS = 100_000
DEFAULT_MAX_RECORDS = 100_000  # DNS transactions, HTTP requests and TLS handshakes kept per capture
CHUNK = 1 << 20

PCAP_MAGICS: dict[bytes, tuple[str, int, str]] = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000, "microseconds"),
    b"\xa1\xb2\xc3\xd4": (">", 1_000, "microseconds"),
    b"\x4d\x3c\xb2\xa1": ("<", 1, "nanoseconds"),
    b"\xa1\xb2\x3c\x4d": (">", 1, "nanoseconds"),
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
_BYTE_ORDER_MAGICS = {b"\x4d\x3c\x2b\x1a": "<", b"\x1a\x2b\x3c\x4d": ">"}

_IDB, _OPB, _SPB, _EPB = 1, 2, 3, 6
_PACKET_BLOCKS = frozenset({_OPB, _SPB, _EPB})


class ByteSource(Protocol):
    def read(self, size: int = -1, /) -> bytes: ...


@dataclass(frozen=True, slots=True)
class CaptureLimits:
    max_packets: int = DEFAULT_MAX_PACKETS
    max_caplen: int = MAX_CAPLEN
    max_flows: int = DEFAULT_MAX_FLOWS
    max_records: int = DEFAULT_MAX_RECORDS


@dataclass(slots=True)
class InterfaceInfo:
    index: int
    link_type: int
    snaplen: int
    ts_base: int = 10
    ts_exponent: int = 6
    ts_offset_s: int = 0
    name: str | None = None

    @property
    def resolution(self) -> str:
        named = {(10, 0): "seconds", (10, 3): "milliseconds", (10, 6): "microseconds", (10, 9): "nanoseconds"}
        return named.get((self.ts_base, self.ts_exponent), f"{self.ts_base}^-{self.ts_exponent} s")

    def ticks_to_ns(self, ticks: int) -> int:
        if self.ts_base == 10:
            exponent = self.ts_exponent
            nanos = int(ticks * 10 ** (9 - exponent)) if exponent <= 9 else int(ticks // 10 ** (exponent - 9))
        else:
            nanos = (ticks * 1_000_000_000) >> self.ts_exponent
        return nanos + self.ts_offset_s * 1_000_000_000

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "link_type": self.link_type,
            "link_type_name": LINK_TYPES.get(self.link_type, "unknown"),
            "snaplen": self.snaplen,
            "timestamp_resolution": self.resolution,
            "name": self.name,
        }


@dataclass(slots=True)
class CaptureInfo:
    format: str
    version: str = ""
    byte_order: str = ""
    snaplen: int | None = None
    interfaces: list[InterfaceInfo] = field(default_factory=list)
    sections: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "version": self.version,
            "byte_order": self.byte_order,
            "snaplen": self.snaplen,
            "sections": self.sections,
            "interfaces": [i.to_dict() for i in self.interfaces],
        }


class Diagnostics:
    """Bounded list of warnings (a hostile file must not be able to exhaust memory with them)."""

    def __init__(self, limit: int = 100) -> None:
        self._limit = limit
        self._items: list[str] = []
        self._dropped = 0

    def add(self, message: str) -> None:
        if len(self._items) < self._limit:
            self._items.append(message)
        else:
            self._dropped += 1

    def __len__(self) -> int:
        return len(self._items) + self._dropped

    def to_list(self) -> list[str]:
        extra = [f"... {self._dropped:,} more warnings not shown"] if self._dropped else []
        return self._items + extra


def detect_format(head: bytes) -> str | None:
    """``"pcap"``, ``"pcapng"`` or None, from the first bytes of a file."""
    if head[:4] in PCAP_MAGICS:
        return "pcap"
    if head[:4] == PCAPNG_MAGIC:
        return "pcapng"
    return None


def sniff_capture(head: bytes) -> str | None:
    """``pcap`` / ``pcapng`` when the first bytes are a capture file header (magic plus a sane next field)."""
    kind = detect_format(head)
    if kind == "pcap" and len(head) >= 6:
        major: int = struct.unpack(PCAP_MAGICS[head[:4]][0] + "H", head[4:6])[0]
        return kind if major == 2 else None
    if kind == "pcapng" and len(head) >= 12:
        return kind if head[8:12] in _BYTE_ORDER_MAGICS else None
    return kind


def read_exact(stream: ByteSource, size: int) -> bytes:
    """Read ``size`` bytes (fewer only at end of file)."""
    if size <= 0:
        return b""
    parts: list[bytes] = []
    remaining = size
    while remaining > 0:
        chunk = stream.read(min(remaining, CHUNK))
        if not chunk:
            break
        parts.append(chunk)
        remaining -= len(chunk)
    return b"".join(parts)


def discard(stream: ByteSource, size: int) -> int:
    """Skip ``size`` bytes without holding them in memory; returns how many were skipped."""
    skipped = 0
    while skipped < size:
        chunk = stream.read(min(size - skipped, CHUNK))
        if not chunk:
            break
        skipped += len(chunk)
    return skipped


class CaptureReader:
    """Base class: iterate :meth:`packets` once; inspect :attr:`warnings` afterwards."""

    def __init__(self, stream: ByteSource, limits: CaptureLimits, info: CaptureInfo) -> None:
        self._stream = stream
        self.limits = limits
        self.info = info
        self.diagnostics = Diagnostics()
        self.truncated = False
        self.limit_reached = False

    @property
    def warnings(self) -> list[str]:
        return self.diagnostics.to_list()

    def packets(self) -> Iterator[RawPacket]:
        raise NotImplementedError

    def _stop(self, message: str) -> None:
        self.truncated = True
        self.diagnostics.add(message)

    def _limit(self) -> None:
        self.limit_reached = True
        self.diagnostics.add(
            f"stopped after {self.limits.max_packets:,} packets (packet limit); the rest of the capture was not read"
        )


def open_capture(stream: ByteSource, limits: CaptureLimits | None = None) -> CaptureReader:
    """Return the reader matching the file's magic bytes."""
    limits = limits or CaptureLimits()
    magic = read_exact(stream, 4)
    if magic in PCAP_MAGICS:
        return PcapReader(stream, limits, magic)
    if magic == PCAPNG_MAGIC:
        return PcapngReader(stream, limits)
    raise InvalidInputError(
        "This is not a pcap or pcapng capture." if magic else "The capture file is empty.",
        reason=f"unrecognized magic bytes 0x{magic.hex()}" if magic else None,
        hint="R$F Protocol reads libpcap (.pcap, .cap) and pcapng (.pcapng) files.",
    )


# --------------------------------------------------------------------------- classic pcap


class PcapReader(CaptureReader):
    def __init__(self, stream: ByteSource, limits: CaptureLimits, magic: bytes) -> None:
        order, self._fraction_ns, resolution = PCAP_MAGICS[magic]
        byte_order = "little-endian" if order == "<" else "big-endian"
        super().__init__(stream, limits, CaptureInfo(format="pcap", byte_order=byte_order, sections=1))
        self._record = struct.Struct(order + "IIII")
        self._link_type = -1
        header = read_exact(stream, 20)
        if len(header) < 20:
            self._stop(f"the file header is truncated ({4 + len(header)} of 24 bytes); no packets could be read")
            return
        major, minor, _zone, _sigfigs, snaplen, network = struct.unpack(order + "HHiIII", header)
        self._link_type = network & 0x03FFFFFF
        self.info.version, self.info.snaplen = f"{major}.{minor}", snaplen
        exponent = 6 if resolution == "microseconds" else 9
        self.info.interfaces = [InterfaceInfo(0, self._link_type, snaplen, ts_exponent=exponent)]
        if major != 2:
            self.diagnostics.add(f"unusual pcap version {major}.{minor}; records were read as version 2.4")

    def packets(self) -> Iterator[RawPacket]:
        if self._link_type < 0:
            return
        fraction_limit = 1_000_000_000 // self._fraction_ns
        number = 0
        while True:
            header = read_exact(self._stream, 16)
            if not header:
                return
            if len(header) < 16:
                self._stop(f"the file ends inside the record header of packet {number + 1}")
                return
            if number >= self.limits.max_packets:
                self._limit()
                return
            seconds, fraction, captured, original = self._record.unpack(header)
            if captured > self.limits.max_caplen:
                self._stop(
                    f"packet {number + 1} claims {captured:,} captured bytes, above the {self.limits.max_caplen:,}-byte"
                    " limit; the file is probably corrupt and reading stopped there"
                )
                return
            data = read_exact(self._stream, captured)
            if len(data) < captured:
                self._stop(f"the file ends inside packet {number + 1} ({len(data)} of {captured} bytes present)")
                return
            number += 1
            if fraction >= fraction_limit:
                self.diagnostics.add(f"packet {number}: timestamp fraction {fraction} is out of range")
            timestamp = seconds * 1_000_000_000 + fraction * self._fraction_ns
            yield RawPacket(number, timestamp, captured, original, self._link_type, 0, data)


# --------------------------------------------------------------------------- pcapng

MAX_INTERFACES = 4096  # interface description blocks per section
_SHB, _SKIPPED = -1, -2  # sentinels: section header handled, oversized block skipped


class PcapngReader(CaptureReader):
    def __init__(self, stream: ByteSource, limits: CaptureLimits) -> None:
        super().__init__(stream, limits, CaptureInfo(format="pcapng"))
        self._order = "<"
        self._interfaces: list[InterfaceInfo] = []
        self._first = True
        self._max_block = limits.max_caplen + (1 << 20)

    def packets(self) -> Iterator[RawPacket]:
        number = 0
        while True:
            block = self._next_block()
            if block is None:
                return
            packet = self._packet(*block)
            if packet is None:
                continue
            if number >= self.limits.max_packets:
                self._limit()
                return
            number += 1
            timestamp, captured, original, interface, data = packet
            link_type = self._interfaces[interface].link_type
            yield RawPacket(number, timestamp, captured, original, link_type, interface, data)

    # ------------------------------------------------------------------ framing
    def _u32(self, raw: bytes) -> int:
        value: int = struct.unpack(self._order + "I", raw)[0]
        return value

    def _next_block(self) -> tuple[int, bytes] | None:
        if self._first:
            self._first = False
            return self._section_header()
        raw_type = read_exact(self._stream, 4)
        if not raw_type:
            return None
        if len(raw_type) < 4:
            self._stop("the file ends inside a block header")
            return None
        if raw_type == PCAPNG_MAGIC:
            return self._section_header()
        block_type = self._u32(raw_type)
        raw_length = read_exact(self._stream, 4)
        if len(raw_length) < 4:
            self._stop("the file ends inside a block header")
            return None
        total = self._u32(raw_length)
        if total < 12 or total % 4:
            self._stop(f"block of type 0x{block_type:08x} has an invalid length ({total}); reading stopped")
            return None
        body = self._body(block_type, total - 12)
        if body is None or not self._trailer(total):
            return None
        return (block_type, body) if body or total == 12 else (_SKIPPED, b"")

    def _section_header(self) -> tuple[int, bytes] | None:
        head = read_exact(self._stream, 8)
        if len(head) < 8:
            self._stop("the file ends inside a section header block")
            return None
        order = _BYTE_ORDER_MAGICS.get(head[4:8])
        if order is None:
            self._stop("section header block has an invalid byte-order magic; reading stopped")
            return None
        self._order = order
        total = self._u32(head[:4])
        if total < 28 or total % 4:
            self._stop(f"section header block has an invalid length ({total}); reading stopped")
            return None
        body = self._body(_SHB, total - 16)
        if body is None or not self._trailer(total):
            return None
        self._interfaces = []
        self.info.sections += 1
        if self.info.sections == 1:
            self.info.byte_order = "little-endian" if order == "<" else "big-endian"
            if len(body) >= 4:
                major, minor = struct.unpack(order + "HH", body[:4])
                self.info.version = f"{major}.{minor}"
        return _SHB, b""

    def _body(self, block_type: int, size: int) -> bytes | None:
        """The block body, ``b""`` when it was too large and skipped, None when the file ended."""
        if size <= self._max_block:
            body = read_exact(self._stream, size)
            if len(body) < size:
                self._stop(f"the file ends inside a block ({len(body)} of {size} bytes present)")
                return None
            return body
        if block_type in _PACKET_BLOCKS:
            self.diagnostics.add(
                f"skipped a {size:,}-byte packet block (larger than the {self._max_block:,}-byte limit)"
            )
        if discard(self._stream, size) < size:
            self._stop("the file ends inside an oversized block")
            return None
        return b""

    def _trailer(self, total: int) -> bool:
        raw = read_exact(self._stream, 4)
        if len(raw) < 4:
            self._stop("the file ends before a block's trailing length")
            return False
        if self._u32(raw) != total:
            self._stop("a block's trailing length does not match its header (corrupt file); reading stopped")
            return False
        return True

    # ------------------------------------------------------------------ block bodies
    def _packet(self, block_type: int, body: bytes) -> tuple[int | None, int, int, int, bytes] | None:
        if block_type == _IDB:
            self._interface(body)
            return None
        if block_type == _EPB:
            return self._enhanced(body, "IIIII", "enhanced packet block")
        if block_type == _OPB:
            return self._enhanced(body, "HHIIII", "obsolete packet block")
        if block_type == _SPB:
            return self._simple(body)
        return None  # section headers, name resolution, statistics, custom and unknown blocks

    def _interface(self, body: bytes) -> None:
        if len(self._interfaces) >= MAX_INTERFACES:
            self.diagnostics.add(f"more than {MAX_INTERFACES} interfaces in one section; extra interfaces ignored")
            return
        iface = InterfaceInfo(index=len(self._interfaces), link_type=-1, snaplen=0)
        self._interfaces.append(iface)
        if len(body) < 8:
            self.diagnostics.add(
                f"interface {iface.index}: description block is too short; its packets are not decoded"
            )
        else:
            iface.link_type, _reserved, iface.snaplen = struct.unpack(self._order + "HHI", body[:8])
            self._interface_options(body[8:], iface)
        if len(self.info.interfaces) < 64:
            self.info.interfaces.append(iface)
        if self.info.snaplen is None:
            self.info.snaplen = iface.snaplen

    def _interface_options(self, options: bytes, iface: InterfaceInfo) -> None:
        pos = 0
        while pos + 4 <= len(options):
            code, length = struct.unpack(self._order + "HH", options[pos : pos + 4])
            value = options[pos + 4 : pos + 4 + length]
            if code == 0 or len(value) < length:
                return
            pos += 4 + ((length + 3) & ~3)
            if code == 2:
                iface.name = printable(value.rstrip(b"\x00"), 64)
            elif code == 9 and length >= 1:
                iface.ts_base, iface.ts_exponent = (2, value[0] & 0x7F) if value[0] & 0x80 else (10, value[0])
            elif code == 14 and length == 8:
                iface.ts_offset_s = struct.unpack(self._order + "q", value)[0]

    def _enhanced(self, body: bytes, layout: str, what: str) -> tuple[int | None, int, int, int, bytes] | None:
        if len(body) < 20:
            self.diagnostics.add(f"skipped an {what} shorter than its fixed header")
            return None
        fields: tuple[int, ...] = struct.unpack(self._order + layout, body[:20])
        interface, ts_high, ts_low, captured, original = fields[0], *fields[-4:]
        if not self._usable(interface, what):
            return None
        if captured > len(body) - 20 or captured > self.limits.max_caplen:
            self.diagnostics.add(f"skipped an {what} whose captured length ({captured:,}) is impossible or too large")
            return None
        timestamp = self._interfaces[interface].ticks_to_ns((ts_high << 32) | ts_low)
        return timestamp, captured, original, interface, body[20 : 20 + captured]

    def _simple(self, body: bytes) -> tuple[int | None, int, int, int, bytes] | None:
        if len(body) < 4 or not self._usable(0, "simple packet block"):
            return None
        original = self._u32(body[:4])
        captured = min(original, len(body) - 4, self.limits.max_caplen)
        snaplen = self._interfaces[0].snaplen
        if snaplen:
            captured = min(captured, snaplen)
        return None, captured, original, 0, body[4 : 4 + captured]

    def _usable(self, interface: int, what: str) -> bool:
        if interface >= len(self._interfaces):
            self.diagnostics.add(f"skipped a {what} that refers to undefined interface {interface}")
            return False
        return True
