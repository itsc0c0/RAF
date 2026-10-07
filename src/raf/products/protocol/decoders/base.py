"""Shared decoder primitives: bounds-checked reading, safe text and address formatting."""

from __future__ import annotations

import ipaddress
import struct

from raf.core.errors import InvalidInputError
from raf.products.protocol.model import DecodedPacket, Layer

_U16 = struct.Struct("!H")
_U32 = struct.Struct("!I")


class DecodeError(InvalidInputError):
    """Truncated or inconsistent protocol data. Decoders catch it and mark their layer malformed."""

    code = "raf.protocol.malformed"


class Cursor:
    """Sequential, bounds-checked reads over ``data[pos:end]`` (network byte order)."""

    __slots__ = ("_data", "_end", "pos")

    def __init__(self, data: bytes, pos: int = 0, end: int | None = None) -> None:
        self._data = data
        self._end = len(data) if end is None else max(0, min(end, len(data)))
        self.pos = max(0, min(pos, self._end))

    @property
    def remaining(self) -> int:
        return self._end - self.pos

    @property
    def end(self) -> int:
        return self._end

    def _advance(self, size: int, what: str) -> int:
        start = self.pos
        if size < 0 or start + size > self._end:
            raise self._truncated(size, what)
        self.pos = start + size
        return start

    def _truncated(self, size: int, what: str) -> DecodeError:
        left = self._end - self.pos
        return DecodeError(f"{what} is truncated (needs {size} byte{'s' * (size != 1)}, {left} left)")

    # u8 / u16 inline the bounds check: they are the hottest calls of the dissector
    def u8(self, what: str) -> int:
        start = self.pos
        if start >= self._end:
            raise self._truncated(1, what)
        self.pos = start + 1
        return self._data[start]

    def u16(self, what: str) -> int:
        start = self.pos
        if start + 2 > self._end:
            raise self._truncated(2, what)
        self.pos = start + 2
        value: int = _U16.unpack_from(self._data, start)[0]
        return value

    def u24(self, what: str) -> int:
        start = self._advance(3, what)
        return int.from_bytes(self._data[start : start + 3], "big")

    def u32(self, what: str) -> int:
        value: int = _U32.unpack_from(self._data, self._advance(4, what))[0]
        return value

    def take(self, size: int, what: str) -> bytes:
        start = self._advance(size, what)
        return self._data[start : start + size]

    def skip(self, size: int, what: str) -> None:
        self._advance(size, what)

    def rest(self) -> bytes:
        data = self._data[self.pos : self._end]
        self.pos = self._end
        return data

    def sub(self, size: int, what: str) -> Cursor:
        """A cursor over the next ``size`` bytes; this cursor moves past them."""
        start = self._advance(size, what)
        return Cursor(self._data, start, start + size)

    def sub_available(self, size: int) -> Cursor:
        """Like :meth:`sub` but tolerates truncation: covers at most the bytes that exist."""
        start = self.pos
        stop = min(self._end, start + max(size, 0))
        self.pos = stop
        return Cursor(self._data, start, stop)


def mark_malformed(layer: Layer, pkt: DecodedPacket, reason: str) -> Layer:
    layer.malformed = reason
    pkt.note_malformed(layer.name, reason)
    return layer


# --------------------------------------------------------------------------- safe text

_ESCAPES = {0x5C: "\\\\"}


def printable(data: bytes, limit: int = 256) -> str:
    """Render untrusted bytes as safe text: printable ASCII is kept, everything else becomes ``\\xNN``.

    Control characters (including terminal escape sequences) can therefore never reach
    a terminal or log. The result is cut at ``limit`` bytes of input (marked with ``…``).
    """
    chunk = data[:limit]
    if chunk.isascii():
        text = chunk.decode("ascii")
        if text.isprintable() and "\\" not in text:
            return text + ("…" if len(data) > limit else "")
    parts = []
    for byte in chunk:
        if byte in _ESCAPES:
            parts.append(_ESCAPES[byte])
        elif 0x20 <= byte < 0x7F:
            parts.append(chr(byte))
        else:
            parts.append(f"\\x{byte:02x}")
    return "".join(parts) + ("…" if len(data) > limit else "")


def printable_text(text: str, limit: int = 256) -> str:
    """Sanitize an already-decoded string the same way as :func:`printable`."""
    return printable(text.encode("utf-8", "replace"), limit)


# --------------------------------------------------------------------------- addresses


def mac_text(data: bytes) -> str:
    return data.hex(":")


def ipv4_text(data: bytes) -> str:
    return f"{data[0]}.{data[1]}.{data[2]}.{data[3]}"


def ipv6_text(data: bytes) -> str:
    return ipaddress.IPv6Address(data).compressed


def hex16(value: int) -> str:
    return f"0x{value:04x}"


def label(table: dict[int, str], value: int, *, width: int = 0) -> str:
    """``name (value)`` for known values, ``unknown (value)`` otherwise."""
    shown = f"0x{value:0{width}x}" if width else str(value)
    name = table.get(value)
    return f"{name} ({shown})" if name else f"unknown ({shown})"
