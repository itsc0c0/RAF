"""HTTP/1.x request and response heads found at the start of a single TCP segment (no reassembly)."""

from __future__ import annotations

import re

from raf.products.protocol.decoders.base import mark_malformed, printable
from raf.products.protocol.model import DecodedPacket, HttpMessage, Layer

MAX_HEAD = 8192  # bytes of the segment examined
MAX_HEADERS = 100
METHODS = frozenset({b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH", b"CONNECT", b"TRACE"})

_LINE_SPLIT = re.compile(rb"\r?\n")
_VERSION = re.compile(rb"^HTTP/\d\.\d$")
_STATUS = re.compile(rb"^\d{3}$")

_HEADER_EXPLANATIONS = {
    "host": ("host", "Host header: the site (virtual host) the client asks for"),
    "user-agent": ("user_agent", "User-Agent: client software as claimed by the client (trivially spoofed)"),
    "content-length": ("content_length", "Content-Length: body size in bytes as declared by the sender"),
    "content-type": ("content_type", "Content-Type: media type of the body"),
    "server": ("server", "Server: server software as claimed by the server"),
    "location": ("location", "Location: where a redirect points to"),
    "referer": ("referer", "Referer: page that linked to this request"),
}


def looks_like_http(payload: bytes) -> bool:
    if payload.startswith(b"HTTP/1."):
        return True
    space = payload.find(b" ", 0, 8)
    return space > 0 and payload[:space] in METHODS


def decode_http(payload: bytes, pkt: DecodedPacket) -> Layer:
    layer = Layer("HTTP")
    pkt.protocols.append("http")
    head = payload[:MAX_HEAD]
    end = head.find(b"\r\n\r\n")
    complete = end >= 0
    lines = _LINE_SPLIT.split(head[:end] if complete else head)
    message = _start_line(lines[0], layer, pkt)
    if message is None:
        return layer
    pkt.http = message
    _headers(lines[1 : MAX_HEADERS + 1], layer, message)
    if complete:
        layer.add("body_bytes", len(payload) - end - 4, "Body bytes present in this segment (bodies are not decoded)")
    else:
        layer.add(
            "headers_complete",
            False,
            "The header block does not end in this segment; R$F does not reassemble TCP streams",
        )
    layer.summary = _summary(message)
    return layer


def _start_line(line: bytes, layer: Layer, pkt: DecodedPacket) -> HttpMessage | None:
    parts = line.split(b" ", 2)
    if line.startswith(b"HTTP/"):
        if len(parts) < 2 or not _VERSION.match(parts[0]) or not _STATUS.match(parts[1]):
            mark_malformed(layer, pkt, "status line is not 'HTTP/x.y CODE REASON'")
            return None
        message = HttpMessage(
            is_request=False,
            version=printable(parts[0]),
            status=int(parts[1]),
            reason=printable(parts[2], 128) if len(parts) > 2 else "",
        )
        layer.add("version", message.version, "Protocol version used by the server")
        layer.add(
            "status", message.status, "Status code: 2xx success, 3xx redirect, 4xx client error, 5xx server error"
        )
        layer.add("reason", message.reason, "Reason phrase (free text, informational only)")
        return message
    if len(parts) != 3 or parts[0] not in METHODS or not _VERSION.match(parts[2]):
        mark_malformed(layer, pkt, "request line is not 'METHOD TARGET HTTP/x.y'")
        return None
    message = HttpMessage(
        is_request=True,
        version=printable(parts[2]),
        method=parts[0].decode("ascii"),
        target=printable(parts[1], 2048),
    )
    layer.add("method", message.method, "Request method: GET reads, POST/PUT send data, CONNECT opens a tunnel")
    layer.add("target", message.target, "Request target: path and query (or a full URL when sent to a proxy)")
    layer.add("version", message.version, "Protocol version requested by the client")
    return message


def _headers(lines: list[bytes], layer: Layer, message: HttpMessage) -> None:
    count = 0
    for line in lines:
        name, sep, value = line.partition(b":")
        if not sep or not name or name != name.strip():
            continue
        count += 1
        known = _HEADER_EXPLANATIONS.get(name.decode("latin-1").lower())
        if known is None:
            continue
        key, explanation = known
        text = printable(value.strip(), 1024)
        layer.add(key, text, explanation)
        if key in ("host", "user_agent", "content_length", "server") and getattr(message, key) is None:
            setattr(message, key, text)
    layer.add("header_count", count, "Header lines seen in this segment")


def _summary(message: HttpMessage) -> str:
    if message.is_request:
        host = f" (Host: {message.host})" if message.host else ""
        return f"{message.method} {message.target} {message.version}{host}"
    return f"{message.version} {message.status} {message.reason}".rstrip()
