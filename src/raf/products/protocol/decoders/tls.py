"""TLS record layer plus ClientHello / ServerHello metadata.

Only the clear-text parts of a handshake are decoded. Encrypted records are
labeled and counted; R$F never attempts to decrypt anything.
"""

from __future__ import annotations

from raf.products.protocol.decoders.base import Cursor, DecodeError, mark_malformed, printable
from raf.products.protocol.decoders.tables import (
    TLS_ALERT_LEVELS,
    TLS_ALERTS,
    TLS_CONTENT_TYPES,
    TLS_HANDSHAKE_TYPES,
    tls_cipher_name,
    tls_extension_name,
    tls_group_name,
    tls_version_name,
)
from raf.products.protocol.model import DecodedPacket, Layer, TlsHello

MAX_RECORDS = 16  # TLS records decoded per segment
MAX_RECORD_LENGTH = 16384 + 2048  # RFC 8446: TLSCiphertext.length must not exceed 2^14 + 256 (2048 in TLS 1.2)
MAX_LISTED = 32  # cipher suites / groups listed in a field
MAX_HANDSHAKES = 8

#: ServerHello.random of a HelloRetryRequest (RFC 8446, section 4.1.3)
HELLO_RETRY_RANDOM = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")


def looks_like_tls(payload: bytes) -> bool:
    return len(payload) >= 5 and payload[0] in TLS_CONTENT_TYPES and payload[1] == 3 and payload[2] <= 4


def decode_tls(payload: bytes, pkt: DecodedPacket) -> list[Layer]:
    """One layer per TLS record in the segment."""
    pkt.protocols.append("tls")
    layers: list[Layer] = []
    cur = Cursor(payload)
    while cur.remaining >= 5 and len(layers) < MAX_RECORDS:
        if not looks_like_tls(payload[cur.pos : cur.pos + 5]):
            break
        layers.append(_record(cur, pkt))
    if not layers:
        return [mark_malformed(Layer("TLS"), pkt, "segment does not start with a TLS record header")]
    if cur.remaining:
        layers[-1].add(
            "trailing_bytes",
            cur.remaining,
            "Bytes after the last decoded record (more records, a continuation, or not TLS)",
        )
    return layers


def _record(cur: Cursor, pkt: DecodedPacket) -> Layer:
    layer = Layer("TLS")
    content_type = cur.u8("TLS content type")
    version = cur.u16("TLS record version")
    length = cur.u16("TLS record length")
    type_name = TLS_CONTENT_TYPES.get(content_type, str(content_type))
    layer.add("content_type", f"{type_name} ({content_type})", "Record type: 22 handshake, 23 encrypted data, 21 alert")
    layer.add(
        "record_version",
        tls_version_name(version),
        "Record-layer version (legacy field: TLS 1.3 still writes TLS 1.0/1.2 here)",
    )
    layer.add("length", length, "Record length in bytes")
    body = cur.sub_available(length)
    layer.summary = type_name
    if length > MAX_RECORD_LENGTH:
        return mark_malformed(layer, pkt, f"record length {length} exceeds the TLS maximum of {MAX_RECORD_LENGTH}")
    if body.remaining < length:
        layer.add(
            "segment",
            f"{body.remaining} of {length} bytes",
            "The record continues in later TCP segments; R$F does not reassemble TCP streams",
        )
    try:
        _content(content_type, body, length, layer, pkt)
    except DecodeError as exc:
        mark_malformed(layer, pkt, exc.message)
    return layer


def _content(content_type: int, body: Cursor, length: int, layer: Layer, pkt: DecodedPacket) -> None:
    if content_type == 22:
        _handshakes(body, layer, pkt)
    elif content_type == 23:
        layer.summary = f"Application Data ({length} bytes, encrypted)"
        layer.add("payload", f"{length} bytes", "Encrypted application data; R$F never decrypts traffic")
    elif content_type == 21:
        if length == 2:
            level, description = body.u8("alert level"), body.u8("alert description")
            name = TLS_ALERTS.get(description, str(description))
            layer.add(
                "alert_level", TLS_ALERT_LEVELS.get(level, str(level)), "Alert level: fatal alerts end the session"
            )
            layer.add("alert", name, "Alert description: why the peer is complaining or closing")
            layer.summary = f"Alert {TLS_ALERT_LEVELS.get(level, str(level))} {name}"
        else:
            layer.summary = "Encrypted Alert"
            layer.add("payload", f"{length} bytes", "Alert sent after encryption started; content is not decrypted")
    elif content_type == 20:
        layer.summary = "ChangeCipherSpec"
        layer.add(
            "change_cipher_spec",
            True,
            "Signals that the sender's next records are encrypted (TLS 1.3 sends it only for compatibility)",
        )
    elif content_type == 24:
        _heartbeat(body, length, layer, pkt)


def _heartbeat(body: Cursor, length: int, layer: Layer, pkt: DecodedPacket) -> None:
    layer.summary = "Heartbeat"
    if body.remaining < 3:
        return
    kind, declared = body.u8("heartbeat type"), body.u16("heartbeat payload length")
    layer.add("heartbeat_type", {1: "request", 2: "response"}.get(kind, str(kind)), "Heartbeat message type")
    layer.add("payload_length", declared, "Payload length the sender claims (RFC 6520)")
    if declared + 3 + 16 > length:
        reason = "heartbeat claims more payload than the record holds (Heartbleed-style over-read request)"
        mark_malformed(layer, pkt, reason)


def _handshakes(body: Cursor, layer: Layer, pkt: DecodedPacket) -> None:
    parts: list[str | TlsHello] = []
    try:
        for _ in range(MAX_HANDSHAKES):
            if body.remaining < 4:
                break
            msg_type = body.u8("handshake type")
            msg_length = body.u24("handshake length")
            name = TLS_HANDSHAKE_TYPES.get(msg_type)
            if name is None or (msg_length > 0x10000 and msg_length > body.remaining):
                parts.append("encrypted handshake message")
                layer.add("payload", f"{body.remaining + 4} bytes", "Handshake data sent after keys changed: encrypted")
                break
            layer.add("handshake_type", f"{name} ({msg_type})", "Handshake message type")
            layer.add("handshake_length", msg_length, "Length of this handshake message in bytes")
            message = body.sub_available(msg_length)
            if msg_type in (1, 2):
                hello = TlsHello(client=msg_type == 1, legacy_version="")
                pkt.tls.append(hello)
                parts.append(hello)
                (_client_hello if hello.client else _server_hello)(message, layer, hello)
            else:
                parts.append(name)
    finally:
        if parts:
            layer.summary = "Handshake: " + ", ".join(p if isinstance(p, str) else hello_text(p) for p in parts)


def hello_text(hello: TlsHello) -> str:
    """One-line description of a (possibly partially decoded) hello."""
    if hello.client:
        return "ClientHello" + (f" (SNI {hello.sni})" if hello.sni else "")
    kind = "HelloRetryRequest" if hello.hello_retry_request else "ServerHello"
    return f"{kind} ({hello.version}, {hello.cipher_suites[0]})" if hello.cipher_suites else kind


def _client_hello(cur: Cursor, layer: Layer, hello: TlsHello) -> None:
    hello.legacy_version = tls_version_name(cur.u16("ClientHello version"))
    layer.add(
        "client_version",
        hello.legacy_version,
        "Highest version the client offers (legacy field; TLS 1.3 is negotiated via supported_versions)",
    )
    cur.skip(32, "ClientHello random")
    session_id = cur.take(cur.u8("session ID length"), "session ID")
    layer.add("session_id_length", len(session_id), "Session ID length (resumption / TLS 1.3 compatibility mode)")
    suites_length = cur.u16("cipher suites length")
    if suites_length % 2:
        raise DecodeError("cipher suites length is odd")
    suites = cur.sub(suites_length, "cipher suites")
    hello.cipher_suites = [tls_cipher_name(suites.u16("cipher suite")) for _ in range(suites_length // 2)]
    layer.add("cipher_suites_count", len(hello.cipher_suites), "Number of cipher suites the client offers")
    layer.add("cipher_suites", hello.cipher_suites[:MAX_LISTED], "Offered cipher suites in client preference order")
    cur.skip(cur.u8("compression methods length"), "compression methods")
    if cur.remaining:
        _extensions(cur.sub_available(cur.u16("extensions length")), layer, hello)


def _server_hello(cur: Cursor, layer: Layer, hello: TlsHello) -> None:
    hello.legacy_version = tls_version_name(cur.u16("ServerHello version"))
    layer.add("server_version", hello.legacy_version, "Version field of the ServerHello (TLS 1.3 says TLS 1.2 here)")
    hello.hello_retry_request = cur.take(32, "ServerHello random") == HELLO_RETRY_RANDOM
    if hello.hello_retry_request:
        layer.add("hello_retry_request", True, "HelloRetryRequest: the server asks the client to retry with other keys")
    cur.skip(cur.u8("session ID length"), "session ID")
    hello.cipher_suites = [tls_cipher_name(cur.u16("selected cipher suite"))]
    layer.add("cipher_suite", hello.cipher_suites[0], "Cipher suite the server selected from the client's offer")
    cur.skip(1, "compression method")
    if cur.remaining >= 2:
        _extensions(cur.sub_available(cur.u16("extensions length")), layer, hello)


def _extensions(cur: Cursor, layer: Layer, hello: TlsHello) -> None:
    """Decode extensions one by one; a malformed extension does not hide the ones after it."""
    names: list[str] = []
    problems: list[str] = []
    while cur.remaining >= 4:
        ext_type = cur.u16("extension type")
        data = cur.sub_available(cur.u16("extension length"))
        names.append(tls_extension_name(ext_type))
        try:
            _extension(ext_type, data, layer, hello)
        except DecodeError as exc:
            problems.append(f"{names[-1]}: {exc.message}")
    layer.add("extensions", names, "Extensions present, in order (GREASE values are deliberate noise)")
    if problems:
        raise DecodeError(problems[0])


def _extension(ext_type: int, data: Cursor, layer: Layer, hello: TlsHello) -> None:
    if ext_type == 0 and hello.client:
        _server_name(data, layer, hello)
    elif ext_type == 16:
        _alpn(data, layer, hello)
    elif ext_type == 43:
        _supported_versions(data, layer, hello)
    elif ext_type == 10 and hello.client:
        groups = data.sub_available(data.u16("supported groups length"))
        names = [tls_group_name(groups.u16("group")) for _ in range(min(groups.remaining // 2, MAX_LISTED))]
        layer.add("supported_groups", names, "Key-exchange groups the client supports (X25519MLKEM768 = post-quantum)")
    elif ext_type == 65037 and hello.client:
        hello.encrypted_client_hello = True
        layer.add(
            "encrypted_client_hello",
            True,
            "ECH: the real server name is encrypted; the visible SNI is only the provider's public name",
        )


def _server_name(data: Cursor, layer: Layer, hello: TlsHello) -> None:
    names = data.sub_available(data.u16("server name list length"))
    while names.remaining >= 3:
        name_type = names.u8("server name type")
        value = names.take(names.u16("server name length"), "server name")
        if name_type == 0 and hello.sni is None:
            hello.sni = printable(value, 255)
            layer.add(
                "server_name",
                hello.sni,
                "SNI: hostname the client asks for; sent in clear text before encryption starts",
            )


def _alpn(data: Cursor, layer: Layer, hello: TlsHello) -> None:
    protocols = data.sub_available(data.u16("ALPN list length"))
    while protocols.remaining >= 1 and len(hello.alpn) < MAX_LISTED:
        hello.alpn.append(printable(protocols.take(protocols.u8("ALPN protocol length"), "ALPN protocol"), 64))
    explanation = (
        "ALPN: application protocols offered (h2 = HTTP/2, http/1.1)"
        if hello.client
        else "ALPN: application protocol the server selected"
    )
    layer.add("alpn", list(hello.alpn), explanation)


def _supported_versions(data: Cursor, layer: Layer, hello: TlsHello) -> None:
    if hello.client:
        versions = data.sub_available(data.u8("supported versions length"))
        offered = [tls_version_name(versions.u16("version")) for _ in range(min(versions.remaining // 2, MAX_LISTED))]
        hello.versions = [v for v in offered if not v.startswith("GREASE")] or offered
        layer.add("supported_versions", hello.versions, "TLS versions the client supports (TLS 1.3 lists 0x0304)")
    else:
        hello.versions = [tls_version_name(data.u16("selected version"))]
        layer.add("selected_version", hello.versions[0], "Version the server actually negotiated")
