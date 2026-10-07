"""DNS over UDP/TCP: header flags, questions and resource records with safe name decompression."""

from __future__ import annotations

from raf.products.protocol.decoders.base import (
    Cursor,
    DecodeError,
    ipv4_text,
    ipv6_text,
    mark_malformed,
    printable,
)
from raf.products.protocol.decoders.tables import DNS_CLASSES, DNS_OPCODES, DNS_RCODES, DNS_TYPES
from raf.products.protocol.model import DecodedPacket, DnsAnswer, DnsMessage, Layer

MAX_NAME_LENGTH = 255  # RFC 1035: a name is at most 255 octets on the wire
MAX_POINTER_JUMPS = 32
MAX_QUESTIONS = 8
MAX_RECORDS = 64  # resource records decoded per message (answer + authority + additional)
MAX_TXT = 256

_FLAG_BITS = (
    (0x0400, "AA", "authoritative answer"),
    (0x0200, "TC", "truncated"),
    (0x0100, "RD", "recursion desired"),
    (0x0080, "RA", "recursion available"),
    (0x0020, "AD", "authentic data"),
    (0x0010, "CD", "checking disabled"),
)
_SECTIONS = (
    ("answers", "Answer section: records that answer the question"),
    ("authority", "Authority section: name servers / SOA for the zone"),
    ("additional", "Additional section: extra records (glue, EDNS0 OPT)"),
)


def type_name(value: int) -> str:
    return DNS_TYPES.get(value, f"TYPE{value}")


def read_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a possibly compressed domain name starting at ``offset``.

    Returns ``(name, next_offset)`` where ``next_offset`` follows the name *in place*
    (after the first compression pointer, if any). Pointer loops, pointers outside the
    message, reserved label types and names longer than 255 octets raise
    :class:`DecodeError`; the work done is bounded no matter what the input contains.
    """
    labels: list[str] = []
    wire_length = 1
    resume: int | None = None
    visited: set[int] = set()
    pos = offset
    while True:
        if pos >= len(data):
            raise DecodeError("name runs past the end of the message")
        length = data[pos]
        if length == 0:
            pos += 1
            break
        kind = length & 0xC0
        if kind == 0xC0:
            if pos + 1 >= len(data):
                raise DecodeError("compression pointer is truncated")
            target = ((length & 0x3F) << 8) | data[pos + 1]
            if resume is None:
                resume = pos + 2
            if target in visited:
                raise DecodeError("compression pointer loop")
            if len(visited) >= MAX_POINTER_JUMPS:
                raise DecodeError(f"more than {MAX_POINTER_JUMPS} compression pointers in one name")
            visited.add(target)
            pos = target
            continue
        if kind:
            raise DecodeError(f"reserved label type 0x{kind:02x}")
        if pos + 1 + length > len(data):
            raise DecodeError("label runs past the end of the message")
        wire_length += length + 1
        if wire_length > MAX_NAME_LENGTH:
            raise DecodeError("name is longer than 255 octets")
        labels.append(_label_text(data[pos + 1 : pos + 1 + length]))
        pos += 1 + length
    return (".".join(labels) or "."), (resume if resume is not None else pos)


def _label_text(raw: bytes) -> str:
    """Presentation format of one label: unusual bytes as ``\\DDD``, dots escaped."""
    if raw.isascii():
        text = raw.decode("ascii")
        if text.isprintable() and "." not in text and "\\" not in text and " " not in text:
            return text
    out = []
    for byte in raw:
        if byte in (0x2E, 0x5C):
            out.append("\\" + chr(byte))
        elif 0x21 <= byte < 0x7F:
            out.append(chr(byte))
        else:
            out.append(f"\\{byte:03d}")
    return "".join(out)


def decode_dns(payload: bytes, pkt: DecodedPacket, *, over_tcp: bool) -> Layer:
    layer = Layer("DNS")
    pkt.protocols.append("dns")
    data = payload
    if over_tcp:
        if len(payload) < 2:
            return mark_malformed(layer, pkt, "DNS-over-TCP length prefix is truncated")
        length = int.from_bytes(payload[:2], "big")
        layer.add("length", length, "DNS over TCP: 2-byte length prefix of the message that follows")
        data = payload[2 : 2 + length]
        if length > len(payload) - 2:
            layer.add(
                "segment",
                f"{len(data)} of {length} bytes",
                "The message continues in later TCP segments; R$F does not reassemble TCP streams",
            )
    message: DnsMessage | None = None
    try:
        message = _header(Cursor(data), layer)
        pkt.dns = message
        _body(data, layer, message)
    except DecodeError as exc:
        mark_malformed(layer, pkt, exc.message)
    if message is not None:
        layer.summary = _summary(message)
    return layer


def _header(cur: Cursor, layer: Layer) -> DnsMessage:
    txid = cur.u16("DNS transaction ID")
    flags = cur.u16("DNS flags")
    is_response = bool(flags & 0x8000)
    opcode = DNS_OPCODES.get((flags >> 11) & 0x0F, f"OPCODE{(flags >> 11) & 0x0F}")
    rcode = DNS_RCODES.get(flags & 0x0F, f"RCODE{flags & 0x0F}")
    layer.add("transaction_id", f"0x{txid:04x}", "Transaction ID: the client picks it, the response echoes it")
    layer.add("type", "response" if is_response else "query", "QR bit: query (0) or response (1)")
    layer.add("opcode", opcode, "Operation: QUERY is a normal lookup; UPDATE/NOTIFY change or announce zone data")
    layer.add(
        "flags",
        [f"{name} ({desc})" for bit, name, desc in _FLAG_BITS if flags & bit],
        "AA authoritative, TC truncated (retry over TCP), RD/RA recursion desired/available, AD/CD DNSSEC",
    )
    if is_response:
        layer.add("rcode", rcode, "Response code: NOERROR, NXDOMAIN (name does not exist), SERVFAIL, REFUSED ...")
    return DnsMessage(txid, is_response, opcode, rcode, truncated=bool(flags & 0x0200))


def _body(data: bytes, layer: Layer, message: DnsMessage) -> None:
    cur = Cursor(data, 4)
    counts = [cur.u16(f"DNS {name} count") for name in ("question", "answer", "authority", "additional")]
    layer.add(
        "counts",
        f"questions {counts[0]}, answers {counts[1]}, authority {counts[2]}, additional {counts[3]}",
        "Number of entries the header announces in each section",
    )
    offset = _questions(data, counts[0], layer, message)
    budget = MAX_RECORDS
    for (section, explanation), count in zip(_SECTIONS, counts[1:], strict=True):
        rows: list[str] = []
        try:
            for _ in range(min(count, budget)):
                answer, offset = _record(data, offset)
                budget -= 1
                rows.append(_record_text(answer))
                if section == "answers":
                    message.answers.append(answer)
        finally:
            if count or rows:  # partial sections stay visible when a record is malformed
                more = count - len(rows)
                layer.add(
                    section, rows + ([f"... {more} more not decoded"] if more and budget == 0 else []), explanation
                )


def _questions(data: bytes, count: int, layer: Layer, message: DnsMessage) -> int:
    """Decode the question section; returns the offset after it."""
    offset = 12
    rows: list[str] = []
    try:
        for _ in range(min(count, MAX_QUESTIONS)):
            name, offset = read_name(data, offset)
            cur = Cursor(data, offset)
            qtype, qclass = cur.u16("question type"), cur.u16("question class")
            offset = cur.pos
            message.questions.append((name, type_name(qtype)))
            rows.append(f"{name} {type_name(qtype)} {DNS_CLASSES.get(qclass, f'CLASS{qclass}')}")
    finally:
        layer.add("questions", rows, "Question section: the name and record type being looked up")
    return offset


def _record(data: bytes, offset: int) -> tuple[DnsAnswer, int]:
    name, offset = read_name(data, offset)
    cur = Cursor(data, offset)
    rtype, rclass, ttl, rdlength = cur.u16("record type"), cur.u16("record class"), cur.u32("TTL"), cur.u16("RDLENGTH")
    start = cur.pos
    cur.skip(rdlength, f"{type_name(rtype)} record data")
    if rtype == 41:  # EDNS0 OPT pseudo-record: class = UDP payload size, TTL = extended flags
        text = f"EDNS0 udp_payload={rclass} version={(ttl >> 16) & 0xFF} do={'yes' if ttl & 0x8000 else 'no'}"
        return DnsAnswer(name, "OPT", 0, text), cur.pos
    return DnsAnswer(name, type_name(rtype), ttl, _rdata(data, rtype, start, rdlength)), cur.pos


def _rdata(data: bytes, rtype: int, start: int, length: int) -> str:
    end = start + length
    if rtype == 1:
        if length != 4:
            raise DecodeError(f"A record data is {length} bytes, expected 4")
        return ipv4_text(data[start:end])
    if rtype == 28:
        if length != 16:
            raise DecodeError(f"AAAA record data is {length} bytes, expected 16")
        return ipv6_text(data[start:end])
    if rtype in (2, 5, 12, 39):  # NS, CNAME, PTR, DNAME
        return _name_within(data, start, end)
    if rtype == 15:
        if length < 3:
            raise DecodeError("MX record data is too short")
        preference = int.from_bytes(data[start : start + 2], "big")
        return f"{preference} {_name_within(data, start + 2, end)}"
    if rtype == 16:
        return _txt(data[start:end])
    if rtype == 6:
        mname, pos = read_name(data, start)
        rname, pos = read_name(data, pos)
        if pos + 20 > end:
            raise DecodeError("SOA record data is too short")
        return f"{mname} {rname} serial {int.from_bytes(data[pos : pos + 4], 'big')}"
    if rtype == 33 and length >= 7:
        priority, weight, port = (int.from_bytes(data[start + i : start + i + 2], "big") for i in (0, 2, 4))
        return f"{priority} {weight} {port} {_name_within(data, start + 6, end)}"
    return f"{length} bytes"


def _name_within(data: bytes, start: int, end: int) -> str:
    name, after = read_name(data, start)
    if after > end:
        raise DecodeError("name in record data runs past RDLENGTH")
    return name


def _txt(raw: bytes) -> str:
    cur = Cursor(raw)
    parts: list[str] = []
    while cur.remaining and sum(len(p) for p in parts) < MAX_TXT:
        size = cur.u8("TXT string length")
        parts.append('"' + printable(cur.take(size, "TXT string"), MAX_TXT).replace('"', '\\"') + '"')
    return " ".join(parts)


def _record_text(answer: DnsAnswer) -> str:
    if answer.rtype == "OPT":
        return answer.data
    return f"{answer.name} {answer.rtype} ttl={answer.ttl} {answer.data}"


def _summary(message: DnsMessage) -> str:
    question = " ".join(message.questions[0][::-1]) if message.questions else ""
    txid = f"0x{message.transaction_id:04x}"
    if not message.is_response:
        return f"query {txid} {question}".rstrip()
    answers = ", ".join(a.data for a in message.answers[:4] if a.rtype != "OPT")
    text = f"response {txid} {message.rcode} {question}".rstrip()
    return f"{text} → {answers}" if answers else text
