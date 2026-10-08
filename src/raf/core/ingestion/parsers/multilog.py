"""Mixed and multi-source logs: one parser for files whose lines come from many sources.

Every line is framed and decoded on its own (:mod:`raf.core.ingestion.logs.dispatch`): a file can
interleave web access logs, CloudTrail and Kubernetes audit JSON, DNS server, database, identity
provider, EDR, flow, application and syslog lines. Lines without a timestamp of their own continue
the record before them (stack traces, wrapped messages); W3C/IIS and Zeek ``#fields`` headers name
the columns of the lines that follow.

Records are identified by their line, as with every line-based parser, so importing the same file
again (even after it was imported with another parser) refers to the same events.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any, ClassVar

from raf.core.ingestion.base import ParseContext, Parser, RawRecord
from raf.core.ingestion.logs.dispatch import Decoded, decode_line, finish, source_label
from raf.core.ingestion.logs.frame import Frame, frame_line
from raf.core.ingestion.logs.structured import decode_structured
from raf.core.security.files import iter_lines
from raf.core.security.redaction import redact_text

MAX_CONTINUATION_LINES = 500
MAX_CONTINUATION_BYTES = 65536
_SNIFF_LINES = 80
_SYSLOG_FRAMINGS = ("rfc3164", "rfc5424", "iso-syslog")
_SYSLOG_PARSER_PROGRAMS = ("sshd", "sudo", "su", "systemd-logind", "cron", "crond", "kernel", "systemd", "cron.d")
_VPC_HEADER = re.compile(r"^version account-id interface-id srcaddr dstaddr")
_W3C_FIELDS = "#Fields:"
_ZEEK_FIELDS = "#fields"


@dataclass(slots=True)
class _Columns:
    """Column names announced by a header (W3C/IIS ``#Fields:``, Zeek ``#fields``)."""

    names: list[str]
    separator: str | None  # None: runs of whitespace
    unset: tuple[str, ...] = ("-",)

    def row(self, text: str) -> dict[str, Any] | None:
        values = text.split(self.separator) if self.separator else text.split()
        if len(values) != len(self.names):
            return None
        row: dict[str, Any] = {}
        for name, value in zip(self.names, values, strict=True):
            if value in self.unset:
                continue
            row[name] = value.replace("+", " ") if name.startswith("cs(") else value
        if "date" in row and "time" in row:  # W3C: separate date and time (UTC)
            row["timestamp"] = f"{row.pop('date')}T{row.pop('time')}Z"
        return row


@dataclass(slots=True)
class _Pending:
    first_line: int
    last_line: int
    frame: Frame
    decoded: Decoded
    lines: list[str] = field(default_factory=list)
    size: int = 0

    def can_take(self, text: str) -> bool:
        return len(self.lines) < MAX_CONTINUATION_LINES and self.size + len(text) <= MAX_CONTINUATION_BYTES

    def take(self, number: int, text: str) -> None:
        self.lines.append(text)
        self.size += len(text)
        self.last_line = number


def _directive(text: str) -> _Columns | None:
    if text.startswith(_W3C_FIELDS):
        names = text[len(_W3C_FIELDS) :].split()
        return _Columns(names[:256], None) if names else None
    if text.startswith(_ZEEK_FIELDS) and len(text) > len(_ZEEK_FIELDS) and text[len(_ZEEK_FIELDS)] in "\t ":
        separator = "\t" if "\t" in text else None
        names = text.split(separator)[1:] if separator else text.split()[1:]
        return _Columns(names[:256], separator, ("-", "(empty)"))
    return None


class MultiLogParser(Parser):
    name: ClassVar[str] = "multilog"
    description: ClassVar[str] = (
        "Mixed and multi-source logs, decoded line by line: web, DNS, database, cloud and Kubernetes audit, "
        "identity providers, EDR and Windows events, flows, firewalls, application JSON/logfmt, CEF/LEEF, "
        "syslog daemons and free text"
    )
    extensions: ClassVar[tuple[str, ...]] = (".log", ".txt", ".out", ".logs")

    # ------------------------------------------------------------------ detection
    @classmethod
    def survey(cls, head: bytes) -> dict[str, Any]:
        """How the first lines of a file decode: sources, decoders, framings and timestamp coverage."""
        text = head.decode("utf-8", "replace")
        lines = [ln for ln in text.splitlines()[:_SNIFF_LINES] if ln.strip() and not ln.startswith("#")]
        if text and not text.endswith("\n") and len(lines) > 1:
            lines = lines[:-1]  # the last line of a head may be cut off
        sources: Counter[str] = Counter()
        families: Counter[str] = Counter()
        framings: Counter[str] = Counter()
        timestamped = continuation = bare_json = 0
        for line in lines:
            frame = frame_line(line)
            if frame.timestamp is None and (line[:1].isspace() or line.startswith(("at ", "Caused by", "..."))):
                continuation += 1
                continue
            decoded = decode_line(frame)
            if frame.timestamp or decoded.record.get("timestamp"):
                timestamped += 1
            if frame.framing == "bare" and line.lstrip().startswith("{"):
                bare_json += 1
            families[decoded.family] += 1
            sources[source_label(decoded, frame)] += 1
            framings[frame.framing] += 1
        records = max(len(lines) - continuation, 1)
        return {
            "lines": len(lines),
            "records": records,
            "timestamped": timestamped / records,
            "bare_json": bare_json / records,
            "sources": sources,
            "families": families,
            "framings": framings,
        }

    @classmethod
    def sniff(cls, path: Path, head: bytes) -> float:
        if not head.strip() or b"\x00" in head[:4096]:
            return 0.0
        info = cls.survey(head)
        if info["lines"] == 0 or info["timestamped"] < 0.5:
            return 0.0
        if info["bare_json"] >= 0.8:
            return 0.0  # JSON Lines: the JSON parser and its normalizers handle them
        families: Counter[str] = info["families"]
        sources: Counter[str] = info["sources"]
        framings: Counter[str] = info["framings"]
        structured = 1 - families.get("text", 0) / max(sum(families.values()), 1)
        syslog_only = set(framings) <= set(_SYSLOG_FRAMINGS) and all(
            source.startswith(_SYSLOG_PARSER_PROGRAMS) or families.get("text") for source in sources
        )
        if syslog_only and set(families) <= {"syslog", "text"}:
            return 0.5  # plain syslog: the syslog parser (0.88) keeps it
        if info["timestamped"] >= 0.6 and (len(families) >= 2 or len(sources) >= 2):
            return 0.95
        if structured >= 0.6:
            return 0.6
        return 0.55

    @classmethod
    def describe(cls, head: bytes) -> str:
        """``11 sources: nginx, app, bind9 ...`` for detection reports."""
        sources: Counter[str] = cls.survey(head)["sources"]
        names = [name for name, _n in sources.most_common(12)]
        if not names:
            return "no recognizable sources in the first lines"
        more = f" and {len(sources) - 12} more" if len(sources) > 12 else ""
        return f"{len(sources)} source(s) in the first lines: {', '.join(names)}{more}"

    # ------------------------------------------------------------------ records
    def records(self, stream: IO[bytes], ctx: ParseContext) -> Iterator[RawRecord]:
        pending: _Pending | None = None
        columns: _Columns | None = None
        for line in iter_lines(stream, ctx.max_record_bytes):
            locator = f"line {line.number}"
            if line.text is None:
                if pending is not None:
                    yield self._emit(pending, ctx)
                    pending = None
                yield RawRecord.rejected(locator, f"Line exceeds {ctx.max_record_bytes} bytes.")
                continue
            text = line.text
            if not text.strip():
                continue
            if text.startswith("#"):
                announced = _directive(text)
                if announced is not None:
                    columns = announced
                elif text.startswith("#close"):
                    columns = None
                continue
            if _VPC_HEADER.match(text):
                continue
            frame = frame_line(text)
            decoded: Decoded | None = None
            if columns is not None:
                row = columns.row(text)
                if row is not None:
                    family, data = decode_structured(row, Frame(text, text))
                    decoded = Decoded(f"{family}-columns" if family in ("json", "kv") else family, data)
                    frame = Frame(text, text)
            if decoded is None:
                decoded = decode_line(frame)
            if not (frame.timestamp or decoded.record.get("timestamp")):
                if pending is not None and pending.can_take(text):
                    pending.take(line.number, text)
                    continue
                if pending is not None:
                    yield self._emit(pending, ctx)
                    pending = None
                yield RawRecord.rejected(locator, "No timestamp in the line, and no earlier record it continues.", text)
                continue
            if pending is not None:
                yield self._emit(pending, ctx)
            pending = _Pending(line.number, line.number, frame, decoded, [text], len(text))
        if pending is not None:
            yield self._emit(pending, ctx)

    def _emit(self, pending: _Pending, ctx: ParseContext) -> RawRecord:
        data = finish(pending.decoded, pending.frame)
        locator = (
            f"line {pending.first_line}"
            if pending.first_line == pending.last_line
            else f"lines {pending.first_line}-{pending.last_line}"
        )
        if len(pending.lines) > 1:
            continued = redact_text("\n".join(pending.lines[1:]))
            message = str(data.get("message") or pending.frame.payload)
            data["message"] = (message + "\n" + continued)[:4000]
            data.setdefault("attributes", {})["continuation_lines"] = len(pending.lines) - 1
        family = pending.decoded.family
        return RawRecord(
            data,
            locator,
            "\n".join(pending.lines),
            parser_label=f"{self.name}-{family}/{self.version}",
            origin=source_label(pending.decoded, pending.frame),
        )


__all__ = ["MultiLogParser"]
