"""Line framing for mixed logs.

A log line is split into its frame - timestamp, source tag (program, service or log name), host,
process id, level - and its payload (the message). Framings recognized, in order:

* RFC 5424 syslog: ``<PRI>1 TIMESTAMP HOST APP PROCID MSGID [SD] MSG``
* RFC 3164 syslog: ``[<PRI>]Mmm dd hh:mm:ss HOST PROG[PID]: MSG``
* a leading ISO-8601 (or ``YYYY/MM/DD``) timestamp, optionally bracketed, followed by
  ``HOST PROG[PID]: MSG`` (syslog written with ISO timestamps), a level (``INFO ...``), a source tag
  (``nginx[edge-01] ...``, ``cloudtrail {...}``, ``k8s-audit: ...``) or the message itself
* a leading epoch timestamp (``1696700000.123 ...``, Squid and similar)
* no frame: the payload is the whole line (JSON objects, CEF, access logs with their own
  timestamp ...); decoders then look for the timestamp inside the payload.

Nothing here interprets the payload; the frame only says where the message starts and what the
line says about its origin.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_TS_ISO = r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?(?:[Zz]|[+-]\d{2}(?::?\d{2})?| ?UTC\b)?"
_TS_SLASH = r"\d{4}/\d{2}/\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?"
_TS_3164 = r"[A-Z][a-z]{2}\s{1,2}\d{1,2}\s\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?"

_RFC5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>1 (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<pid>\S+) (?P<msgid>\S+) "
    r"(?P<sd>-|(?:\[(?:[^\]\\]|\\.)*\])+)(?: (?P<msg>.*))?$"
)
_RFC3164 = re.compile(
    rf"^(?:<(?P<pri>\d{{1,3}})>)?(?P<ts>{_TS_3164})(?:\s+(?P<year>\d{{4}}))?\s+(?P<host>\S+)\s+"
    r"(?P<prog>[A-Za-z0-9_][\w.\-/]*?)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$"
)
_RFC3164_BARE = re.compile(rf"^(?:<(?P<pri>\d{{1,3}})>)?(?P<ts>{_TS_3164})\s+(?P<host>\S+)\s+(?P<msg>.*)$")
_LEADING_TS = re.compile(
    rf"^(?:<(?P<pri>\d{{1,3}})>)?\[?(?P<ts>{_TS_ISO}|{_TS_SLASH})\]?(?:\s+|(?=[\[{{])|$)(?P<rest>.*)$"
)
_EPOCH = re.compile(r"^(?P<ts>1\d{9}(?:\.\d{1,9})?|1\d{12})\s+(?P<rest>\S.*)$")
_SYSLOG_TAIL = re.compile(
    r"^(?P<host>[A-Za-z0-9_][\w.\-:]{0,252})\s+(?P<prog>[A-Za-z_][\w.\-/]{0,63})(?:\[(?P<pid>\d{1,10})\])?:\s?"
    r"(?P<msg>.*)$"
)
_LEVEL_TAIL = re.compile(
    r"^\[?(?P<level>TRACE|DEBUG|INFO|NOTICE|WARN(?:ING)?|ERR(?:OR)?|CRIT(?:ICAL)?|FATAL|ALERT|EMERG(?:ENCY)?|SEVERE)"
    r"\]?(?:\s*[:|]\s*|\s+-\s+|\s+|$)(?P<msg>.*)$",
    re.IGNORECASE,
)
_TAG_TAIL = re.compile(
    r"^(?P<tag>[A-Za-z][\w.\-/]{0,63})(?:\[(?P<inner>[^\]\s]{1,128})\])?:?\s+(?P<msg>\S.*)$",
)
_SD_ELEMENT = re.compile(r"\[(?P<id>[^\s\]]+)(?P<params>(?:\s+[^\s=\]]+=\"(?:[^\"\\]|\\.)*\")*)\s*\]")
_SD_PARAM = re.compile(r"([^\s=\]]+)=\"((?:[^\"\\]|\\.)*)\"")

LEVELS = frozenset(
    {
        "trace",
        "debug",
        "info",
        "notice",
        "warn",
        "warning",
        "err",
        "error",
        "crit",
        "critical",
        "fatal",
        "alert",
        "emerg",
        "emergency",
        "severe",
    }
)
_SYSLOG_LEVELS = ("emerg", "alert", "crit", "error", "warning", "notice", "info", "debug")
_MONTHS = {
    m: i for i, m in enumerate(("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), 1)
}


@dataclass(slots=True)
class Frame:
    text: str  # the whole line
    payload: str  # the message (what follows the frame)
    timestamp: str | None = None
    tag: str | None = None  # program, service or log name
    host: str | None = None
    pid: str | None = None
    level: str | None = None  # lower case
    framing: str = "bare"  # rfc5424 | rfc3164 | iso-syslog | tagged | timestamped | epoch | bare
    facility: int | None = None
    msgid: str | None = None
    structured: dict[str, dict[str, str]] | None = None

    @property
    def message(self) -> str:
        """Everything after the timestamp (tag included): what a free-text reader would call the message."""
        if self.framing == "tagged" and self.tag:
            inner = f"[{self.host or self.pid}]" if (self.host or self.pid) else ""
            return f"{self.tag}{inner} {self.payload}"
        return self.payload


def _pri(frame: Frame, value: str | None) -> None:
    if not value:
        return
    number = int(value)
    if number > 191:
        return
    frame.facility = number // 8
    frame.level = frame.level or _SYSLOG_LEVELS[number % 8]


def _structured(text: str) -> dict[str, dict[str, str]] | None:
    if text == "-":
        return None
    elements: dict[str, dict[str, str]] = {}
    for element in _SD_ELEMENT.finditer(text):
        params = {
            k: v.replace('\\"', '"').replace("\\]", "]").replace("\\\\", "\\")
            for k, v in _SD_PARAM.findall(element["params"])
        }
        elements[element["id"]] = params
    return elements or None


def _nil(value: str | None) -> str | None:
    return None if value in (None, "", "-") else value


def _syslog_time(ts: str, year: str | None) -> str:
    """An RFC 3164 timestamp; with a year (some daemons add one) it becomes ISO-8601."""
    if not year:
        return ts
    month, day, clock = ts.split()
    number = _MONTHS.get(month.lower())
    return f"{year}-{number:02d}-{int(day):02d}T{clock}" if number else ts


def frame_line(text: str) -> Frame:
    """Split ``text`` into frame and payload (never fails: an unframed line is all payload)."""
    if text.startswith("<") and (m := _RFC5424.match(text)):
        frame = Frame(
            text,
            (m["msg"] or "").removeprefix("\ufeff"),
            timestamp=_nil(m["ts"]),
            tag=_nil(m["app"]),
            host=_nil(m["host"]),
            pid=_nil(m["pid"]),
            framing="rfc5424",
            msgid=_nil(m["msgid"]),
            structured=_structured(m["sd"]),
        )
        _pri(frame, m["pri"])
        return frame
    if text[:1].isalpha() or text.startswith("<"):
        if m := _RFC3164.match(text):
            frame = Frame(
                text,
                m["msg"],
                timestamp=_syslog_time(m["ts"], m["year"]),
                tag=m["prog"],
                host=m["host"],
                pid=m["pid"],
                framing="rfc3164",
            )
            _pri(frame, m["pri"])
            return frame
        if m := _RFC3164_BARE.match(text):
            frame = Frame(text, m["msg"], timestamp=m["ts"], host=m["host"], framing="rfc3164")
            _pri(frame, m["pri"])
            return frame
    if m := _LEADING_TS.match(text):
        frame = Frame(text, m["rest"], timestamp=m["ts"], framing="timestamped")
        _pri(frame, m["pri"])
        _split_tail(frame, m["rest"])
        return frame
    if m := _EPOCH.match(text):
        return Frame(text, m["rest"], timestamp=m["ts"], framing="epoch")
    return Frame(text, text)


def _split_tail(frame: Frame, rest: str) -> None:
    """What follows a leading timestamp: syslog host + program, a level, a source tag, or the message."""
    m = _SYSLOG_TAIL.match(rest)
    if m is not None and m["host"].lower() not in LEVELS and m["prog"].lower() not in LEVELS:
        frame.host, frame.tag, frame.pid, frame.payload = m["host"], m["prog"], m["pid"], m["msg"]
        frame.framing = "iso-syslog"
        return
    if m := _LEVEL_TAIL.match(rest):
        frame.level = m["level"].lower()
        frame.payload = m["msg"]
        return
    if (m := _TAG_TAIL.match(rest)) and m["tag"].lower() not in LEVELS:
        frame.tag = m["tag"]
        inner = m["inner"]
        if inner is not None:
            if inner.isdigit():
                frame.pid = inner
            else:
                frame.host = inner
        frame.payload = m["msg"]
        frame.framing = "tagged"


__all__ = ["LEVELS", "Frame", "frame_line"]
