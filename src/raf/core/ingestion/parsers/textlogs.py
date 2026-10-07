"""Text log parsers: syslog (RFC 3164/5424 with sshd/sudo/su/cron/firewall
extraction), web access logs (common/combined) and generic timestamped lines.

Parsers emit native records; the native normalizer turns them into events.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import IO, Any, ClassVar

from raf.core.ingestion.base import ParseContext, Parser, RawRecord
from raf.core.security.files import iter_lines

# --------------------------------------------------------------------------- syslog framing

_RFC3164 = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(?P<host>\S+)\s+"
    r"(?P<prog>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$"
)
_ISO_SYSLOG = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<host>\S+)\s+"
    r"(?P<prog>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$"
)
_RFC5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>1\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<prog>\S+)\s+(?P<pid>\S+)\s+(?P<msgid>\S+)\s+"
    r"(?P<sd>-|(?:\[.*?\])+)\s?(?P<msg>.*)$"
)

# --------------------------------------------------------------------------- program extractors

_SSH_ACCEPT = re.compile(r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
_SSH_FAIL = re.compile(
    r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
_SSH_INVALID = re.compile(r"^Invalid user (?P<user>\S*) from (?P<ip>\S+)")
_SSH_DISCONNECT = re.compile(r"^Disconnected from (?:user )?(?P<user>\S+) (?P<ip>\S+) port (?P<port>\d+)")
_PAM_CLOSED = re.compile(r"session closed for user (?P<user>\S+)")
_SUDO = re.compile(
    r"^\s*(?P<user>\S+) : (?:TTY=(?P<tty>\S+) ; )?PWD=(?P<pwd>\S+) ; USER=(?P<as>\S+) ;"
    r"(?: COMMAND=(?P<cmd>.+))?$"
)
_SUDO_FAIL = re.compile(r"^\s*(?P<user>\S+) : (?P<n>\d+) incorrect password attempts?")
_SU_OK = re.compile(r"^(?:\(to (?P<as1>\S+)\) (?P<user1>\S+) on|Successful su for (?P<as2>\S+) by (?P<user2>\S+))")
_SU_FAIL = re.compile(r"^FAILED su for (?P<as>\S+) by (?P<user>\S+)")
_LOGIND_NEW = re.compile(r"^New session (?P<sid>\S+) of user (?P<user>\S+)")
_LOGIND_REMOVED = re.compile(r"^Removed session (?P<sid>\S+)")
_CRON = re.compile(r"^\((?P<user>[^)]+)\) CMD \((?P<cmd>.*)\)\s*$")
_FIREWALL = re.compile(
    r"IN=(?P<in>\S*) OUT=(?P<out>\S*).*?SRC=(?P<src>\S+) DST=(?P<dst>\S+).*?PROTO=(?P<proto>\S+)"
    r"(?:.*?SPT=(?P<spt>\d+))?(?:.*?DPT=(?P<dpt>\d+))?"
)

Extractor = Callable[[re.Match[str], dict[str, Any]], dict[str, Any] | None]


def _event(base: dict[str, Any], event_type: str, **fields: Any) -> dict[str, Any]:
    record = {**base, "event_type": event_type}
    attributes = dict(base.get("attributes") or {})
    attributes.update({k: v for k, v in fields.pop("attributes", {}).items() if v not in (None, "")})
    record.update(fields)
    record["attributes"] = attributes
    return record


def extract_program(prog: str, msg: str, base: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """Map a syslog program message onto a native event (returns record and extractor label)."""
    program = prog.lower()
    host = base["host"]
    if program.startswith("sshd"):
        if m := _SSH_ACCEPT.match(msg):
            return _event(
                base,
                "auth.login",
                actor=m["user"],
                target=host,
                outcome="success",
                action="ssh-login",
                attributes={"src_ip": m["ip"], "src_port": int(m["port"]), "method": m["method"], "protocol": "ssh"},
            ), "syslog-sshd"
        if m := _SSH_FAIL.match(msg):
            return _event(
                base,
                "auth.failure",
                actor=m["user"],
                target=host,
                outcome="failure",
                action="ssh-login",
                severity="low",
                attributes={
                    "src_ip": m["ip"],
                    "src_port": int(m["port"]),
                    "method": m["method"],
                    "invalid_user": bool(m["invalid"]),
                    "protocol": "ssh",
                },
            ), "syslog-sshd"
        if m := _SSH_INVALID.match(msg):
            return _event(
                base,
                "auth.failure",
                actor=m["user"] or "unknown",
                target=host,
                outcome="failure",
                action="ssh-invalid-user",
                severity="low",
                attributes={"src_ip": m["ip"], "invalid_user": True, "protocol": "ssh"},
            ), "syslog-sshd"
        if m := _SSH_DISCONNECT.match(msg):
            return _event(
                base,
                "auth.logout",
                actor=m["user"],
                target=host,
                action="ssh-disconnect",
                attributes={"src_ip": m["ip"], "protocol": "ssh"},
            ), "syslog-sshd"
        if m := _PAM_CLOSED.search(msg):
            return _event(base, "auth.logout", actor=m["user"], target=host, action="session-closed"), "syslog-sshd"
    if program == "sudo":
        if m := _SUDO_FAIL.match(msg):
            return _event(
                base,
                "auth.failure",
                actor=m["user"],
                target=host,
                outcome="failure",
                action="sudo",
                severity="medium",
                attributes={"attempts": int(m["n"])},
            ), "syslog-sudo"
        if m := _SUDO.match(msg):
            return _event(
                base,
                "auth.privilege",
                actor=m["user"],
                target=host,
                outcome="success",
                action="sudo",
                attributes={"as_user": m["as"], "command": (m["cmd"] or "").strip(), "pwd": m["pwd"], "tty": m["tty"]},
            ), "syslog-sudo"
    if program == "su":
        if m := _SU_FAIL.match(msg):
            return _event(
                base,
                "auth.failure",
                actor=m["user"],
                target=host,
                outcome="failure",
                action="su",
                severity="medium",
                attributes={"as_user": m["as"]},
            ), "syslog-su"
        if m := _SU_OK.match(msg):
            return _event(
                base,
                "auth.privilege",
                actor=m["user1"] or m["user2"],
                target=host,
                outcome="success",
                action="su",
                attributes={"as_user": m["as1"] or m["as2"]},
            ), "syslog-su"
    if program == "systemd-logind":
        if m := _LOGIND_NEW.match(msg):
            return _event(
                base,
                "auth.login",
                actor=m["user"],
                target=host,
                outcome="success",
                action="session-new",
                attributes={"session_id": m["sid"]},
            ), "syslog-logind"
        if m := _LOGIND_REMOVED.match(msg):
            return _event(
                base, "auth.logout", target=host, action="session-removed", attributes={"session_id": m["sid"]}
            ), "syslog-logind"
    if program in ("cron", "crond") and (m := _CRON.match(msg)):
        command = m["cmd"].strip()
        image = command.split()[0] if command else "cron-job"
        return _event(
            base,
            "process.start",
            actor=m["user"],
            action="cron",
            attributes={"image": image, "command_line": command, "scheduler": "cron"},
        ), "syslog-cron"
    if program == "kernel" and (m := _FIREWALL.search(msg)):
        blocked = any(word in msg.upper() for word in ("BLOCK", "DROP", "DENY", "REJECT"))
        return _event(
            base,
            "network.connection",
            actor=m["src"],
            target=m["dst"],
            outcome="failure" if blocked else "success",
            action="firewall",
            attributes={
                "src_ip": m["src"],
                "dst_ip": m["dst"],
                "protocol": m["proto"].lower(),
                "src_port": int(m["spt"]) if m["spt"] else None,
                "dst_port": int(m["dpt"]) if m["dpt"] else None,
                "interface_in": m["in"],
                "interface_out": m["out"],
                "blocked": blocked,
            },
        ), "syslog-firewall"
    return _event(base, "log.message", target=host, attributes={"program": prog}), "syslog"


class SyslogParser(Parser):
    name: ClassVar[str] = "syslog"
    description: ClassVar[str] = "Syslog (RFC 3164/5424, ISO) incl. sshd, sudo, su, logind, cron, firewall"
    extensions: ClassVar[tuple[str, ...]] = (".log", ".syslog")

    @classmethod
    def _match(cls, line: str) -> re.Match[str] | None:
        return _RFC5424.match(line) or _ISO_SYSLOG.match(line) or _RFC3164.match(line)

    @classmethod
    def sniff(cls, path: Path, head: bytes) -> float:
        lines = [ln for ln in head.decode("utf-8", "replace").splitlines()[:20] if ln.strip()]
        if not lines:
            return 0.0
        hits = sum(1 for ln in lines if cls._match(ln))
        ratio = hits / len(lines)
        return 0.88 if ratio >= 0.6 else 0.3 * ratio

    def records(self, stream: IO[bytes], ctx: ParseContext) -> Iterator[RawRecord]:
        for line in iter_lines(stream, ctx.max_record_bytes):
            locator = f"line {line.number}"
            if line.text is None:
                yield RawRecord.rejected(locator, f"Line exceeds {ctx.max_record_bytes} bytes.")
                continue
            if not line.text.strip():
                continue
            match = self._match(line.text)
            if not match:
                yield RawRecord.rejected(locator, "Line is not in a recognized syslog format.", line.text)
                continue
            groups = match.groupdict()
            base: dict[str, Any] = {
                "timestamp": groups["ts"],
                "host": groups["host"],
                "message": groups["msg"],
                "attributes": {"program": groups["prog"]},
            }
            if groups.get("pid") and groups["pid"] != "-":
                base["attributes"]["program_pid"] = groups["pid"]
            record, label = extract_program(groups["prog"], groups["msg"], base)
            yield RawRecord(record, locator, line.text, parser_label=f"{label}/{self.version}")


# --------------------------------------------------------------------------- web access logs

_ACCESS = re.compile(
    r'^(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]{3,10}) (?P<path>\S+)'
    r'(?: (?P<proto>HTTP/[\d.]+))?" (?P<status>\d{3}) (?P<size>\d+|-)(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?'
)


class AccessLogParser(Parser):
    name: ClassVar[str] = "access-log"
    description: ClassVar[str] = "Web server access logs (NCSA common / combined)"
    extensions: ClassVar[tuple[str, ...]] = (".log",)

    @classmethod
    def sniff(cls, path: Path, head: bytes) -> float:
        lines = [ln for ln in head.decode("utf-8", "replace").splitlines()[:20] if ln.strip()]
        if not lines:
            return 0.0
        ratio = sum(1 for ln in lines if _ACCESS.match(ln)) / len(lines)
        return 0.92 if ratio >= 0.6 else 0.3 * ratio

    def records(self, stream: IO[bytes], ctx: ParseContext) -> Iterator[RawRecord]:
        server = ctx.source.default_host or ctx.options.get("server") or "web"
        for line in iter_lines(stream, ctx.max_record_bytes):
            locator = f"line {line.number}"
            if line.text is None:
                yield RawRecord.rejected(locator, f"Line exceeds {ctx.max_record_bytes} bytes.")
                continue
            if not line.text.strip():
                continue
            m = _ACCESS.match(line.text)
            if not m:
                yield RawRecord.rejected(locator, "Line is not in common/combined access log format.", line.text)
                continue
            status = int(m["status"])
            user = m["user"] if m["user"] != "-" else None
            record = {
                "timestamp": m["ts"],
                "event_type": "http.request",
                "action": m["method"].lower(),
                "actor": {"type": "ip", "name": m["ip"]},
                "host": server,
                "target": {"type": "url", "name": f"http://{server}{m['path']}"},
                "outcome": "failure" if status >= 400 else "success",
                "severity": "low" if status in (401, 403) else "info",
                "message": f"{m['method']} {m['path']} -> {status}",
                "attributes": {
                    k: v
                    for k, v in {
                        "src_ip": m["ip"],
                        "method": m["method"],
                        "path": m["path"],
                        "status": status,
                        "bytes": int(m["size"]) if m["size"] != "-" else None,
                        "protocol": m["proto"],
                        "referrer": m["ref"] if m["ref"] not in (None, "-") else None,
                        "user_agent": m["ua"],
                        "user": user,
                    }.items()
                    if v is not None
                },
            }
            yield RawRecord(record, locator, line.text, parser_label=f"access-log/{self.version}")


# --------------------------------------------------------------------------- generic text

_LEADING_TS = re.compile(
    r"^\[?(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2}| UTC)?)\]?\s*[-|:]?\s*"
    r"(?:(?P<level>DEBUG|INFO|NOTICE|WARN(?:ING)?|ERROR|CRIT(?:ICAL)?|FATAL)\b\s*[-|:]?\s*)?(?P<msg>.*)$",
    re.IGNORECASE,
)


class TextLogParser(Parser):
    name: ClassVar[str] = "text"
    description: ClassVar[str] = "Generic timestamped text lines (fallback)"
    extensions: ClassVar[tuple[str, ...]] = (".log", ".txt")

    @classmethod
    def sniff(cls, path: Path, head: bytes) -> float:
        text = head.decode("utf-8", "replace")
        if not text.strip() or "\x00" in text:
            return 0.0
        lines = [ln for ln in text.splitlines()[:20] if ln.strip()]
        ratio = sum(1 for ln in lines if _LEADING_TS.match(ln)) / max(len(lines), 1)
        return 0.5 if ratio >= 0.5 else 0.12

    def records(self, stream: IO[bytes], ctx: ParseContext) -> Iterator[RawRecord]:
        host = ctx.source.default_host
        for line in iter_lines(stream, ctx.max_record_bytes):
            locator = f"line {line.number}"
            if line.text is None:
                yield RawRecord.rejected(locator, f"Line exceeds {ctx.max_record_bytes} bytes.")
                continue
            if not line.text.strip():
                continue
            m = _LEADING_TS.match(line.text.strip())
            if not m:
                yield RawRecord.rejected(locator, "Required timestamp could not be determined.", line.text)
                continue
            level = (m["level"] or "INFO").upper()
            record = {
                "timestamp": m["ts"],
                "event_type": "log.message",
                "message": m["msg"],
                "severity": {
                    "WARN": "MEDIUM",
                    "WARNING": "MEDIUM",
                    "ERROR": "HIGH",
                    "FATAL": "CRITICAL",
                    "CRIT": "CRITICAL",
                    "CRITICAL": "CRITICAL",
                }.get(level, "INFO"),
                "attributes": {"level": level},
            }
            if host:
                record["host"] = host
            yield RawRecord(record, locator, line.text, parser_label=f"text/{self.version}")
