"""Database statements in logs: a native ``db.query`` (or authentication) event per statement, with
the statement redacted, its verb and tables extracted, and risky operations flagged."""

from __future__ import annotations

import re
from typing import Any

from raf.core.ingestion.logs.records import ip, ip_ref, level_severity, record, ref
from raf.core.objects.types import ObjectType
from raf.core.security.redaction import redact_text

_VERB = re.compile(r"^\s*(?:/\*.*?\*/\s*)?(?P<verb>[A-Za-z]+)", re.DOTALL)
_TABLES = re.compile(r"(?i)\b(?:from|join|into|update|table|truncate)\s+(?P<name>[A-Za-z_][\w.\"$]*)")
_PASSWORD = re.compile(r"(?i)(\b(?:password|identified\s+by)\s+)('[^']*'|\"[^\"]*\"|\S+)")
#: Statements that read or write outside the database, change access or destroy data.
RISKY_SQL: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("file-export", re.compile(r"(?i)\bcopy\b.+\bto\b\s*(?:'|stdout|program)|\binto\s+(?:out|dump)file\b")),
    ("file-read", re.compile(r"(?i)\b(?:pg_read_file|pg_read_binary_file|pg_ls_dir|lo_import|load_file)\s*\(")),
    ("command-execution", re.compile(r"(?i)\b(?:xp_cmdshell|copy\b.+\bfrom\s+program|sys_exec|lo_export)\b")),
    ("privilege-change", re.compile(r"(?i)\b(?:grant|revoke)\b.+\b(?:to|from)\b|\b(?:create|alter)\s+(?:role|user)\b")),
    ("destructive", re.compile(r"(?i)\b(?:drop\s+(?:table|database|schema)|truncate\s+table|truncate\s+\w)")),
)


def redact_sql(statement: str) -> str:
    """A statement as it may be stored: literal passwords masked, secret-looking values redacted."""
    return redact_text(_PASSWORD.sub(lambda m: f"{m.group(1)}'****'", statement))[:4000]


def analyze_sql(statement: str) -> dict[str, Any]:
    verb = _VERB.match(statement)
    tables = []
    for match in _TABLES.finditer(statement):
        name = match["name"].strip('"')
        if name.lower() not in ("select", "set", "where") and name not in tables:
            tables.append(name)
        if len(tables) >= 16:
            break
    risks = [name for name, pattern in RISKY_SQL if pattern.search(statement)]
    return {
        "sql_verb": verb["verb"].upper() if verb else None,
        "tables": tables or None,
        "sql_risk": risks or None,
    }


def database_ref(engine: str, host: str | None, database: str) -> dict[str, Any] | None:
    where = host or "db"
    return ref(
        ObjectType.SERVICE.value,
        f"{database}@{where}",
        key=f"{engine}/{where}/{database}",
        kind="database",
        engine=engine,
        database=database,
        host=host,
    )


def account_ref(engine: str, host: str | None, user: str) -> dict[str, Any] | None:
    return ref(
        ObjectType.IDENTITY.value, user, key=f"{engine}/{host or 'db'}/{user}", kind="database-role", engine=engine
    )


def database_record(
    *,
    engine: str,
    host: str | None,
    user: str | None,
    database: str | None,
    client: str | None,
    application: str | None,
    level: str | None,
    message: str,
    timestamp: Any = None,
    duration_ms: float | None = None,
    extra: dict[str, Any] | None = None,
    event_type: str = "db.query",
    outcome: str | None = None,
) -> dict[str, Any]:
    """One database log record: a statement (``db.query``) or a connection/authentication event."""
    statement = message
    attrs: dict[str, Any] = {
        "engine": engine,
        "db_user": user,
        "database": database,
        "application": application,
        "src_ip": ip(client),
        "client": client if client and not ip(client) else None,
        "level": level.lower() if level else None,
        "duration_ms": duration_ms,
        **(extra or {}),
    }
    if event_type == "db.query":
        attrs.update(analyze_sql(statement))
        attrs["statement"] = redact_sql(statement)
    target = database_ref(engine, host, database) if database else ref(ObjectType.SERVICE.value, f"{engine}@{host}")
    actor = account_ref(engine, host, user) if user else ip_ref(client)
    risky = attrs.get("sql_risk")
    shown = (attrs.get("statement") or redact_text(message))[:300]
    return record(
        event_type,
        timestamp=timestamp,
        actor=actor,
        target=target,
        host=host,
        outcome_=outcome,
        severity="medium" if risky else level_severity(level),
        action=(attrs.get("sql_verb") or event_type.rsplit(".", 1)[-1]).lower(),
        message=f"{user or client or 'unknown'}@{database or engine}: {shown}",
        attributes=attrs,
    )


__all__ = ["RISKY_SQL", "account_ref", "analyze_sql", "database_record", "database_ref", "redact_sql"]
