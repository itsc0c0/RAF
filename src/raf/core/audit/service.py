"""Tamper-evident audit log of R$F's own important actions.

Each entry stores ``prev_hash`` and ``entry_hash = sha256(prev_hash + canonical
entry)``. ``verify()`` recomputes the chain; any edited, inserted or deleted row
breaks it.
"""

from __future__ import annotations

import builtins
import getpass
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import Engine, func, select

from raf.core.storage import schema as s
from raf.core.timeutil import format_ts, utcnow

GENESIS = "0" * 64


def current_user() -> str:
    try:
        return getpass.getuser()
    except (KeyError, OSError):  # pragma: no cover - containers without passwd entry
        return "unknown"


def chain_hash(prev_hash: str, payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False)
    return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class AuditEntry:
    id: int
    ts: datetime
    actor: str
    interface: str
    command: str
    workspace: str
    operation: str
    affected: builtins.list[str]
    result: str
    details: dict[str, Any]
    entry_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "ts": format_ts(self.ts),
            "actor": self.actor,
            "interface": self.interface,
            "command": self.command,
            "workspace": self.workspace,
            "operation": self.operation,
            "affected": self.affected,
            "result": self.result,
            "details": self.details,
            "entry_hash": self.entry_hash,
        }


class AuditLog:
    def __init__(
        self, engine: Engine, *, workspace: str, interface: str, command: str = "", actor: str | None = None
    ) -> None:
        self.engine = engine
        self.workspace = workspace
        self.interface = interface
        self.command = command
        self.actor = actor or current_user()

    def record(
        self,
        operation: str,
        *,
        affected: builtins.list[str] | None = None,
        result: str = "success",
        details: dict[str, Any] | None = None,
    ) -> int:
        ts = utcnow()
        affected_list = [str(a) for a in (affected or [])][:500]
        details_dict = dict(details or {})
        with self.engine.begin() as conn:
            row = conn.execute(select(s.audit_log.c.entry_hash).order_by(s.audit_log.c.id.desc()).limit(1)).first()
            prev = row[0] if row else GENESIS
            payload = {
                "ts": format_ts(ts),
                "actor": self.actor,
                "interface": self.interface,
                "command": self.command,
                "workspace": self.workspace,
                "operation": operation,
                "affected": affected_list,
                "result": result,
                "details": details_dict,
            }
            entry_hash = chain_hash(prev, payload)
            res = conn.execute(
                s.audit_log.insert().values(
                    ts=ts,
                    actor=self.actor,
                    interface=self.interface,
                    command=self.command,
                    workspace=self.workspace,
                    operation=operation,
                    affected=affected_list,
                    result=result,
                    details=details_dict,
                    prev_hash=prev,
                    entry_hash=entry_hash,
                )
            )
            return int(res.inserted_primary_key[0]) if res.inserted_primary_key else 0

    def list(self, *, limit: int = 50, operation: str | None = None) -> builtins.list[AuditEntry]:
        stmt = select(s.audit_log).order_by(s.audit_log.c.id.desc()).limit(limit)
        if operation:
            stmt = stmt.where(s.audit_log.c.operation.like(f"{operation}%"))
        with self.engine.connect() as conn:
            rows = conn.execute(stmt).all()
        return [
            AuditEntry(
                r.id,
                r.ts,
                r.actor,
                r.interface,
                r.command,
                r.workspace,
                r.operation,
                list(r.affected or []),
                r.result,
                dict(r.details or {}),
                r.entry_hash,
            )
            for r in rows
        ]

    def count(self) -> int:
        with self.engine.connect() as conn:
            return int(conn.execute(select(func.count()).select_from(s.audit_log)).scalar_one())

    def verify(self) -> dict[str, Any]:
        prev = GENESIS
        checked = 0
        with self.engine.connect() as conn:
            for r in conn.execute(select(s.audit_log).order_by(s.audit_log.c.id)).yield_per(1000):
                payload = {
                    "ts": format_ts(r.ts),
                    "actor": r.actor,
                    "interface": r.interface,
                    "command": r.command,
                    "workspace": r.workspace,
                    "operation": r.operation,
                    "affected": list(r.affected or []),
                    "result": r.result,
                    "details": dict(r.details or {}),
                }
                if r.prev_hash != prev or chain_hash(prev, payload) != r.entry_hash:
                    return {"valid": False, "checked": checked, "broken_at": r.id}
                prev = r.entry_hash
                checked += 1
        return {"valid": True, "checked": checked, "broken_at": None}
