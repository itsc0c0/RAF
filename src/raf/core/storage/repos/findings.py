"""Finding repository: normalized findings across all products."""

from __future__ import annotations

import builtins
from collections.abc import Iterable, Sequence
from datetime import datetime
from typing import Any

from sqlalchemy import Connection, Engine, delete, func, or_, select, update

from raf.core.errors import NotFoundError
from raf.core.objects.models import EvidenceRef, Finding
from raf.core.objects.types import FindingStatus, Severity
from raf.core.storage import schema as s
from raf.core.storage.database import chunks, transaction, upsert
from raf.core.storage.repos.objects import UpsertStats, escape_like
from raf.core.timeutil import utcnow

#: Statuses an analyzer re-run must not override (analyst decisions).
_STICKY = {FindingStatus.FALSE_POSITIVE.value, FindingStatus.SUPPRESSED.value, FindingStatus.ACKNOWLEDGED.value}


def finding_from_row(row: Any) -> Finding:
    m = row._mapping
    return Finding.model_construct(
        id=m["id"],
        title=m["title"],
        description=m["description"],
        severity=Severity(m["severity"]),
        confidence=m["confidence"],
        product=m["product"],
        rule_id=m["rule_id"],
        status=FindingStatus(m["status"]),
        affected_objects=list(m["affected"] or []),
        evidence=[EvidenceRef.model_construct(**e) for e in (m["evidence"] or [])],
        recommendation=m["recommendation"],
        explanation=list(m["explanation"] or []),
        created_at=m["created_at"],
        updated_at=m["updated_at"],
        tags=list(m["tags"] or []),
        metadata=dict(m["meta"] or {}),
    )


class FindingRepository:
    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    def upsert(self, findings: Iterable[Finding], conn: Connection | None = None) -> UpsertStats:
        stats = UpsertStats()
        items = {f.id: f for f in findings}
        if not items:
            return stats
        now = utcnow()
        with transaction(self.engine, conn) as c:
            for batch in chunks(sorted(items), 500):
                existing = {
                    r._mapping["id"]: r._mapping
                    for r in c.execute(select(s.findings).where(s.findings.c.id.in_(batch)))
                }
                rows: builtins.list[dict[str, Any]] = []
                links: builtins.list[dict[str, Any]] = []
                for fid in batch:
                    f = items[fid]
                    prior = existing.get(fid)
                    status = f.status.value
                    created_at = f.created_at
                    if prior is not None:
                        stats.updated += 1
                        created_at = prior["created_at"]
                        if prior["status"] in _STICKY:
                            status = prior["status"]
                    else:
                        stats.created += 1
                    rows.append(
                        {
                            "id": fid,
                            "product": f.product,
                            "rule_id": f.rule_id,
                            "title": f.title,
                            "description": f.description,
                            "severity": f.severity.value,
                            "severity_rank": f.severity.rank,
                            "confidence": f.confidence,
                            "status": status,
                            "recommendation": f.recommendation,
                            "affected": list(f.affected_objects),
                            "evidence": [e.to_json_dict() for e in f.evidence],
                            "explanation": f.explanation,
                            "tags": sorted(set(f.tags)),
                            "meta": f.metadata,
                            "created_at": created_at,
                            "updated_at": now,
                        }
                    )
                    links.extend({"finding_id": fid, "object_id": oid} for oid in dict.fromkeys(f.affected_objects))
                upsert(c, s.findings, rows, ["id"])
                c.execute(delete(s.finding_objects).where(s.finding_objects.c.finding_id.in_(batch)))
                upsert(c, s.finding_objects, links, ["finding_id", "object_id"], update=False)
        return stats

    def get(self, finding_id: str) -> Finding | None:
        with self.engine.connect() as c:
            row = c.execute(select(s.findings).where(s.findings.c.id == finding_id)).first()
        return finding_from_row(row) if row else None

    def require(self, finding_id: str) -> Finding:
        finding = self.get(finding_id)
        if finding is None:
            raise NotFoundError(f"Finding '{finding_id}' does not exist.", suggestions=["raf findings"])
        return finding

    def _filtered(
        self,
        stmt: Any,
        *,
        product: str | None,
        min_severity: Severity | None,
        statuses: Sequence[str] | None,
        object_id: str | None,
        text: str | None,
        rule_id: str | None,
    ) -> Any:
        c = s.findings.c
        if product:
            stmt = stmt.where(c.product == product)
        if rule_id:
            stmt = stmt.where(c.rule_id == rule_id)
        if min_severity is not None:
            stmt = stmt.where(c.severity_rank >= min_severity.rank)
        if statuses:
            stmt = stmt.where(c.status.in_(list(statuses)))
        if object_id:
            stmt = stmt.where(
                c.id.in_(select(s.finding_objects.c.finding_id).where(s.finding_objects.c.object_id == object_id))
            )
        if text:
            pattern = f"%{escape_like(text.lower())}%"
            stmt = stmt.where(
                or_(func.lower(c.title).like(pattern, escape="\\"), func.lower(c.id).like(pattern, escape="\\"))
            )
        return stmt

    def list(
        self,
        *,
        product: str | None = None,
        min_severity: Severity | None = None,
        statuses: Sequence[str] | None = None,
        object_id: str | None = None,
        text: str | None = None,
        rule_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> builtins.list[Finding]:
        stmt = self._filtered(
            select(s.findings),
            product=product,
            min_severity=min_severity,
            statuses=statuses,
            object_id=object_id,
            text=text,
            rule_id=rule_id,
        )
        stmt = (
            stmt.order_by(s.findings.c.severity_rank.desc(), s.findings.c.confidence.desc(), s.findings.c.id)
            .limit(limit)
            .offset(offset)
        )
        with self.engine.connect() as c:
            return [finding_from_row(r) for r in c.execute(stmt)]

    def count(
        self,
        *,
        product: str | None = None,
        min_severity: Severity | None = None,
        statuses: Sequence[str] | None = None,
        object_id: str | None = None,
        text: str | None = None,
    ) -> int:
        stmt = self._filtered(
            select(func.count()).select_from(s.findings),
            product=product,
            min_severity=min_severity,
            statuses=statuses,
            object_id=object_id,
            text=text,
            rule_id=None,
        )
        with self.engine.connect() as c:
            return int(c.execute(stmt).scalar_one())

    def count_by_severity(self, statuses: Sequence[str] | None = None) -> dict[str, int]:
        stmt = select(s.findings.c.severity, func.count()).group_by(s.findings.c.severity)
        if statuses:
            stmt = stmt.where(s.findings.c.status.in_(list(statuses)))
        with self.engine.connect() as c:
            rows: dict[str, int] = {str(k): int(v) for k, v in c.execute(stmt).all()}
        return {sev.value: int(rows.get(sev.value, 0)) for sev in Severity}

    def set_status(self, finding_id: str, status: FindingStatus, note: str | None = None) -> Finding:
        finding = self.require(finding_id)
        meta = dict(finding.metadata)
        history = list(meta.get("status_history", []))
        history.append({"from": finding.status.value, "to": status.value, "note": note, "at": utcnow().isoformat()})
        meta["status_history"] = history[-50:]
        with self.engine.begin() as c:
            c.execute(
                update(s.findings)
                .where(s.findings.c.id == finding_id)
                .values(status=status.value, meta=meta, updated_at=utcnow())
            )
        return self.require(finding_id)

    def resolve_absent(
        self, product: str, rule_ids: Sequence[str], present_ids: Iterable[str], conn: Connection | None = None
    ) -> int:
        """Auto-resolve open findings of the given rules that a re-run no longer produced."""
        present = set(present_ids)
        resolved = 0
        with transaction(self.engine, conn) as c:
            rows = c.execute(
                select(s.findings.c.id).where(
                    s.findings.c.product == product,
                    s.findings.c.rule_id.in_(list(rule_ids)),
                    s.findings.c.status == FindingStatus.OPEN.value,
                )
            ).all()
            stale = [r[0] for r in rows if r[0] not in present]
            for batch in chunks(stale, 500):
                resolved += (
                    c.execute(
                        update(s.findings)
                        .where(s.findings.c.id.in_(batch))
                        .values(status=FindingStatus.RESOLVED.value, updated_at=utcnow())
                    ).rowcount
                    or 0
                )
        return resolved

    def delete_for_product(self, product: str, before: datetime | None = None) -> int:
        with self.engine.begin() as c:
            stmt = select(s.findings.c.id).where(s.findings.c.product == product)
            if before is not None:
                stmt = stmt.where(s.findings.c.updated_at < before)
            ids = [r[0] for r in c.execute(stmt)]
            for batch in chunks(ids, 500):
                c.execute(delete(s.finding_objects).where(s.finding_objects.c.finding_id.in_(batch)))
                c.execute(delete(s.findings).where(s.findings.c.id.in_(batch)))
        return len(ids)
