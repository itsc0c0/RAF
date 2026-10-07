"""Small repositories: provenance, counters, key-value state."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from sqlalchemy import Connection, Engine, delete, func, select, update

from raf.core.objects.models import ProvenanceDraft, ProvenanceRecord
from raf.core.storage import schema as s
from raf.core.storage.database import transaction, upsert
from raf.core.timeutil import utcnow


class ProvenanceRepository:
    """Every derived fact keeps where it came from (source, record, parser, event, evidence)."""

    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    def add_many(
        self, drafts: Iterable[ProvenanceDraft], *, job_id: str | None = None, conn: Connection | None = None
    ) -> int:
        now = utcnow()
        rows = [
            {
                "subject_id": d.subject_id,
                "subject_kind": d.subject_kind,
                "event_id": d.event_id,
                "source": d.source,
                "source_sha256": d.source_sha256,
                "record": d.record,
                "parser": d.parser,
                "observed_at": d.observed_at,
                "job_id": job_id,
                "evidence_id": d.evidence_id,
                "note": d.note,
                "recorded_at": now,
            }
            for d in drafts
        ]
        if not rows:
            return 0
        with transaction(self.engine, conn) as c:
            for start in range(0, len(rows), 1000):
                c.execute(s.provenance.insert(), rows[start : start + 1000])
        return len(rows)

    def for_subject(self, subject_id: str, limit: int = 50) -> list[ProvenanceRecord]:
        stmt = (
            select(s.provenance)
            .where(s.provenance.c.subject_id == subject_id)
            .order_by(s.provenance.c.observed_at, s.provenance.c.id)
            .limit(limit)
        )
        with self.engine.connect() as c:
            rows = c.execute(stmt).all()
        return [
            ProvenanceRecord.model_construct(
                subject_id=r.subject_id,
                subject_kind=r.subject_kind,
                source=r.source,
                parser=r.parser,
                record=r.record,
                event_id=r.event_id,
                observed_at=r.observed_at,
                evidence_id=r.evidence_id,
                source_sha256=r.source_sha256,
                job_id=r.job_id,
                note=r.note,
                recorded_at=r.recorded_at,
            )
            for r in rows
        ]

    def count_for_subject(self, subject_id: str) -> int:
        with self.engine.connect() as c:
            return int(
                c.execute(
                    select(func.count()).select_from(s.provenance).where(s.provenance.c.subject_id == subject_id)
                ).scalar_one()
            )

    def subjects_for_jobs(
        self, job_ids: Iterable[str], kind: str | None = None, *, source: str | None = None
    ) -> set[str]:
        stmt = select(s.provenance.c.subject_id).where(s.provenance.c.job_id.in_(list(job_ids))).distinct()
        if kind:
            stmt = stmt.where(s.provenance.c.subject_kind == kind)
        if source:
            stmt = stmt.where(s.provenance.c.source == source)
        with self.engine.connect() as c:
            return {r[0] for r in c.execute(stmt)}

    def jobs_for_sources(self, digests: Iterable[str]) -> list[str]:
        """Jobs that imported data from sources with these SHA-256 digests (oldest job first)."""
        wanted = sorted({d for d in digests if d})
        if not wanted:
            return []
        stmt = (
            select(s.provenance.c.job_id)
            .where(s.provenance.c.source_sha256.in_(wanted), s.provenance.c.job_id.is_not(None))
            .distinct()
        )
        with self.engine.connect() as c:
            jobs = [str(r[0]) for r in c.execute(stmt)]
        return sorted(jobs, key=lambda j: (len(j), j))

    def source_digests(self, job_id: str) -> set[str]:
        """SHA-256 digests of the sources a job imported."""
        stmt = (
            select(s.provenance.c.source_sha256)
            .where(s.provenance.c.job_id == job_id, s.provenance.c.source_sha256.is_not(None))
            .distinct()
        )
        with self.engine.connect() as c:
            return {str(r[0]) for r in c.execute(stmt)}

    def source_names(self, job_id: str, digest: str) -> set[str]:
        """Names under which a job recorded the source with this digest."""
        stmt = (
            select(s.provenance.c.source)
            .where(s.provenance.c.job_id == job_id, s.provenance.c.source_sha256 == digest)
            .distinct()
        )
        with self.engine.connect() as c:
            return {str(r[0]) for r in c.execute(stmt)}

    def jobs_for_subjects(self, subject_ids: Iterable[str]) -> dict[str, set[str | None]]:
        """Which jobs contributed provenance to each subject (``None`` = written outside a job)."""
        ids = sorted(set(subject_ids))
        result: dict[str, set[str | None]] = {}
        with self.engine.connect() as c:
            for start in range(0, len(ids), 500):
                stmt = (
                    select(s.provenance.c.subject_id, s.provenance.c.job_id)
                    .where(s.provenance.c.subject_id.in_(ids[start : start + 500]))
                    .distinct()
                )
                for subject, job in c.execute(stmt):
                    result.setdefault(subject, set()).add(job)
        return result

    def delete_for_jobs(self, job_ids: Iterable[str], conn: Connection | None = None) -> int:
        jobs = sorted(set(job_ids))
        removed = 0
        with transaction(self.engine, conn) as c:
            for start in range(0, len(jobs), 500):
                removed += (
                    c.execute(delete(s.provenance).where(s.provenance.c.job_id.in_(jobs[start : start + 500]))).rowcount
                    or 0
                )
        return removed

    def delete_for_subjects(self, subject_ids: Iterable[str], conn: Connection | None = None) -> None:
        ids = sorted(set(subject_ids))
        with transaction(self.engine, conn) as c:
            for start in range(0, len(ids), 500):
                c.execute(delete(s.provenance).where(s.provenance.c.subject_id.in_(ids[start : start + 500])))


class CounterRepository:
    """Monotonic per-workspace counters for human-friendly IDs (job-12, analysis-3)."""

    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    def next(self, name: str, conn: Connection | None = None) -> int:
        with transaction(self.engine, conn) as c:
            row = c.execute(select(s.counters.c.value).where(s.counters.c.name == name)).first()
            if row is None:
                c.execute(s.counters.insert().values(name=name, value=1))
                return 1
            value = int(row[0]) + 1
            c.execute(update(s.counters).where(s.counters.c.name == name).values(value=value))
            return value


class KVRepository:
    """Namespaced key-value state for products (small JSON documents only)."""

    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    def get(self, namespace: str, key: str, default: Any = None) -> Any:
        with self.engine.connect() as c:
            row = c.execute(select(s.kv.c.value).where(s.kv.c.namespace == namespace, s.kv.c.key == key)).first()
        return row[0] if row else default

    def set(self, namespace: str, key: str, value: Any, conn: Connection | None = None) -> None:
        with transaction(self.engine, conn) as c:
            upsert(
                c,
                s.kv,
                [{"namespace": namespace, "key": key, "value": value, "updated_at": utcnow()}],
                ["namespace", "key"],
            )

    def delete(self, namespace: str, key: str) -> None:
        with self.engine.begin() as c:
            c.execute(delete(s.kv).where(s.kv.c.namespace == namespace, s.kv.c.key == key))

    def items(self, namespace: str) -> dict[str, Any]:
        with self.engine.connect() as c:
            rows = c.execute(
                select(s.kv.c.key, s.kv.c.value).where(s.kv.c.namespace == namespace).order_by(s.kv.c.key)
            ).all()
        return {str(k): v for k, v in rows}
