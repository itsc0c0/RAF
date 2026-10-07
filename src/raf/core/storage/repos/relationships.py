"""Relationship repository: first-class, temporal, provenance-backed relationships."""

from __future__ import annotations

import builtins
from collections.abc import Iterable, Iterator, Sequence
from datetime import datetime
from typing import Any, Literal

from sqlalchemy import Connection, Engine, and_, delete, func, or_, select, update

from raf.core.objects.models import Relationship, RelationshipDraft
from raf.core.storage import schema as s
from raf.core.storage.database import chunks, transaction, upsert
from raf.core.storage.repos.objects import UpsertStats
from raf.core.timeutil import utcnow

Direction = Literal["out", "in", "both"]


def relationship_from_row(row: Any) -> Relationship:
    m = row._mapping
    return Relationship.model_construct(
        id=m["id"],
        relationship_type=m["type"],
        source_object=m["source_id"],
        target_object=m["target_id"],
        first_seen=m["first_seen"],
        last_seen=m["last_seen"],
        valid_from=m["valid_from"],
        valid_to=m["valid_to"],
        confidence=m["confidence"],
        source=m["source"],
        metadata=dict(m["meta"] or {}),
        observations=m["observations"],
        created_at=m["created_at"],
        updated_at=m["updated_at"],
        synthetic=bool(m["synthetic"]),
    )


def draft_from_relationship(rel: Relationship) -> RelationshipDraft:
    return RelationshipDraft(
        type=rel.relationship_type,
        source_id=rel.source_object,
        target_id=rel.target_object,
        id=rel.id,
        first_seen=rel.first_seen,
        last_seen=rel.last_seen,
        valid_from=rel.valid_from,
        valid_to=rel.valid_to,
        source=rel.source,
        confidence=rel.confidence,
        metadata=dict(rel.metadata),
        observations=rel.observations,
        synthetic=rel.synthetic,
    )


def temporal_clause(at: datetime | None) -> Any:
    """SQL clause selecting relationships valid at ``at`` (or currently active when None)."""
    c = s.relationships.c
    if at is None:
        return c.valid_to.is_(None)
    start = func.coalesce(c.valid_from, c.first_seen)
    return and_(or_(start.is_(None), start <= at), or_(c.valid_to.is_(None), c.valid_to > at))


class RelationshipRepository:
    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    def get(self, rel_id: str) -> Relationship | None:
        with self.engine.connect() as c:
            row = c.execute(select(s.relationships).where(s.relationships.c.id == rel_id)).first()
        return relationship_from_row(row) if row else None

    def get_many(self, ids: Iterable[str]) -> dict[str, Relationship]:
        result: dict[str, Relationship] = {}
        with self.engine.connect() as c:
            for batch in chunks(sorted(set(ids)), 500):
                for row in c.execute(select(s.relationships).where(s.relationships.c.id.in_(batch))):
                    rel = relationship_from_row(row)
                    result[rel.id] = rel
        return result

    def edges(
        self,
        object_ids: Sequence[str],
        *,
        direction: Direction = "both",
        types: Sequence[str] | None = None,
        at: datetime | None = None,
        include_inactive: bool = False,
        conn: Connection | None = None,
    ) -> builtins.list[Relationship]:
        """Relationships touching ``object_ids`` (batched; ordered deterministically)."""
        results: dict[str, Relationship] = {}
        c_ = s.relationships.c
        with transaction(self.engine, conn) as c:
            for batch in chunks(sorted(set(object_ids)), 400):
                clauses = []
                if direction in ("out", "both"):
                    clauses.append(c_.source_id.in_(batch))
                if direction in ("in", "both"):
                    clauses.append(c_.target_id.in_(batch))
                stmt = select(s.relationships).where(or_(*clauses))
                if types:
                    stmt = stmt.where(c_.type.in_(list(types)))
                if not include_inactive or at is not None:
                    stmt = stmt.where(temporal_clause(at))
                for row in c.execute(stmt):
                    rel = relationship_from_row(row)
                    results[rel.id] = rel
        return sorted(results.values(), key=lambda r: (r.source_object, r.relationship_type, r.target_object))

    def between(self, a: str, b: str) -> builtins.list[Relationship]:
        c_ = s.relationships.c
        stmt = select(s.relationships).where(
            or_(and_(c_.source_id == a, c_.target_id == b), and_(c_.source_id == b, c_.target_id == a))
        )
        with self.engine.connect() as c:
            return [relationship_from_row(r) for r in c.execute(stmt)]

    def list(
        self,
        *,
        types: Sequence[str] | None = None,
        source: str | None = None,
        target: str | None = None,
        include_inactive: bool = True,
        limit: int = 100,
        offset: int = 0,
    ) -> builtins.list[Relationship]:
        c_ = s.relationships.c
        stmt = select(s.relationships)
        if types:
            stmt = stmt.where(c_.type.in_(list(types)))
        if source:
            stmt = stmt.where(c_.source_id == source)
        if target:
            stmt = stmt.where(c_.target_id == target)
        if not include_inactive:
            stmt = stmt.where(c_.valid_to.is_(None))
        stmt = stmt.order_by(c_.source_id, c_.type, c_.target_id).limit(limit).offset(offset)
        with self.engine.connect() as c:
            return [relationship_from_row(r) for r in c.execute(stmt)]

    def count(self, *, types: Sequence[str] | None = None) -> int:
        stmt = select(func.count()).select_from(s.relationships)
        if types:
            stmt = stmt.where(s.relationships.c.type.in_(list(types)))
        with self.engine.connect() as c:
            return int(c.execute(stmt).scalar_one())

    def count_by_type(self) -> dict[str, int]:
        with self.engine.connect() as c:
            rows = c.execute(select(s.relationships.c.type, func.count()).group_by(s.relationships.c.type)).all()
        return {str(t): int(n) for t, n in sorted(rows)}

    def iter_all(self, *, batch: int = 5000, types: Sequence[str] | None = None) -> Iterator[Relationship]:
        stmt = select(s.relationships)
        if types:
            stmt = stmt.where(s.relationships.c.type.in_(list(types)))
        with self.engine.connect() as c:
            for row in c.execute(stmt.order_by(s.relationships.c.id)).yield_per(batch):
                yield relationship_from_row(row)

    def upsert_drafts(
        self, drafts: Iterable[RelationshipDraft], conn: Connection | None = None, now: datetime | None = None
    ) -> UpsertStats:
        merged: dict[str, RelationshipDraft] = {}
        for draft in drafts:
            current = merged.get(draft.id)
            if current is None:
                merged[draft.id] = draft
            else:
                current.merge(draft)
        stats = UpsertStats()
        if not merged:
            return stats
        now = now or utcnow()
        with transaction(self.engine, conn) as c:
            for batch in chunks(sorted(merged), 500):
                existing = {
                    r._mapping["id"]: r
                    for r in c.execute(select(s.relationships).where(s.relationships.c.id.in_(batch)))
                }
                rows = []
                for rid in batch:
                    draft = merged[rid]
                    row = existing.get(rid)
                    if row is not None:
                        base = draft_from_relationship(relationship_from_row(row))
                        base.merge(draft)
                        final, created_at = base, row._mapping["created_at"]
                        stats.updated += 1
                    else:
                        final, created_at = draft, now
                        stats.created += 1
                    rows.append(self._row(final, created_at, now))
                upsert(c, s.relationships, rows, ["id"])
        return stats

    @staticmethod
    def _row(d: RelationshipDraft, created_at: datetime, now: datetime) -> dict[str, Any]:
        return {
            "id": d.id,
            "type": d.type,
            "source_id": d.source_id,
            "target_id": d.target_id,
            "created_at": created_at,
            "updated_at": now,
            "first_seen": d.first_seen,
            "last_seen": d.last_seen,
            "valid_from": d.valid_from,
            "valid_to": d.valid_to,
            "source": d.source,
            "confidence": d.confidence,
            "meta": d.metadata,
            "observations": d.observations,
            "synthetic": d.synthetic,
        }

    def end(self, rel_ids: Iterable[str], at: datetime, conn: Connection | None = None) -> int:
        """Mark relationships as no longer valid from ``at`` (temporal end, not deletion)."""
        changed = 0
        with transaction(self.engine, conn) as c:
            for batch in chunks(sorted(set(rel_ids)), 500):
                result = c.execute(
                    update(s.relationships)
                    .where(s.relationships.c.id.in_(batch))
                    .values(valid_to=at, updated_at=utcnow())
                )
                changed += result.rowcount or 0
        return changed

    def delete(self, ids: Iterable[str], conn: Connection | None = None) -> int:
        removed = 0
        with transaction(self.engine, conn) as c:
            for batch in chunks(sorted(set(ids)), 500):
                removed += c.execute(delete(s.relationships).where(s.relationships.c.id.in_(batch))).rowcount or 0
        return removed

    def delete_touching(self, object_ids: Iterable[str], conn: Connection | None = None) -> int:
        removed = 0
        c_ = s.relationships.c
        with transaction(self.engine, conn) as c:
            for batch in chunks(sorted(set(object_ids)), 400):
                removed += (
                    c.execute(
                        delete(s.relationships).where(or_(c_.source_id.in_(batch), c_.target_id.in_(batch)))
                    ).rowcount
                    or 0
                )
        return removed
