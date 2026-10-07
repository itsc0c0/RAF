"""Object repository: canonical security objects with deterministic merge semantics."""

from __future__ import annotations

import builtins
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import Connection, Engine, delete, func, or_, select

from raf.core.errors import NotFoundError
from raf.core.objects.models import ObjectDraft, SecurityObject, build_object
from raf.core.storage import schema as s
from raf.core.storage.database import chunks, transaction, upsert
from raf.core.timeutil import utcnow


@dataclass(slots=True)
class UpsertStats:
    created: int = 0
    updated: int = 0

    def __iadd__(self, other: UpsertStats) -> UpsertStats:
        self.created += other.created
        self.updated += other.updated
        return self


def object_from_row(row: Any) -> SecurityObject:
    m = row._mapping
    return build_object(
        id=m["id"],
        type=m["type"],
        name=m["name"],
        created_at=m["created_at"],
        updated_at=m["updated_at"],
        first_seen=m["first_seen"],
        last_seen=m["last_seen"],
        valid_from=m["valid_from"],
        valid_to=m["valid_to"],
        source=m["source"],
        confidence=m["confidence"],
        tags=list(m["tags"] or []),
        metadata=dict(m["meta"] or {}),
        observations=m["observations"],
        synthetic=bool(m["synthetic"]),
    )


def draft_from_object(obj: SecurityObject) -> ObjectDraft:
    return ObjectDraft(
        type=obj.type,
        name=obj.name,
        id=obj.id,
        first_seen=obj.first_seen,
        last_seen=obj.last_seen,
        valid_from=obj.valid_from,
        valid_to=obj.valid_to,
        source=obj.source,
        confidence=obj.confidence,
        tags=set(obj.tags),
        metadata=dict(obj.metadata),
        observations=obj.observations,
        synthetic=obj.synthetic,
    )


def _aliases(draft: ObjectDraft) -> builtins.list[str]:
    raw = draft.metadata.get("aliases")
    if not isinstance(raw, list):
        return []
    return sorted({str(a).strip().lower() for a in raw if str(a).strip()})


class ObjectRepository:
    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    # ------------------------------------------------------------------ reads
    def get(self, object_id: str, conn: Connection | None = None) -> SecurityObject | None:
        with transaction(self.engine, conn) as c:
            row = c.execute(select(s.objects).where(s.objects.c.id == object_id)).first()
        return object_from_row(row) if row else None

    def require(self, object_id: str) -> SecurityObject:
        obj = self.get(object_id)
        if obj is None:
            raise NotFoundError(
                f"Object '{object_id}' does not exist in this workspace.",
                suggestions=[f"raf search {object_id.split(':', 1)[-1]}"],
            )
        return obj

    def get_many(self, ids: Iterable[str], conn: Connection | None = None) -> dict[str, SecurityObject]:
        unique = sorted(set(ids))
        result: dict[str, SecurityObject] = {}
        with transaction(self.engine, conn) as c:
            for batch in chunks(unique, 500):
                for row in c.execute(select(s.objects).where(s.objects.c.id.in_(batch))):
                    obj = object_from_row(row)
                    result[obj.id] = obj
        return result

    def existing_ids(self, ids: Iterable[str], conn: Connection | None = None) -> set[str]:
        unique = sorted(set(ids))
        found: set[str] = set()
        with transaction(self.engine, conn) as c:
            for batch in chunks(unique, 500):
                found.update(r[0] for r in c.execute(select(s.objects.c.id).where(s.objects.c.id.in_(batch))))
        return found

    def find_by_name(
        self, name: str, types: Sequence[str] | None = None, conn: Connection | None = None
    ) -> builtins.list[SecurityObject]:
        """Case-insensitive lookup by name or alias."""
        lowered = name.strip().lower()
        alias_ids = select(s.object_aliases.c.object_id).where(s.object_aliases.c.alias_lc == lowered)
        stmt = select(s.objects).where(or_(s.objects.c.name_lc == lowered, s.objects.c.id.in_(alias_ids)))
        if types:
            stmt = stmt.where(s.objects.c.type.in_(list(types)))
        with transaction(self.engine, conn) as c:
            rows = c.execute(stmt.order_by(s.objects.c.type, s.objects.c.id).limit(50)).all()
        return [object_from_row(r) for r in rows]

    def list(
        self,
        *,
        types: Sequence[str] | None = None,
        tag: str | None = None,
        text: str | None = None,
        ids: Sequence[str] | None = None,
        synthetic: bool | None = None,
        limit: int = 100,
        offset: int = 0,
        order: str = "name",
    ) -> builtins.list[SecurityObject]:
        stmt = self._filtered(select(s.objects), types=types, text=text, ids=ids, synthetic=synthetic)
        order_col = {
            "name": s.objects.c.name_lc,
            "id": s.objects.c.id,
            "type": s.objects.c.type,
            "last_seen": s.objects.c.last_seen,
            "updated": s.objects.c.updated_at,
        }.get(order, s.objects.c.name_lc)
        stmt = stmt.order_by(order_col, s.objects.c.id)
        rows: builtins.list[SecurityObject] = []
        with self.engine.connect() as c:
            if tag is None:
                result = c.execute(stmt.limit(limit).offset(offset))
                return [object_from_row(r) for r in result]
            # Tags live in a JSON array; filter portably in Python while streaming.
            skipped = 0
            for row in c.execute(stmt).yield_per(1000):
                obj = object_from_row(row)
                if tag not in obj.tags:
                    continue
                if skipped < offset:
                    skipped += 1
                    continue
                rows.append(obj)
                if len(rows) >= limit:
                    break
        return rows

    def _filtered(
        self,
        stmt: Any,
        *,
        types: Sequence[str] | None,
        text: str | None,
        ids: Sequence[str] | None,
        synthetic: bool | None,
    ) -> Any:
        if types:
            stmt = stmt.where(s.objects.c.type.in_(list(types)))
        if ids is not None:
            stmt = stmt.where(s.objects.c.id.in_(list(ids)))
        if synthetic is not None:
            stmt = stmt.where(s.objects.c.synthetic == synthetic)
        if text:
            pattern = f"%{_escape_like(text.lower())}%"
            stmt = stmt.where(
                or_(s.objects.c.name_lc.like(pattern, escape="\\"), s.objects.c.id.like(pattern, escape="\\"))
            )
        return stmt

    def count(self, *, types: Sequence[str] | None = None, text: str | None = None) -> int:
        stmt = self._filtered(
            select(func.count()).select_from(s.objects), types=types, text=text, ids=None, synthetic=None
        )
        with self.engine.connect() as c:
            return int(c.execute(stmt).scalar_one())

    def count_by_type(self) -> dict[str, int]:
        with self.engine.connect() as c:
            rows = c.execute(select(s.objects.c.type, func.count()).group_by(s.objects.c.type)).all()
        return {str(t): int(n) for t, n in sorted(rows)}

    def iter_all(
        self,
        *,
        types: Sequence[str] | None = None,
        exclude_types: Sequence[str] | None = None,
        batch: int = 2000,
    ) -> Iterator[SecurityObject]:
        stmt = select(s.objects)
        if types:
            stmt = stmt.where(s.objects.c.type.in_(list(types)))
        if exclude_types:
            stmt = stmt.where(s.objects.c.type.not_in(list(exclude_types)))
        with self.engine.connect() as c:
            for row in c.execute(stmt.order_by(s.objects.c.id)).yield_per(batch):
                yield object_from_row(row)

    # ------------------------------------------------------------------ writes
    def upsert_drafts(
        self, drafts: Iterable[ObjectDraft], conn: Connection | None = None, now: datetime | None = None
    ) -> UpsertStats:
        """Merge drafts into the store. Drafts are consumed (may be mutated)."""
        merged: dict[str, ObjectDraft] = {}
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
                existing = {r._mapping["id"]: r for r in c.execute(select(s.objects).where(s.objects.c.id.in_(batch)))}
                rows: builtins.list[dict[str, Any]] = []
                alias_rows: builtins.list[dict[str, Any]] = []
                for oid in batch:
                    draft = merged[oid]
                    row = existing.get(oid)
                    if row is not None:
                        base = draft_from_object(object_from_row(row))
                        base.merge(draft)
                        final, created_at = base, row._mapping["created_at"]
                        stats.updated += 1
                    else:
                        final, created_at = draft, now
                        stats.created += 1
                    rows.append(self._row(final, created_at, now))
                    alias_rows.extend({"alias_lc": a, "object_id": oid} for a in _aliases(final))
                upsert(c, s.objects, rows, ["id"])
                upsert(c, s.object_aliases, alias_rows, ["alias_lc", "object_id"], update=False)
        return stats

    @staticmethod
    def _row(d: ObjectDraft, created_at: datetime, now: datetime) -> dict[str, Any]:
        return {
            "id": d.id,
            "type": d.type,
            "name": d.name,
            "name_lc": d.name.lower(),
            "created_at": created_at,
            "updated_at": now,
            "first_seen": d.first_seen,
            "last_seen": d.last_seen,
            "valid_from": d.valid_from,
            "valid_to": d.valid_to,
            "source": d.source,
            "confidence": d.confidence,
            "tags": sorted(d.tags),
            "meta": d.metadata,
            "observations": d.observations,
            "synthetic": d.synthetic,
        }

    def update_metadata(self, object_id: str, patch: dict[str, Any], conn: Connection | None = None) -> None:
        obj = self.get(object_id, conn)
        if obj is None:
            raise NotFoundError(f"Object '{object_id}' does not exist.")
        draft = draft_from_object(obj)
        draft.metadata.update(patch)
        with transaction(self.engine, conn) as c:
            upsert(c, s.objects, [self._row(draft, obj.created_at, utcnow())], ["id"])

    def delete(self, ids: Iterable[str], conn: Connection | None = None) -> int:
        unique = sorted(set(ids))
        removed = 0
        with transaction(self.engine, conn) as c:
            for batch in chunks(unique, 500):
                removed += c.execute(delete(s.objects).where(s.objects.c.id.in_(batch))).rowcount or 0
                c.execute(delete(s.object_aliases).where(s.object_aliases.c.object_id.in_(batch)))
        return removed

    def ids_by_source_prefix(self, prefix: str) -> builtins.list[str]:
        pattern = _escape_like(prefix) + "%"
        with self.engine.connect() as c:
            return [
                r[0] for r in c.execute(select(s.objects.c.id).where(s.objects.c.source.like(pattern, escape="\\")))
            ]

    def search(
        self, text: str, *, types: Sequence[str] | None = None, limit: int = 25
    ) -> builtins.list[SecurityObject]:
        """Ranked search: exact name/id > alias > prefix > substring."""
        lowered = text.strip().lower()
        if not lowered:
            return []
        pattern = f"%{_escape_like(lowered)}%"
        alias_ids = select(s.object_aliases.c.object_id).where(s.object_aliases.c.alias_lc.like(pattern, escape="\\"))
        stmt = select(s.objects).where(
            or_(
                s.objects.c.name_lc.like(pattern, escape="\\"),
                s.objects.c.id.like(pattern, escape="\\"),
                s.objects.c.id.in_(alias_ids),
            )
        )
        if types:
            stmt = stmt.where(s.objects.c.type.in_(list(types)))
        with self.engine.connect() as c:
            rows = [object_from_row(r) for r in c.execute(stmt.limit(500))]

        def rank(obj: SecurityObject) -> tuple[int, int, str]:
            name = obj.name.lower()
            key = obj.id.split(":", 1)[-1]
            if name == lowered or obj.id == lowered or key == lowered:
                score = 0
            elif lowered in [str(a).lower() for a in obj.metadata.get("aliases", []) or []]:
                score = 1
            elif name.startswith(lowered) or key.startswith(lowered):
                score = 2
            else:
                score = 3
            return (score, len(name), obj.id)

        rows.sort(key=rank)  # ranking is applied in Python for portability
        return rows[:limit]

    def window(self) -> tuple[datetime | None, datetime | None]:
        with self.engine.connect() as c:
            row = c.execute(select(func.min(s.objects.c.first_seen), func.max(s.objects.c.last_seen))).first()
        return (row[0], row[1]) if row else (None, None)


def _escape_like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


escape_like = _escape_like

__all__ = ["ObjectRepository", "UpsertStats", "draft_from_object", "escape_like", "object_from_row"]
