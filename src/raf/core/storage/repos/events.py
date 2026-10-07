"""Event repository: canonical normalized events with object/incident indexes."""

from __future__ import annotations

import base64
from collections import defaultdict
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import BigInteger, Connection, Engine, Integer, and_, cast, delete, func, or_, select, text

from raf.core.errors import InvalidInputError
from raf.core.objects.models import Event, EventDraft, EventObject
from raf.core.objects.types import Severity
from raf.core.storage import schema as s
from raf.core.storage.database import chunks, transaction, upsert
from raf.core.storage.repos.objects import escape_like
from raf.core.timeutil import format_ts, parse_timestamp, utcnow


@dataclass(slots=True)
class EventQuery:
    start: datetime | None = None
    end: datetime | None = None
    event_types: Sequence[str] | None = None  # exact or prefix ("auth.*" / "auth")
    categories: Sequence[str] | None = None
    object_ids: Sequence[str] | None = None  # involved in any role
    object_groups: Sequence[Sequence[str]] | None = None  # and, for every group, one of its objects is involved
    actor: str | None = None
    target: str | None = None
    incident_id: str | None = None
    job_ids: Sequence[str] | None = None
    event_ids: Sequence[str] | None = None
    min_severity: Severity | None = None
    max_severity: Severity | None = None
    min_confidence: float | None = None
    max_confidence: float | None = None
    outcome: str | None = None
    source: str | None = None
    text: str | None = None
    texts: Sequence[str] | None = None  # further texts that must all match, like ``text``
    synthetic: bool | None = None

    def with_(self, **changes: Any) -> EventQuery:
        return replace(self, **changes)


@dataclass(slots=True)
class EventPage:
    items: list[Event]
    next_cursor: str | None
    total: int | None = None


@dataclass(slots=True)
class InsertStats:
    created: int = 0
    duplicates: int = 0
    created_ids: list[str] = field(default_factory=list)


def encode_cursor(ts: datetime, event_id: str) -> str:
    return base64.urlsafe_b64encode(f"{format_ts(ts)}|{event_id}".encode()).decode()


def decode_cursor(cursor: str) -> tuple[datetime, str]:
    try:
        raw = base64.urlsafe_b64decode(cursor.encode()).decode()
        ts_text, event_id = raw.split("|", 1)
        return parse_timestamp(ts_text), event_id
    except (ValueError, UnicodeDecodeError) as exc:
        raise InvalidInputError("Invalid pagination cursor.") from exc


def event_from_row(row: Any, objects: list[EventObject] | None = None, incidents: list[str] | None = None) -> Event:
    m = row._mapping
    return Event.model_construct(
        id=m["id"],
        timestamp=m["ts"],
        event_type=m["event_type"],
        category=m["category"],
        action=m["action"],
        outcome=m["outcome"],
        actor=m["actor_id"],
        target=m["target_id"],
        objects=objects or [],
        source=m["source"],
        parser=m["parser"],
        record=m["record"],
        raw_reference=m["raw_ref"],
        raw=m["raw"],
        severity=Severity(m["severity"]),
        confidence=m["confidence"],
        attributes=dict(m["attributes"] or {}),
        relationships=list(m["rel_ids"] or []),
        message=m["message"],
        synthetic=bool(m["synthetic"]),
        job_id=m["job_id"],
        incidents=incidents or [],
        ingested_at=m["ingested_at"],
    )


class EventRepository:
    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    # ------------------------------------------------------------------ writes
    def insert_drafts(
        self, drafts: Sequence[EventDraft], *, job_id: str | None = None, conn: Connection | None = None
    ) -> InsertStats:
        stats = InsertStats()
        if not drafts:
            return stats
        now = utcnow()
        unique: dict[str, EventDraft] = {}
        for draft in drafts:
            if draft.id in unique:
                stats.duplicates += 1
            else:
                unique[draft.id] = draft
        with transaction(self.engine, conn) as c:
            existing: set[str] = set()
            for batch in chunks(list(unique), 500):
                existing.update(r[0] for r in c.execute(select(s.events.c.id).where(s.events.c.id.in_(batch))))
            stats.duplicates += len(existing)
            rows: list[dict[str, Any]] = []
            obj_rows: list[dict[str, Any]] = []
            inc_rows: list[dict[str, Any]] = []
            for eid, d in unique.items():
                if eid in existing:
                    continue
                rows.append(
                    {
                        "id": eid,
                        "ts": d.timestamp,
                        "event_type": d.event_type,
                        "category": d.category,
                        "action": d.action,
                        "outcome": d.outcome,
                        "actor_id": d.actor,
                        "target_id": d.target,
                        "severity": d.severity.value,
                        "confidence": d.confidence,
                        "source": d.source,
                        "parser": d.parser,
                        "record": d.record,
                        "raw_ref": d.raw_reference,
                        "raw": d.raw,
                        "attributes": d.attributes,
                        "rel_ids": d.relationships,
                        "message": d.message,
                        "synthetic": d.synthetic,
                        "job_id": job_id,
                        "ingested_at": now,
                    }
                )
                seen: set[tuple[str, str]] = set()
                for ref in d.objects:
                    key = (ref.object_id, ref.role)
                    if key in seen:
                        continue
                    seen.add(key)
                    obj_rows.append({"event_id": eid, "object_id": ref.object_id, "role": ref.role, "ts": d.timestamp})
                for incident in dict.fromkeys(d.incidents):
                    inc_rows.append({"incident_id": incident, "event_id": eid, "ts": d.timestamp})
                stats.created_ids.append(eid)
            upsert(c, s.events, rows, ["id"], update=False)
            upsert(c, s.event_objects, obj_rows, ["event_id", "object_id", "role"], update=False)
            upsert(c, s.incident_events, inc_rows, ["incident_id", "event_id"], update=False)
            stats.created = len(rows)
        return stats

    def link_incident(self, incident_id: str, event_ids: Iterable[str], conn: Connection | None = None) -> int:
        ids = sorted(set(event_ids))
        linked = 0
        with transaction(self.engine, conn) as c:
            for batch in chunks(ids, 500):
                rows = c.execute(select(s.events.c.id, s.events.c.ts).where(s.events.c.id.in_(batch))).all()
                upsert(
                    c,
                    s.incident_events,
                    [{"incident_id": incident_id, "event_id": r[0], "ts": r[1]} for r in rows],
                    ["incident_id", "event_id"],
                    update=False,
                )
                linked += len(rows)
        return linked

    def delete(self, query: EventQuery, conn: Connection | None = None) -> int:
        ids = list(self._ids(query))
        removed = 0
        with transaction(self.engine, conn) as c:
            for batch in chunks(ids, 500):
                c.execute(delete(s.event_objects).where(s.event_objects.c.event_id.in_(batch)))
                c.execute(delete(s.incident_events).where(s.incident_events.c.event_id.in_(batch)))
                removed += c.execute(delete(s.events).where(s.events.c.id.in_(batch))).rowcount or 0
        return removed

    # ------------------------------------------------------------------ reads
    def _where(self, stmt: Any, q: EventQuery) -> Any:
        c = s.events.c
        if q.start is not None:
            stmt = stmt.where(c.ts >= q.start)
        if q.end is not None:
            stmt = stmt.where(c.ts <= q.end)
        if q.event_types:
            clauses = []
            for et in q.event_types:
                et = et.strip()
                if et.endswith(".*") or "." not in et:
                    prefix = et[:-2] if et.endswith(".*") else et
                    clauses.append(
                        or_(c.event_type == prefix, c.event_type.like(escape_like(prefix) + ".%", escape="\\"))
                    )
                else:
                    clauses.append(c.event_type == et)
            stmt = stmt.where(or_(*clauses))
        if q.categories:
            stmt = stmt.where(c.category.in_(list(q.categories)))
        for group in [*([q.object_ids] if q.object_ids else []), *(q.object_groups or [])]:
            sub = select(s.event_objects.c.event_id).where(s.event_objects.c.object_id.in_(list(group)))
            stmt = stmt.where(c.id.in_(sub))
        if q.actor:
            stmt = stmt.where(c.actor_id == q.actor)
        if q.target:
            stmt = stmt.where(c.target_id == q.target)
        if q.incident_id:
            sub = select(s.incident_events.c.event_id).where(s.incident_events.c.incident_id == q.incident_id)
            stmt = stmt.where(c.id.in_(sub))
        if q.job_ids:
            stmt = stmt.where(c.job_id.in_(list(q.job_ids)))
        if q.event_ids is not None:
            stmt = stmt.where(c.id.in_(list(q.event_ids)))
        if q.min_severity is not None:
            allowed = [sev.value for sev in Severity if sev.rank >= q.min_severity.rank]
            stmt = stmt.where(c.severity.in_(allowed))
        if q.max_severity is not None:
            allowed = [sev.value for sev in Severity if sev.rank <= q.max_severity.rank]
            stmt = stmt.where(c.severity.in_(allowed))
        if q.min_confidence is not None:
            stmt = stmt.where(c.confidence >= q.min_confidence)
        if q.max_confidence is not None:
            stmt = stmt.where(c.confidence <= q.max_confidence)
        if q.outcome:
            stmt = stmt.where(c.outcome == q.outcome)
        if q.source:
            stmt = stmt.where(c.source.like(f"%{escape_like(q.source)}%", escape="\\"))
        if q.synthetic is not None:
            stmt = stmt.where(c.synthetic == q.synthetic)
        for wanted in [*([q.text] if q.text else []), *(q.texts or [])]:
            pattern = f"%{escape_like(wanted.lower())}%"
            stmt = stmt.where(
                or_(
                    func.lower(c.message).like(pattern, escape="\\"),
                    func.lower(c.event_type).like(pattern, escape="\\"),
                    func.lower(c.actor_id).like(pattern, escape="\\"),
                    func.lower(c.target_id).like(pattern, escape="\\"),
                    func.lower(c.raw).like(pattern, escape="\\"),
                )
            )
        return stmt

    def _ids(self, q: EventQuery) -> Iterator[str]:
        with self.engine.connect() as c:
            for row in c.execute(self._where(select(s.events.c.id), q)).yield_per(5000):
                yield row[0]

    def get(self, event_id: str) -> Event | None:
        page = self.query(EventQuery(event_ids=[event_id]), limit=1)
        return page.items[0] if page.items else None

    def get_many(self, ids: Iterable[str]) -> dict[str, Event]:
        result: dict[str, Event] = {}
        for batch in chunks(sorted(set(ids)), 500):
            for ev in self.query(EventQuery(event_ids=list(batch)), limit=len(batch)).items:
                result[ev.id] = ev
        return result

    def query(
        self,
        q: EventQuery,
        *,
        limit: int = 100,
        cursor: str | None = None,
        descending: bool = False,
        with_objects: bool = True,
    ) -> EventPage:
        c = s.events.c
        stmt = self._where(select(s.events), q)
        if cursor:
            cts, cid = decode_cursor(cursor)
            if descending:
                stmt = stmt.where(or_(c.ts < cts, and_(c.ts == cts, c.id < cid)))
            else:
                stmt = stmt.where(or_(c.ts > cts, and_(c.ts == cts, c.id > cid)))
        order = (c.ts.desc(), c.id.desc()) if descending else (c.ts.asc(), c.id.asc())
        stmt = stmt.order_by(*order).limit(limit + 1)
        with self.engine.connect() as conn:
            rows = conn.execute(stmt).all()
            has_more = len(rows) > limit
            rows = rows[:limit]
            ids = [r._mapping["id"] for r in rows]
            objects = self._objects_for(conn, ids) if with_objects else {}
            incidents = self._incidents_for(conn, ids) if with_objects else {}
        items = [event_from_row(r, objects.get(r._mapping["id"]), incidents.get(r._mapping["id"])) for r in rows]
        next_cursor = encode_cursor(items[-1].timestamp, items[-1].id) if has_more and items else None
        return EventPage(items=items, next_cursor=next_cursor)

    def iter(self, q: EventQuery, *, batch: int = 2000, with_objects: bool = True) -> Iterator[Event]:
        """Stream all matching events in (timestamp, id) order."""
        cursor: str | None = None
        while True:
            page = self.query(q, limit=batch, cursor=cursor, with_objects=with_objects)
            yield from page.items
            if not page.next_cursor:
                return
            cursor = page.next_cursor

    def _objects_for(self, conn: Connection, ids: Sequence[str]) -> dict[str, list[EventObject]]:
        result: dict[str, list[EventObject]] = defaultdict(list)
        for batch in chunks(list(ids), 500):
            stmt = (
                select(s.event_objects.c.event_id, s.event_objects.c.object_id, s.event_objects.c.role)
                .where(s.event_objects.c.event_id.in_(batch))
                .order_by(s.event_objects.c.event_id, s.event_objects.c.role, s.event_objects.c.object_id)
            )
            for eid, oid, role in conn.execute(stmt):
                result[eid].append(EventObject.model_construct(object_id=oid, role=role))
        return result

    def _incidents_for(self, conn: Connection, ids: Sequence[str]) -> dict[str, list[str]]:
        result: dict[str, list[str]] = defaultdict(list)
        for batch in chunks(list(ids), 500):
            stmt = (
                select(s.incident_events.c.event_id, s.incident_events.c.incident_id)
                .where(s.incident_events.c.event_id.in_(batch))
                .order_by(s.incident_events.c.incident_id)
            )
            for eid, iid in conn.execute(stmt):
                result[eid].append(iid)
        return result

    def count(self, q: EventQuery | None = None) -> int:
        stmt = self._where(select(func.count()).select_from(s.events), q or EventQuery())
        with self.engine.connect() as c:
            return int(c.execute(stmt).scalar_one())

    def bounds(self, q: EventQuery | None = None) -> tuple[datetime | None, datetime | None]:
        stmt = self._where(select(func.min(s.events.c.ts), func.max(s.events.c.ts)), q or EventQuery())
        with self.engine.connect() as c:
            row = c.execute(stmt).first()
        if not row or row[0] is None:
            return None, None
        lo, hi = row[0], row[1]
        # Aggregates bypass the column type on some backends; normalize.
        return _as_utc(lo), _as_utc(hi)

    _GROUPABLE = {
        "event_type": s.events.c.event_type,
        "category": s.events.c.category,
        "actor": s.events.c.actor_id,
        "target": s.events.c.target_id,
        "severity": s.events.c.severity,
        "source": s.events.c.source,
        "outcome": s.events.c.outcome,
        "parser": s.events.c.parser,
    }

    def group_counts(self, q: EventQuery, field_name: str, limit: int = 50) -> list[tuple[str | None, int]]:
        column = self._GROUPABLE.get(field_name)
        if column is None:
            raise InvalidInputError(
                f"Cannot group events by '{field_name}'.", hint="Group by one of: " + ", ".join(sorted(self._GROUPABLE))
            )
        stmt = self._where(select(column, func.count().label("n")), q).group_by(column)
        stmt = stmt.order_by(func.count().desc(), column).limit(limit)
        with self.engine.connect() as c:
            return [(r[0], int(r[1])) for r in c.execute(stmt)]

    def histogram(self, q: EventQuery, buckets: int = 60) -> list[dict[str, Any]]:
        """Event counts in equal-width time buckets over the matching range.

        Computed in whole microseconds (bucket width rounded up to one, at least one second), so an
        event on a bucket boundary falls into the later bucket on every database."""
        lo, hi = self.bounds(q)
        if lo is None or hi is None:
            return []
        span = max((hi - lo) // _MICROSECOND, _SECOND_US)
        width = max(-(-span // max(buckets, 1)), _SECOND_US)
        counts = [0] * (span // width + 1)
        start = (lo - _EPOCH) // _MICROSECOND
        with self.engine.connect() as c:
            micros = _epoch_micros(c.dialect.name)
            if micros is not None:  # bucket in SQL
                bucket_expr = ((micros - start) // width).label("b")
                stmt = self._where(select(bucket_expr, func.count()), q).group_by(text("b"))
                for bucket, n in c.execute(stmt):
                    counts[min(max(int(bucket or 0), 0), len(counts) - 1)] += int(n)
            else:  # portable fallback
                for (ts,) in c.execute(self._where(select(s.events.c.ts), q)).yield_per(10000):
                    stamp = _as_utc(ts) or lo
                    counts[min(((stamp - lo) // _MICROSECOND) // width, len(counts) - 1)] += 1
        return [{"start": lo + i * width * _MICROSECOND, "count": n} for i, n in enumerate(counts)]

    def object_counts(self, q: EventQuery, limit: int = 2000) -> list[tuple[str, int]]:
        """Objects involved in the matching events, most involved first: ``[(object_id, events)]``."""
        eo = s.event_objects.c
        ids = self._where(select(s.events.c.id), q)
        stmt = (
            select(eo.object_id, func.count(func.distinct(eo.event_id)).label("n"))
            .where(eo.event_id.in_(ids))
            .group_by(eo.object_id)
            .order_by(func.count(func.distinct(eo.event_id)).desc(), eo.object_id)
            .limit(limit)
        )
        with self.engine.connect() as c:
            return [(str(oid), int(n)) for oid, n in c.execute(stmt)]

    def object_activity(self, object_ids: Sequence[str]) -> dict[str, tuple[datetime | None, datetime | None, int]]:
        """First/last event time and event count per object (via the event_objects index)."""
        eo = s.event_objects.c
        result: dict[str, tuple[datetime | None, datetime | None, int]] = {}
        with self.engine.connect() as c:
            for batch in chunks(sorted(set(object_ids)), 400):
                stmt = select(eo.object_id, func.min(eo.ts), func.max(eo.ts), func.count(func.distinct(eo.event_id)))
                stmt = stmt.where(eo.object_id.in_(batch)).group_by(eo.object_id)
                for oid, lo, hi, n in c.execute(stmt):
                    result[oid] = (_as_utc(lo), _as_utc(hi), int(n))
        return result

    def incident_ids(self) -> dict[str, int]:
        with self.engine.connect() as c:
            rows = c.execute(
                select(s.incident_events.c.incident_id, func.count()).group_by(s.incident_events.c.incident_id)
            ).all()
        return {str(i): int(n) for i, n in rows}


_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_MICROSECOND = timedelta(microseconds=1)
_SECOND_US = 1_000_000


def _epoch_micros(dialect: str) -> Any:
    """``events.ts`` as exact integer microseconds since the epoch in SQL, or None (compute in Python)."""
    ts = s.events.c.ts
    if dialect == "sqlite":  # stored as UTC text 'YYYY-MM-DD HH:MM:SS.ffffff'
        return cast(func.strftime("%s", ts), Integer) * _SECOND_US + cast(func.substr(ts, 21, 6), Integer)
    if dialect == "postgresql":  # naive UTC timestamp; EXTRACT(EPOCH ...) is an exact numeric
        return cast(func.extract("epoch", ts) * _SECOND_US, BigInteger)
    return None


def _as_utc(value: Any) -> datetime | None:
    if value is None:
        return None
    parsed: datetime = datetime.fromisoformat(value) if isinstance(value, str) else value
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)
