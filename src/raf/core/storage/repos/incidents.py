"""Incidents are canonical objects (type ``incident``) plus an event membership index."""

from __future__ import annotations

import builtins
from collections.abc import Iterable, Sequence
from datetime import datetime
from typing import Any

from sqlalchemy import Engine, func, select

from raf.core.objects.models import Incident, ObjectDraft, SecurityObject
from raf.core.objects.types import ObjectType, Severity
from raf.core.storage import schema as s
from raf.core.storage.repos.events import EventRepository, _as_utc
from raf.core.storage.repos.objects import ObjectRepository
from raf.core.timeutil import parse_timestamp


class IncidentRepository:
    def __init__(self, engine: Engine, objects: ObjectRepository, events: EventRepository) -> None:
        self.engine = engine
        self.objects = objects
        self.events = events

    def upsert(
        self,
        name: str,
        *,
        title: str | None = None,
        status: str | None = None,
        severity: Severity | None = None,
        description: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        source: str = "unknown",
        tags: Sequence[str] = (),
        metadata: dict[str, Any] | None = None,
        synthetic: bool = False,
    ) -> str:
        meta: dict[str, Any] = dict(metadata or {})
        if title is not None:
            meta["title"] = title
        if status is not None:
            meta["status"] = status
        if severity is not None:
            meta["severity"] = severity.value
        if description is not None:
            meta["description"] = description
        if start is not None:
            meta["start"] = start.isoformat()
        if end is not None:
            meta["end"] = end.isoformat()
        draft = ObjectDraft.make(
            ObjectType.INCIDENT, name, source=source, tags=set(tags), metadata=meta, synthetic=synthetic, confidence=1.0
        )
        self.objects.upsert_drafts([draft])
        return draft.id

    def link_events(self, incident_id: str, event_ids: Iterable[str]) -> int:
        return self.events.link_incident(incident_id, event_ids)

    def _to_model(self, obj: SecurityObject, count: int, lo: datetime | None, hi: datetime | None) -> Incident:
        meta = obj.metadata
        start = _meta_time(meta.get("start")) or lo
        end = _meta_time(meta.get("end")) or hi
        try:
            severity = Severity.parse(meta.get("severity", "MEDIUM"))
        except Exception:  # noqa: BLE001 - tolerate odd imported values
            severity = Severity.MEDIUM
        return Incident.model_construct(
            id=obj.id,
            name=obj.name,
            title=str(meta.get("title") or obj.name),
            status=str(meta.get("status", "open")),
            severity=severity,
            start=start,
            end=end,
            description=str(meta.get("description", "")),
            source=obj.source,
            event_count=count,
            created_at=obj.created_at,
            updated_at=obj.updated_at,
            tags=obj.tags,
            metadata=meta,
        )

    def _stats(self, incident_ids: Sequence[str]) -> dict[str, tuple[int, datetime | None, datetime | None]]:
        ie = s.incident_events.c
        stmt = (
            select(ie.incident_id, func.count(), func.min(ie.ts), func.max(ie.ts))
            .where(ie.incident_id.in_(list(incident_ids)))
            .group_by(ie.incident_id)
        )
        with self.engine.connect() as c:
            return {r[0]: (int(r[1]), _as_utc(r[2]), _as_utc(r[3])) for r in c.execute(stmt)}

    def get(self, incident_id: str) -> Incident | None:
        obj = self.objects.get(incident_id)
        if obj is None or obj.type != ObjectType.INCIDENT:
            return None
        count, lo, hi = self._stats([incident_id]).get(incident_id, (0, None, None))
        return self._to_model(obj, count, lo, hi)

    def list(self, limit: int = 200) -> builtins.list[Incident]:
        objs = self.objects.list(types=[ObjectType.INCIDENT], limit=limit, order="name")
        stats = self._stats([o.id for o in objs]) if objs else {}
        return [self._to_model(o, *stats.get(o.id, (0, None, None))) for o in objs]


def _meta_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return parse_timestamp(value)
    except Exception:  # noqa: BLE001
        return None
