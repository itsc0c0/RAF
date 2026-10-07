"""R$F Timeline: unified, filterable, exportable event timelines for any scope."""

from __future__ import annotations

import csv
import hashlib
import json
from collections.abc import Iterator, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import Field

from raf.core.context.app import RafContext
from raf.core.errors import InvalidInputError
from raf.core.objects.models import Event, RafModel
from raf.core.objects.types import Severity
from raf.core.query.language import parse_filter
from raf.core.query.scope import Scope
from raf.core.storage.repos.events import EventQuery
from raf.core.timeutil import format_ts

EXPORT_FORMATS = ("json", "jsonl", "csv", "raf")
GROUP_FIELDS = ("category", "event_type", "actor", "target", "severity", "source", "outcome")
CSV_COLUMNS = (
    "timestamp",
    "event_id",
    "event_type",
    "category",
    "action",
    "outcome",
    "actor",
    "actor_name",
    "target",
    "target_name",
    "severity",
    "confidence",
    "source",
    "parser",
    "record",
    "raw_reference",
    "message",
)


def export_format(fmt: str) -> str:
    """The canonical (lower-case) export format; anything else is an :class:`InvalidInputError`."""
    value = fmt.strip().lower()
    if value not in EXPORT_FORMATS:
        raise InvalidInputError(f"Unknown export format '{fmt}'.", hint="Formats: " + ", ".join(EXPORT_FORMATS))
    return value


class TimelineResult(RafModel):
    scope: dict[str, Any]
    filters: list[str] = Field(default_factory=list)
    total: int
    first: datetime | None = None
    last: datetime | None = None
    items: list[Event]
    names: dict[str, str] = Field(default_factory=dict)
    next_cursor: str | None = None
    group_by: str | None = None
    groups: list[dict[str, Any]] = Field(default_factory=list)
    histogram: list[dict[str, Any]] = Field(default_factory=list)


class TimelineService:
    def __init__(self, ctx: RafContext) -> None:
        self.ctx = ctx
        self.store = ctx.store

    def query(
        self,
        scope: Scope,
        *,
        start: datetime | None = None,
        end: datetime | None = None,
        types: Sequence[str] | None = None,
        categories: Sequence[str] | None = None,
        severity: str | None = None,
        text: str | None = None,
        filter_text: str | None = None,
    ) -> tuple[EventQuery, list[str]]:
        query = scope.event_query()
        query.start = start or query.start
        query.end = end or query.end
        if types:
            query.event_types = list(types)
        if categories:
            query.categories = [c.lower() for c in categories]
        if severity:
            query.min_severity = Severity.parse(severity)
        if text:
            query.text = text
        terms: list[str] = []
        if filter_text:
            parsed = parse_filter(filter_text, resolver=self.ctx.resolver, base=query)
            query, terms = parsed.query, parsed.terms
        return query, terms

    def timeline(
        self,
        scope: Scope,
        query: EventQuery,
        terms: list[str] | None = None,
        *,
        limit: int = 100,
        cursor: str | None = None,
        descending: bool = False,
        group_by: str | None = "category",
        buckets: int = 48,
    ) -> TimelineResult:
        if group_by is not None and group_by not in GROUP_FIELDS:
            raise InvalidInputError(f"Cannot group by '{group_by}'.", hint="Use one of: " + ", ".join(GROUP_FIELDS))
        page = self.store.events.query(query, limit=limit, cursor=cursor, descending=descending)
        first, last = self.store.events.bounds(query)
        total = self.store.events.count(query)
        ids: set[str] = set()
        for ev in page.items:
            ids.update(i for i in (ev.actor, ev.target) if i)
            ids.update(ref.object_id for ref in ev.objects if ref.role == "host")
        names = {i: o.name for i, o in self.store.objects.get_many(ids).items()} if ids else {}
        groups = []
        if group_by:
            field = {"event_type": "event_type"}.get(group_by, group_by)
            groups = [{"key": k, "count": n} for k, n in self.store.events.group_counts(query, field, limit=30)]
        histogram = (
            [
                {"start": format_ts(b["start"]), "count": b["count"]}
                for b in self.store.events.histogram(query, buckets=buckets)
            ]
            if total
            else []
        )
        return TimelineResult(
            scope=scope.to_dict(),
            filters=terms or [],
            total=total,
            first=first,
            last=last,
            items=page.items,
            names=names,
            next_cursor=page.next_cursor,
            group_by=group_by,
            groups=groups,
            histogram=histogram,
        )

    def iter_events(self, query: EventQuery) -> Iterator[Event]:
        yield from self.store.events.iter(query)

    # ------------------------------------------------------------------ export
    def export(self, scope: Scope, query: EventQuery, fmt: str, output: Path) -> dict[str, Any]:
        fmt = export_format(fmt)
        output.parent.mkdir(parents=True, exist_ok=True)
        count = 0
        if fmt == "raf":
            from raf.core.bundle.format import export_bundle

            events = list(self.iter_events(query))
            object_ids = {ref.object_id for ev in events for ref in ev.objects}
            objects = list(self.store.objects.get_many(object_ids).values())
            rel_ids = {rid for ev in events for rid in ev.relationships}
            relationships = list(self.store.relationships.get_many(rel_ids).values())
            incidents = [scope.obj] if scope.kind == "incident" and scope.obj else []
            manifest = export_bundle(
                self.ctx,
                output,
                objects=objects + incidents,
                relationships=relationships,
                events=events,
                scope={"timeline": scope.to_dict()},
                description=f"Timeline export of {scope.label}",
            )
            count = len(events)
            digest = hashlib.sha256(output.read_bytes()).hexdigest()
            return {
                "path": str(output),
                "format": fmt,
                "events": count,
                "sha256": digest,
                "bundle_version": manifest.format_version,
            }
        names: dict[str, str] = {}
        with output.open("w", encoding="utf-8", newline="") as handle:
            if fmt == "csv":
                writer = csv.writer(handle)
                writer.writerow(CSV_COLUMNS)
            elif fmt == "json":
                handle.write("[\n")
            for ev in self.iter_events(query):
                if fmt == "csv":
                    missing = [i for i in (ev.actor, ev.target) if i and i not in names]
                    if missing:
                        names.update({o.id: o.name for o in self.store.objects.get_many(missing).values()})
                    # Every text cell can carry imported data (names, sources, actions, records ...).
                    writer.writerow(
                        [
                            format_ts(ev.timestamp),
                            _csv_safe(ev.id),
                            _csv_safe(ev.event_type),
                            _csv_safe(ev.category),
                            _csv_safe(ev.action),
                            _csv_safe(ev.outcome or ""),
                            _csv_safe(ev.actor or ""),
                            _csv_safe(names.get(ev.actor or "", "")),
                            _csv_safe(ev.target or ""),
                            _csv_safe(names.get(ev.target or "", "")),
                            ev.severity.value,
                            ev.confidence,
                            _csv_safe(ev.source),
                            _csv_safe(ev.parser),
                            _csv_safe(ev.record or ""),
                            _csv_safe(ev.raw_reference or ""),
                            _csv_safe(ev.message or ""),
                        ]
                    )
                else:
                    payload = json.dumps(ev.to_json_dict(), ensure_ascii=False)
                    if fmt == "json":
                        handle.write(("  " if count == 0 else ",\n  ") + payload)
                    else:
                        handle.write(payload + "\n")
                count += 1
            if fmt == "json":
                handle.write("\n]\n")
        digest = hashlib.sha256(output.read_bytes()).hexdigest()
        return {"path": str(output), "format": fmt, "events": count, "sha256": digest}


def _csv_safe(text: str) -> str:
    """Neutralize spreadsheet formula injection in exported untrusted text."""
    if text and text[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text
    return text
