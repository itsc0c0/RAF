"""R$F Lens: a security data workbench over the shared store.

Lens opens any scope - the workspace, an object, an incident, an analysis, an evidence item or a
data source (e.g. an imported packet capture) - and returns, in one answer, the matching events
plus everything needed to explore them: groups, a time histogram, which object types are
involved, the most involved objects (each a pivot into Graph, Timeline, Trace, Evidence and
Exposure), related findings and, for single objects, relationship drill-down.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any

from pydantic import Field

from raf.core.context.app import RafContext
from raf.core.objects.models import Event, Finding, RafModel
from raf.core.query.scope import Scope, resolve_scope
from raf.products.timeline.service import GROUP_FIELDS, TimelineService

MAX_TOP = 25


class LensResult(RafModel):
    scope: dict[str, Any]
    filters: list[str] = Field(default_factory=list)
    total: int
    first: datetime | None = None
    last: datetime | None = None
    items: list[Event] = Field(default_factory=list)
    names: dict[str, str] = Field(default_factory=dict)
    next_cursor: str | None = None
    group_by: str | None = None
    groups: list[dict[str, Any]] = Field(default_factory=list)
    histogram: list[dict[str, Any]] = Field(default_factory=list)
    involved: list[dict[str, Any]] = Field(default_factory=list)
    top_objects: list[dict[str, Any]] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    relationships: list[dict[str, Any]] = Field(default_factory=list)
    pivots: dict[str, list[dict[str, str]]] = Field(default_factory=dict)


def pivot_commands(object_id: str, object_type: str) -> list[dict[str, str]]:
    """Terminal and web destinations for an object (the same set the UI pivot menu offers)."""
    ref = f'"{object_id}"' if any(ch.isspace() for ch in object_id) else object_id
    out = [
        {"product": "graph", "command": f"raf graph {ref}", "view": f"/graph?focus={object_id}"},
        {"product": "timeline", "command": f"raf timeline {ref}", "view": f"/timeline?object={object_id}"},
        {"product": "trace", "command": f"raf trace {ref}", "view": f"/investigate?trace={object_id}"},
        {
            "product": "evidence",
            "command": f"raf evidence list --object {ref}",
            "view": f"/evidence?object={object_id}",
        },
    ]
    if object_type in ("host", "service", "cloud_resource", "container", "ip"):
        out.append(
            {"product": "exposure", "command": f"raf exposure show {ref}", "view": f"/exposure?object={object_id}"}
        )
    return out


class LensService:
    def __init__(self, ctx: RafContext) -> None:
        self.ctx = ctx
        self.store = ctx.store
        self.timeline = TimelineService(ctx)

    def scope_for(self, words: list[str]) -> Scope:
        return resolve_scope(self.ctx, words)

    def query(
        self,
        scope: Scope,
        *,
        filter_text: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        source: str | None = None,
        group_by: str | None = "event_type",
        buckets: int = 60,
        limit: int = 100,
        cursor: str | None = None,
    ) -> LensResult:
        query, terms = self.timeline.query(scope, start=start, end=end, filter_text=filter_text)
        if scope.kind == "object" and scope.id.startswith("evidence:"):
            obj = self.store.objects.get(scope.id)
            if obj is not None:
                # events parsed from this item: same import job (when recorded) and same source name
                evidence_job = obj.metadata.get("job")
                query.object_ids = None
                query.job_ids = [str(evidence_job)] if evidence_job else None
                query.source = obj.name
                terms.append(f"evidence item {obj.name}")
        if source:
            query.source = source
            terms.append(f"source contains {source}")
        if group_by not in (None, *GROUP_FIELDS):
            group_by = "event_type"
        base = self.timeline.timeline(
            scope, query, terms, limit=limit, cursor=cursor, group_by=group_by, buckets=buckets
        )
        counts = self.store.events.object_counts(query, limit=2000) if base.total else []
        involved = Counter(oid.split(":", 1)[0] for oid, _n in counts)
        top_ids = [oid for oid, _n in counts if oid != scope.id][:MAX_TOP]
        objects = self.store.objects.get_many(top_ids) if top_ids else {}
        top: list[dict[str, Any]] = []
        for oid, n in counts:
            if oid not in objects:
                continue
            obj = objects[oid]
            criticality = obj.criticality.value if obj.criticality else None
            top.append({"id": oid, "name": obj.name, "type": obj.type, "count": n, "criticality": criticality})
        findings: dict[str, Finding] = {}
        for oid in [scope.id, *top_ids[:10]]:
            for finding in self.store.findings.list(object_id=oid, statuses=["OPEN", "ACKNOWLEDGED"], limit=10):
                findings.setdefault(finding.id, finding)
        relationships = []
        if scope.kind == "object" and not scope.id.startswith("evidence:"):
            by_type: Counter[tuple[str, str]] = Counter()
            for rel in self.store.relationships.edges([scope.id], direction="both"):
                direction = "out" if rel.source_object == scope.id else "in"
                by_type[(rel.relationship_type, direction)] += 1
            relationships = [{"type": t, "direction": d, "count": n} for (t, d), n in by_type.most_common(20)]
        names = dict(base.names)
        names.update({t["id"]: t["name"] for t in top})
        pivots = {t["id"]: pivot_commands(t["id"], t["type"]) for t in top[:10]}
        return LensResult(
            **base.model_dump(exclude={"names"}),
            names=names,
            involved=[{"type": t, "count": n} for t, n in involved.most_common()],
            top_objects=top,
            findings=sorted(findings.values(), key=lambda f: -f.severity.rank)[:20],
            relationships=relationships,
            pivots=pivots,
        )
