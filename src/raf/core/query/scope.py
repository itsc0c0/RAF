"""Investigation scopes: what a command is "about".

A scope is an object (``WS-04``, ``host WS-04``), an incident (``INC-001``),
an analysis (``analysis-3``), a job (``job-12``), a context reference
(``@last``) or the whole workspace. Graph, Timeline, Lens and Replay accept the
same scope syntax so pivots between them are lossless.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from sqlalchemy import select

from raf.core.context.app import RafContext
from raf.core.errors import InvalidInputError, NotFoundError
from raf.core.objects.models import SecurityObject
from raf.core.objects.types import ObjectType, validate_object_type
from raf.core.storage import schema as s
from raf.core.storage.repos.events import EventQuery

_TYPE_WORDS = {t.value for t in ObjectType} | {"hostname", "account", "cve", "proc"}


@dataclass(slots=True)
class Scope:
    kind: str  # object | incident | analysis | job | workspace
    id: str
    label: str
    obj: SecurityObject | None = None
    job_ids: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def event_query(self) -> EventQuery:
        if self.kind == "incident":
            return EventQuery(incident_id=self.id)
        if self.kind == "object":
            return EventQuery(object_ids=[self.id])
        if self.kind in ("analysis", "job"):
            return EventQuery(job_ids=self.job_ids or ["<none>"])
        return EventQuery()

    def to_dict(self) -> dict[str, object]:
        return {"kind": self.kind, "id": self.id, "label": self.label, "job_ids": self.job_ids}


def analysis_jobs(ctx: RafContext, analysis_id: str) -> list[str]:
    with ctx.store.engine.connect() as conn:
        row = conn.execute(
            select(s.analyses.c.job_id, s.analyses.c.stats).where(s.analyses.c.id == analysis_id)
        ).first()
    if row is None:
        raise NotFoundError(f"Analysis '{analysis_id}' does not exist.", suggestions=["raf jobs"])
    jobs = [row[0]] if row[0] else []
    extra = (row[1] or {}).get("job_ids") if isinstance(row[1], dict) else None
    if isinstance(extra, list):
        jobs.extend(str(j) for j in extra if j not in jobs)
    return jobs


def resolve_scope(ctx: RafContext, parts: Sequence[str], *, default_workspace: bool = True) -> Scope:
    words = [p for p in parts if p]
    if not words:
        if default_workspace:
            return Scope(kind="workspace", id=ctx.workspace.name, label=f"workspace {ctx.workspace.name}")
        raise InvalidInputError("Specify what to look at (an object, incident, analysis or 'workspace').")
    if len(words) > 2:
        raise InvalidInputError(f"Unexpected arguments: {' '.join(words[2:])}")
    if len(words) == 1 and words[0].lower() in ("workspace", "all", "@workspace"):
        return Scope(kind="workspace", id=ctx.workspace.name, label=f"workspace {ctx.workspace.name}")
    types: list[str] | None = None
    ref = words[-1]
    if len(words) == 2:
        if words[0].lower() not in _TYPE_WORDS:
            raise InvalidInputError(
                f"'{words[0]}' is not an object type.",
                hint="Use '<type> <name>' (for example: host WS-04) or a single reference.",
            )
        types = [validate_object_type(words[0])]
    resolved = ctx.resolve(ref, types=types, accept=("object", "analysis", "job"))
    if resolved.kind == "analysis":
        ctx.refs.remember("analysis", resolved.id)
        return Scope(
            kind="analysis",
            id=resolved.id,
            label=resolved.id,
            job_ids=analysis_jobs(ctx, resolved.id),
            notes=resolved.notes,
        )
    if resolved.kind == "job":
        ctx.jobs.require(resolved.id)
        return Scope(kind="job", id=resolved.id, label=resolved.id, job_ids=[resolved.id], notes=resolved.notes)
    obj = resolved.obj
    assert obj is not None
    if obj.type == ObjectType.INCIDENT:
        ctx.refs.remember("incident", obj.id)
        return Scope(kind="incident", id=obj.id, label=obj.name, obj=obj, notes=resolved.notes)
    ctx.refs.remember("object", obj.id)
    return Scope(kind="object", id=obj.id, label=obj.name, obj=obj, notes=resolved.notes)
