"""Investigation scopes: what a command is "about".

A scope is an object (``WS-04``, ``host WS-04``), an incident (``INC-001``),
an analysis (``analysis-3``), a job (``job-12``), a context reference
(``@last``) or the whole workspace. Graph, Timeline, Lens and Replay accept the
same scope syntax so pivots between them are lossless. Events, findings and
snapshots are not scopes.
"""

from __future__ import annotations

import shlex
from collections.abc import Sequence
from dataclasses import dataclass, field

from raf.core.context.app import RafContext
from raf.core.errors import InvalidInputError, NotFoundError
from raf.core.objects.models import SecurityObject
from raf.core.objects.types import ObjectType, validate_object_type
from raf.core.storage.repos.events import EventQuery


@dataclass(slots=True)
class Scope:
    kind: str  # object | incident | analysis | job | workspace
    id: str
    label: str
    obj: SecurityObject | None = None
    job_ids: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    #: For analyses that re-read data an earlier, larger import already holds: only that source.
    source: str | None = None

    def event_query(self) -> EventQuery:
        if self.kind == "incident":
            return EventQuery(incident_id=self.id)
        if self.kind == "object":
            return EventQuery(object_ids=[self.id])
        if self.kind in ("analysis", "job"):
            return EventQuery(job_ids=self.job_ids or ["<none>"], source=self.source)
        return EventQuery()

    def to_dict(self) -> dict[str, object]:
        data: dict[str, object] = {"kind": self.kind, "id": self.id, "label": self.label, "job_ids": self.job_ids}
        if self.source:
            data["source"] = self.source
        return data


def analysis_jobs(ctx: RafContext, analysis_id: str) -> list[str]:
    record = ctx.store.analyses.get(analysis_id)
    if record is None:
        raise NotFoundError(f"Analysis '{analysis_id}' does not exist.", suggestions=["raf analyses"])
    return record.job_ids


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
        try:  # canonical types, their aliases (hostname, cve, ...) and plugin x-<name> types
            types = [validate_object_type(words[0])]
        except InvalidInputError as exc:
            raise InvalidInputError(
                f"'{words[0]}' is not an object type.",
                hint="Use '<type> <name>' (for example: host WS-04) or a single reference; raf help objects lists "
                "the types.",
                details=exc.details,
            ) from None
    resolved = ctx.resolve(ref, types=types, accept=("object", "analysis", "job"))
    if resolved.kind not in ("object", "analysis", "job"):  # an event:, finding: or snapshot: ID
        if resolved.kind == "snapshot":
            show = f"raf snapshot show {shlex.quote(resolved.id.split(':', 1)[1])}"
        else:
            show = f"raf show {shlex.quote(resolved.id)}"
        raise InvalidInputError(
            f"'{ref}' is {'an' if resolved.kind[0] in 'aeiou' else 'a'} {resolved.kind}, which is not a scope.",
            hint="A scope is an object, an incident, an analysis, a job or the workspace.",
            suggestions=[show],
        )
    if resolved.kind == "analysis":
        ctx.refs.remember("analysis", resolved.id)
        record = ctx.store.analyses.get(resolved.id)
        source = record.stats.get("scope_source") if record is not None else None
        return Scope(
            kind="analysis",
            id=resolved.id,
            label=resolved.id,
            job_ids=analysis_jobs(ctx, resolved.id),
            notes=resolved.notes,
            source=str(source) if source else None,
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
