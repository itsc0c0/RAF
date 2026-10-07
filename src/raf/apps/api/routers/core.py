"""Core API routes: platform, workspaces, objects, relationships, events, findings, incidents, jobs."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, Field

from raf.analysis.pivots import pivots_for
from raf.apps.api.deps import Ctx, get_pool
from raf.core.errors import InvalidInputError
from raf.core.jobs.manager import JobStatus
from raf.core.objects.models import SecurityObject
from raf.core.objects.types import FindingStatus, Severity, validate_object_type
from raf.core.query.resolve import Resolved
from raf.core.storage.repos.events import EventQuery
from raf.core.timeutil import parse_timestamp
from raf.core.workspace.manager import RafHome, WorkspaceManager
from raf.version import API_VERSION, RAF_VERSION, versions

router = APIRouter()

Limit = Annotated[int, Query(ge=1, le=1000)]
Offset = Annotated[int, Query(ge=0)]


def _available(ctx: Any) -> set[str] | None:
    if ctx.registry is None:
        return None
    return {p.name for p in ctx.registry.products() if p.available}


#: Where references that resolve to something other than an object are described.
_OTHER_ROUTES = {"event": "events", "finding": "findings", "snapshot": "snapshots"}


def _require_object(ref: str, resolved: Resolved) -> SecurityObject:
    """The object a reference resolved to; event, finding and snapshot IDs are refused with their route."""
    if resolved.obj is None:
        route = f"/api/{API_VERSION}/{_OTHER_ROUTES.get(resolved.kind, resolved.kind)}/{resolved.id}"
        raise InvalidInputError(
            f"'{ref}' is {'an' if resolved.kind[0] in 'aeiou' else 'a'} {resolved.kind}, not an object.",
            hint=f"Use GET {route}.",
            details={"kind": resolved.kind, "id": resolved.id, "route": route},
        )
    return resolved.obj


# --------------------------------------------------------------------------- platform


@router.get("/health", tags=["platform"])
def health() -> dict[str, Any]:
    return {"status": "ok", "version": RAF_VERSION}


@router.get("/version", tags=["platform"])
def version() -> dict[str, str]:
    return versions()


@router.get("/status", tags=["platform"])
def status(ctx: Ctx) -> dict[str, Any]:
    products = ctx.registry.products() if ctx.registry else []
    return {
        "raf_version": RAF_VERSION,
        "core": "ONLINE",
        "database": "ONLINE",
        "workspace": ctx.workspace.name,
        "products": {"total": len(products), "available": sum(1 for p in products if p.available)},
        "data": ctx.store.stats(),
        "findings_by_severity": ctx.store.findings.count_by_severity(statuses=["OPEN"]),
        "oracle_provider": ctx.settings.get("oracle.provider"),
    }


@router.get("/products", tags=["products"])
def products(ctx: Ctx) -> dict[str, Any]:
    assert ctx.registry is not None
    return {"items": [p.to_dict() for p in ctx.registry.products()]}


@router.get("/products/{name}", tags=["products"])
def product_info(name: str, ctx: Ctx) -> dict[str, Any]:
    assert ctx.registry is not None
    return ctx.registry.info(name).to_dict() | {"dependents": ctx.registry.dependents(name)}


@router.post("/products/{name}/enable", tags=["products"])
def product_enable(name: str, ctx: Ctx) -> dict[str, Any]:
    assert ctx.registry is not None
    info = ctx.registry.enable(name)
    ctx.audit.record("product.enable", affected=[name])
    return info.to_dict()


@router.post("/products/{name}/disable", tags=["products"])
def product_disable(name: str, ctx: Ctx) -> dict[str, Any]:
    assert ctx.registry is not None
    info = ctx.registry.disable(name)
    ctx.audit.record("product.disable", affected=[name])
    return info.to_dict()


@router.get("/config", tags=["platform"])
def config(ctx: Ctx) -> dict[str, Any]:
    items = []
    for entry in ctx.settings.entries():
        value = ("set" if ctx.settings.secret(entry.key) else "not set") if entry.secret else entry.value
        items.append(
            {
                "key": entry.key,
                "value": value,
                "origin": entry.origin,
                "secret": entry.secret,
                "description": entry.description,
            }
        )
    return {"items": items}


# --------------------------------------------------------------------------- workspaces


class WorkspaceCreate(BaseModel):
    name: str
    description: str = ""


@router.get("/workspaces", tags=["workspaces"])
def workspaces(request: Request) -> dict[str, Any]:
    pool = get_pool(request)
    manager = WorkspaceManager(RafHome.from_env(pool.env), pool.env)
    return {"items": [i.to_dict() for i in manager.list()], "current": manager.current_name()}


@router.post("/workspaces", tags=["workspaces"], status_code=201)
def create_workspace(body: WorkspaceCreate, request: Request) -> dict[str, Any]:
    pool = get_pool(request)
    manager = WorkspaceManager(RafHome.from_env(pool.env), pool.env)
    ws = manager.create(body.name, body.description)
    pool.get(ws.name).audit.record("workspace.create", affected=[ws.name])
    return {"name": ws.name, "path": str(ws.path)}


@router.post("/workspaces/{name}/use", tags=["workspaces"])
def use_workspace(name: str, request: Request) -> dict[str, Any]:
    pool = get_pool(request)
    manager = WorkspaceManager(RafHome.from_env(pool.env), pool.env)
    ws = manager.use(name)
    return {"name": ws.name, "current": True}


# --------------------------------------------------------------------------- objects


@router.get("/objects", tags=["objects"])
def list_objects(
    ctx: Ctx,
    type: Annotated[list[str] | None, Query()] = None,
    q: str | None = None,
    tag: str | None = None,
    limit: Limit = 100,
    offset: Offset = 0,
) -> dict[str, Any]:
    types = [validate_object_type(t) for t in type] if type else None
    items = ctx.store.objects.list(types=types, text=q, tag=tag, limit=limit, offset=offset)
    total = ctx.store.objects.count(types=types, text=q) if tag is None else None
    return {"items": [o.to_json_dict() for o in items], "total": total, "limit": limit, "offset": offset}


@router.get("/objects/types", tags=["objects"])
def object_type_counts(ctx: Ctx) -> dict[str, Any]:
    return {"objects": ctx.store.objects.count_by_type(), "relationships": ctx.store.relationships.count_by_type()}


@router.get("/objects/{object_id:path}/relationships", tags=["objects"])
def object_relationships(
    object_id: str, ctx: Ctx, direction: str = "both", at: str | None = None, limit: Limit = 200
) -> dict[str, Any]:
    resolved = ctx.resolve(object_id)
    if direction not in {"in", "out", "both"}:
        raise InvalidInputError("direction must be in, out or both")
    rels = ctx.store.relationships.edges(
        [resolved.id],
        direction=direction,  # type: ignore[arg-type]
        at=parse_timestamp(at) if at else None,
        include_inactive=at is None,
    )
    return {"object_id": resolved.id, "items": [r.to_json_dict() for r in rels[:limit]], "total": len(rels)}


@router.get("/objects/{object_id:path}/provenance", tags=["objects"])
def object_provenance(object_id: str, ctx: Ctx, limit: Limit = 100) -> dict[str, Any]:
    resolved = ctx.resolve(object_id, accept=("object", "finding"))  # findings have provenance too
    items = ctx.store.provenance.for_subject(resolved.id, limit=limit)
    return {
        "object_id": resolved.id,
        "items": [p.to_json_dict() for p in items],
        "total": ctx.store.provenance.count_for_subject(resolved.id),
    }


@router.get("/objects/{object_id:path}/pivots", tags=["objects"])
def object_pivots(object_id: str, ctx: Ctx) -> dict[str, Any]:
    obj = _require_object(object_id, ctx.resolve(object_id, accept=("object", "event", "finding", "snapshot")))
    return {
        "object_id": obj.id,
        "items": [p.to_dict() for p in pivots_for(obj.id, obj.type, _available(ctx))],
    }


@router.get("/objects/{object_id:path}", tags=["objects"])
def get_object(object_id: str, ctx: Ctx) -> dict[str, Any]:
    resolved = ctx.resolve(object_id, accept=("object", "event", "finding", "snapshot"))
    obj = _require_object(object_id, resolved)
    activity = ctx.store.events.object_activity([obj.id]).get(obj.id)
    return {
        "object": obj.to_json_dict(),
        "notes": resolved.notes,
        "activity": {"first_event": activity[0], "last_event": activity[1], "events": activity[2]}
        if activity
        else None,
        "relationship_count": len(ctx.store.relationships.edges([obj.id], include_inactive=True)),
        "findings": [f.to_json_dict() for f in ctx.store.findings.list(object_id=obj.id, limit=20)],
        "pivots": [p.to_dict() for p in pivots_for(obj.id, obj.type, _available(ctx))],
    }


@router.get("/relationships", tags=["objects"])
def list_relationships(
    ctx: Ctx,
    type: Annotated[list[str] | None, Query()] = None,
    source: str | None = None,
    target: str | None = None,
    limit: Limit = 100,
    offset: Offset = 0,
) -> dict[str, Any]:
    items = ctx.store.relationships.list(types=type, source=source, target=target, limit=limit, offset=offset)
    return {
        "items": [r.to_json_dict() for r in items],
        "limit": limit,
        "offset": offset,
        "total": ctx.store.relationships.count(types=type) if not (source or target) else None,
    }


@router.get("/search", tags=["objects"])
def search(
    ctx: Ctx, q: Annotated[str, Query(min_length=1, max_length=200)], limit: Annotated[int, Query(ge=1, le=100)] = 20
) -> dict[str, Any]:
    objs = ctx.store.objects.search(q, limit=limit)
    findings = ctx.store.findings.list(text=q, limit=10)
    incidents = [o for o in objs if o.type == "incident"]
    return {
        "query": q,
        "objects": [o.to_json_dict() for o in objs if o.type != "incident"],
        "incidents": [o.to_json_dict() for o in incidents],
        "findings": [f.to_json_dict() for f in findings],
    }


# --------------------------------------------------------------------------- events


def event_query_from_params(
    ctx: Any,
    start: str | None,
    end: str | None,
    type: list[str] | None,
    category: list[str] | None,
    object: str | None,
    incident: str | None,
    severity: str | None,
    q: str | None,
    actor: str | None = None,
    job: str | None = None,
) -> EventQuery:
    return EventQuery(
        start=parse_timestamp(start) if start else None,
        end=parse_timestamp(end) if end else None,
        event_types=type,
        categories=category,
        object_ids=[ctx.resolve(object).id] if object else None,
        incident_id=ctx.resolve(incident, types=["incident"]).id if incident else None,
        min_severity=Severity.parse(severity) if severity else None,
        text=q,
        actor=ctx.resolve(actor).id if actor else None,
        job_ids=[job] if job else None,
    )


@router.get("/events", tags=["events"])
def list_events(
    ctx: Ctx,
    start: str | None = None,
    end: str | None = None,
    type: Annotated[list[str] | None, Query()] = None,
    category: Annotated[list[str] | None, Query()] = None,
    object: str | None = None,
    incident: str | None = None,
    severity: str | None = None,
    q: str | None = None,
    actor: str | None = None,
    job: str | None = None,
    cursor: str | None = None,
    descending: bool = False,
    limit: Limit = 200,
) -> dict[str, Any]:
    query = event_query_from_params(ctx, start, end, type, category, object, incident, severity, q, actor, job)
    page = ctx.store.events.query(query, limit=limit, cursor=cursor, descending=descending)
    return {
        "items": [e.to_json_dict() for e in page.items],
        "next_cursor": page.next_cursor,
        "total": ctx.store.events.count(query) if cursor is None else None,
    }


@router.get("/events/{event_id:path}", tags=["events"])
def get_event(event_id: str, ctx: Ctx) -> dict[str, Any]:
    from raf.core.errors import NotFoundError

    event = ctx.store.events.get(event_id)
    if event is None:
        raise NotFoundError(f"Event '{event_id}' does not exist.")
    return event.to_json_dict()


# --------------------------------------------------------------------------- findings / incidents


class FindingStatusUpdate(BaseModel):
    status: FindingStatus
    note: str | None = Field(default=None, max_length=2000)


@router.get("/findings", tags=["findings"])
def list_findings(
    ctx: Ctx,
    product: str | None = None,
    severity: str | None = None,
    status: Annotated[list[str] | None, Query()] = None,
    object: str | None = None,
    q: str | None = None,
    limit: Limit = 100,
    offset: Offset = 0,
) -> dict[str, Any]:
    object_id = ctx.resolve(object).id if object else None
    statuses = [FindingStatus(s.upper()).value for s in status] if status else None
    min_sev = Severity.parse(severity) if severity else None
    items = ctx.store.findings.list(
        product=product,
        min_severity=min_sev,
        statuses=statuses,
        object_id=object_id,
        text=q,
        limit=limit,
        offset=offset,
    )
    total = ctx.store.findings.count(
        product=product, min_severity=min_sev, statuses=statuses, object_id=object_id, text=q
    )
    return {"items": [f.to_json_dict() for f in items], "total": total, "limit": limit, "offset": offset}


@router.get("/findings/{finding_id:path}", tags=["findings"])
def get_finding(finding_id: str, ctx: Ctx) -> dict[str, Any]:
    return ctx.store.findings.require(finding_id).to_json_dict()


@router.patch("/findings/{finding_id:path}", tags=["findings"])
def update_finding(finding_id: str, body: FindingStatusUpdate, ctx: Ctx) -> dict[str, Any]:
    finding = ctx.store.findings.set_status(finding_id, body.status, body.note)
    ctx.audit.record("finding.status", affected=[finding_id], details={"status": body.status.value})
    return finding.to_json_dict()


@router.get("/incidents", tags=["incidents"])
def list_incidents(ctx: Ctx) -> dict[str, Any]:
    return {"items": [i.to_json_dict() for i in ctx.store.incidents.list()]}


@router.get("/incidents/{incident_id:path}", tags=["incidents"])
def get_incident(incident_id: str, ctx: Ctx) -> dict[str, Any]:
    from raf.core.errors import NotFoundError

    resolved = ctx.resolve(incident_id, types=["incident"])
    incident = ctx.store.incidents.get(resolved.id)
    if incident is None:
        raise NotFoundError(f"Incident '{incident_id}' does not exist.")
    return incident.to_json_dict()


# --------------------------------------------------------------------------- jobs / audit


@router.get("/jobs", tags=["jobs"])
def list_jobs(ctx: Ctx, status: str | None = None, limit: Limit = 50) -> dict[str, Any]:
    items = ctx.jobs.list(limit=limit, status=JobStatus(status.upper()) if status else None)
    return {"items": [j.to_json_dict() for j in items]}


@router.get("/jobs/{job_id}", tags=["jobs"])
def get_job(job_id: str, ctx: Ctx) -> dict[str, Any]:
    return ctx.jobs.require(job_id).to_json_dict()


@router.post("/jobs/{job_id}/cancel", tags=["jobs"])
def cancel_job(job_id: str, ctx: Ctx) -> dict[str, Any]:
    job = ctx.jobs.cancel(job_id)
    ctx.audit.record("job.cancel", affected=[job_id])
    return job.to_json_dict()


@router.get("/audit", tags=["platform"])
def audit(ctx: Ctx, limit: Limit = 50) -> dict[str, Any]:
    return {"items": [e.to_dict() for e in ctx.audit.list(limit=limit)], "chain": ctx.audit.verify()}
