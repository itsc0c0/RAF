"""R$F Surface API routes (mounted at /api/v1/surface).

Inventories reach the API only as request bodies (a raf-surface/1 document or a JSON list of
records, at most 20 MB); no route accepts a server-side path and nothing performs network I/O.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from raf.core.errors import InvalidInputError, ResourceLimitExceeded
from raf.core.timeutil import parse_timestamp
from raf.products.surface.model import MAX_DOCUMENT_BYTES
from raf.products.surface.rules import DEFAULT_EXPIRING_DAYS
from raf.products.surface.service import SurfaceService
from raf.sdk.api import Ctx

router = APIRouter()

Limit = Annotated[int, Query(ge=1, le=5000)]
Offset = Annotated[int, Query(ge=0)]
ExpiringDays = Annotated[int, Query(ge=1, le=3650)]
TimeSpec = Annotated[str | None, Query(max_length=64, description="Reference time (ISO-8601 or epoch).")]


class InventoryTooLarge(ResourceLimitExceeded):
    http_status = 413


class ScopeRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=300)
    kind: str | None = Field(None, max_length=20, description="domain, cidr, ip or cloud_account (default: inferred)")
    owner: str | None = Field(None, max_length=200)
    authorization: str | None = Field(None, max_length=200, description="Authorization reference, e.g. a ticket")
    replace: bool = False


def _time(value: str | None) -> Any:
    return parse_timestamp(value) if value else None


@router.get("/summary")
def summary(ctx: Ctx, at: TimeSpec = None, expiring_days: ExpiringDays = DEFAULT_EXPIRING_DAYS) -> dict[str, Any]:
    """Counts, scope, the domain → address → service/certificate tree and the top open findings."""
    data: dict[str, Any] = SurfaceService(ctx).summary(at=_time(at), expiring_days=expiring_days).to_json_dict()
    return data


@router.get("/assets")
def assets(
    ctx: Ctx,
    kind: Annotated[str | None, Query(max_length=20)] = None,
    scope: Annotated[str, Query(max_length=5, description="in, out or all")] = "all",
    references: bool = False,
    limit: Limit = 200,
    offset: Offset = 0,
) -> dict[str, Any]:
    items, total = SurfaceService(ctx).assets(
        kind=kind, scope=scope, include_references=references, limit=limit, offset=offset
    )
    return {"items": [a.to_json_dict() for a in items], "total": total, "limit": limit, "offset": offset}


@router.get("/scope")
def list_scope(ctx: Ctx) -> dict[str, Any]:
    entries = SurfaceService(ctx).scope_entries()
    return {"items": [e.to_json_dict() for e in entries], "total": len(entries)}


@router.post("/scope", status_code=201)
def add_scope(request: ScopeRequest, ctx: Ctx) -> dict[str, Any]:
    entry, result = SurfaceService(ctx).add_scope(
        request.target, request.kind, request.owner, request.authorization, replace=request.replace, via="api"
    )
    return {"entry": entry.to_json_dict(), "result": result}


@router.delete("/scope/{target:path}")
def remove_scope(target: str, ctx: Ctx) -> dict[str, Any]:
    entry = SurfaceService(ctx).remove_scope(target[:300], via="api")
    return {"entry": entry.to_json_dict(), "result": "removed"}


@router.post("/analyze")
def analyze(
    ctx: Ctx, at: TimeSpec = None, expiring_days: ExpiringDays = DEFAULT_EXPIRING_DAYS, persist: bool = True
) -> dict[str, Any]:
    data: dict[str, Any] = (
        SurfaceService(ctx)
        .analyze(at=_time(at), expiring_days=expiring_days, persist=persist, via="api")
        .to_json_dict()
    )
    return data


@router.get("/findings")
def findings(
    ctx: Ctx,
    rule: Annotated[str | None, Query(max_length=64)] = None,
    min_severity: Annotated[str | None, Query(max_length=16)] = None,
    status: Annotated[str, Query(max_length=20, description="open (default), resolved, ... or all")] = "open",
    limit: Limit = 100,
    offset: Offset = 0,
) -> dict[str, Any]:
    items, total = SurfaceService(ctx).findings(
        rule=rule, min_severity=min_severity, status=status, limit=limit, offset=offset
    )
    return {"items": [f.to_json_dict() for f in items], "total": total, "limit": limit, "offset": offset}


async def _read_body(request: Request, limit: int) -> bytes:
    declared = request.headers.get("content-length", "")
    too_large = f"Surface inventories are limited to {limit // (1024 * 1024)} MB per request."
    if declared.isdigit() and int(declared) > limit:
        raise InventoryTooLarge(too_large)
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise InventoryTooLarge(too_large)
        chunks.append(chunk)
    body = b"".join(chunks)
    if not body.strip():
        raise InvalidInputError(
            "The request body is empty.", hint="Send a raf-surface/1 document or a JSON list of records."
        )
    return body


@router.post("/import")
async def import_inventory(
    request: Request,
    ctx: Ctx,
    apply_scope: bool = False,
    fmt: Annotated[str, Query(alias="format", max_length=8, description="json (default), jsonl, yaml or csv")] = "json",
    source_name: Annotated[str | None, Query(max_length=200)] = None,
) -> dict[str, Any]:
    """Import an inventory sent as the request body (no paths). ``apply_scope=true`` also adds the
    document's ``scope`` entries to the authorized scope."""
    body = await _read_body(request, MAX_DOCUMENT_BYTES)
    service = SurfaceService(ctx)
    result = await run_in_threadpool(
        service.import_bytes,
        body,
        source_name=source_name or "api-request",
        fmt=fmt,
        apply_scope=apply_scope,
        via="api",
    )
    data: dict[str, Any] = result.to_json_dict()
    return data
