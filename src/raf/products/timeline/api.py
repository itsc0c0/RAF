"""R$F Timeline API routes (mounted at /api/v1/timeline)."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Query
from fastapi.responses import FileResponse
from starlette.background import BackgroundTask

from raf.core.query.scope import resolve_scope
from raf.core.timeutil import parse_timestamp
from raf.products.timeline.service import TimelineService, export_format
from raf.sdk.api import Ctx

router = APIRouter()

_MEDIA = {"csv": "text/csv", "json": "application/json", "jsonl": "application/x-ndjson", "raf": "application/zip"}


def _query(
    ctx: Any,
    ref: str | None,
    start: str | None,
    end: str | None,
    type: list[str] | None,
    category: list[str] | None,
    severity: str | None,
    q: str | None,
    filter: str | None,
) -> Any:
    scope = resolve_scope(ctx, [] if not ref or ref == "workspace" else [ref])
    service = TimelineService(ctx)
    query, terms = service.query(
        scope,
        start=parse_timestamp(start) if start else None,
        end=parse_timestamp(end) if end else None,
        types=type,
        categories=category,
        severity=severity,
        text=q,
        filter_text=filter,
    )
    return scope, service, query, terms


@router.get("")
def timeline(
    ctx: Ctx,
    ref: str | None = None,
    start: str | None = None,
    end: str | None = None,
    type: Annotated[list[str] | None, Query()] = None,
    category: Annotated[list[str] | None, Query()] = None,
    severity: str | None = None,
    q: str | None = None,
    filter: str | None = None,
    group_by: str | None = "category",
    cursor: str | None = None,
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    descending: bool = False,
    buckets: Annotated[int, Query(ge=1, le=500)] = 60,
) -> dict[str, Any]:
    scope, service, query, terms = _query(ctx, ref, start, end, type, category, severity, q, filter)
    result = service.timeline(
        scope, query, terms, limit=limit, cursor=cursor, descending=descending, group_by=group_by, buckets=buckets
    )
    data: dict[str, Any] = result.to_json_dict()
    return data


@router.get("/export")
def export(
    ctx: Ctx,
    ref: str | None = None,
    format: str = "csv",
    start: str | None = None,
    end: str | None = None,
    type: Annotated[list[str] | None, Query()] = None,
    severity: str | None = None,
    filter: str | None = None,
) -> FileResponse:
    fmt = export_format(format)  # before anything is created
    scope, service, query, _terms = _query(ctx, ref, start, end, type, None, severity, None, filter)
    handle = tempfile.NamedTemporaryFile(delete=False, suffix=f".{fmt}")  # noqa: SIM115 - removed after send
    handle.close()
    path = Path(handle.name)
    try:
        info = service.export(scope, query, fmt, path)
        ctx.audit.record("timeline.export", affected=[scope.id], details={**info, "path": "download"})
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return FileResponse(
        path,
        media_type=_MEDIA[fmt],
        filename=f"timeline-{scope.label}.{fmt}",
        background=BackgroundTask(path.unlink, missing_ok=True),
    )
