"""R$F Lens API routes (mounted at /api/v1/lens)."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Query

from raf.apps.api.deps import Ctx
from raf.core.timeutil import parse_timestamp
from raf.products.lens.service import LensService

router = APIRouter()


@router.get("/query")
def query(
    ctx: Ctx,
    ref: str | None = None,
    filter: str | None = None,
    source: Annotated[str | None, Query(max_length=300)] = None,
    start: str | None = None,
    end: str | None = None,
    group_by: str = "event_type",
    buckets: Annotated[int, Query(ge=4, le=500)] = 60,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    cursor: str | None = None,
) -> dict[str, Any]:
    service = LensService(ctx)
    scope = service.scope_for([] if not ref or ref == "workspace" else [ref])
    result = service.query(
        scope,
        filter_text=filter,
        source=source,
        start=parse_timestamp(start) if start else None,
        end=parse_timestamp(end) if end else None,
        group_by=group_by,
        buckets=buckets,
        limit=limit,
        cursor=cursor,
    )
    data: dict[str, Any] = result.to_json_dict()
    return data
