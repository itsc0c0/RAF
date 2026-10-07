"""R$F Blast API routes (mounted at /api/v1/blast)."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Query

from raf.apps.api.deps import Ctx
from raf.core.timeutil import parse_timestamp
from raf.products.blast.service import BlastService

router = APIRouter()


@router.get("/{ref:path}")
def blast(
    ref: str,
    ctx: Ctx,
    max_depth: Annotated[int | None, Query(ge=1, le=12)] = None,
    min_confidence: Annotated[float | None, Query(ge=0.0, le=1.0)] = None,
    at: str | None = None,
) -> dict[str, Any]:
    resolved = ctx.resolve(ref)
    result = BlastService(ctx).blast(
        resolved.id, max_depth=max_depth, min_confidence=min_confidence, at=parse_timestamp(at) if at else None
    )
    data: dict[str, Any] = result.to_json_dict()
    return data
