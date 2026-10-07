"""R$F Trace API routes (mounted at /api/v1/trace)."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Query

from raf.core.errors import InvalidInputError
from raf.products.trace.service import TraceService
from raf.sdk.api import Ctx

router = APIRouter()


@router.get("/{ref:path}")
def trace(ref: str, ctx: Ctx, direction: str = "both", depth: Annotated[int, Query(ge=1, le=6)] = 3) -> dict[str, Any]:
    if direction not in ("both", "back", "backward", "forward", "fwd"):
        raise InvalidInputError("direction must be back, forward or both")
    resolved = ctx.resolve(ref)
    return TraceService(ctx).trace(resolved.id, direction=direction, depth=depth).to_json_dict()
