"""R$F Replay API routes (mounted at /api/v1/replay)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from raf.core.query.scope import resolve_scope
from raf.core.timeutil import parse_timestamp
from raf.products.replay.service import ReplayService
from raf.sdk.api import Ctx

router = APIRouter()


@router.get("/{ref:path}/state")
def state(ref: str, ctx: Ctx, at: str, include_context: bool = True) -> dict[str, Any]:
    service = ReplayService(ctx)
    timeline = service.build(resolve_scope(ctx, [ref]), include_context=include_context)
    return service.state_at(timeline, parse_timestamp(at)).to_json_dict()


@router.get("/{ref:path}/window")
def window(ref: str, ctx: Ctx, start: str, end: str) -> dict[str, Any]:
    service = ReplayService(ctx)
    timeline = service.build(resolve_scope(ctx, [ref]))
    return service.changes(timeline, parse_timestamp(start), parse_timestamp(end))


@router.get("/{ref:path}")
def timeline(
    ref: str, ctx: Ctx, include_context: bool = True, start: str | None = None, end: str | None = None
) -> dict[str, Any]:
    """Initial state plus ordered steps with deltas; the web player applies deltas client-side."""
    built = ReplayService(ctx).build(
        resolve_scope(ctx, [ref]),
        include_context=include_context,
        start=parse_timestamp(start) if start else None,
        end=parse_timestamp(end) if end else None,
    )
    return built.to_json_dict()
