"""R$F Range API routes (mounted at /api/v1/range)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from raf.core.timeutil import parse_timestamp
from raf.products.range.service import RangeService, preset_table
from raf.sdk.api import Ctx

router = APIRouter()


class CreateRange(BaseModel):
    name: str = Field(..., max_length=41)
    preset: str | None = Field(None, max_length=40)
    seed: int | None = Field(None, ge=0, le=2**31, description="Default: the range.default_seed setting.")
    config: dict[str, Any] = Field(default_factory=dict)
    start: str | None = Field(None, max_length=40)


class Advance(BaseModel):
    hours: float = Field(24.0, gt=0, le=24 * 14)


@router.get("/presets")
def presets() -> dict[str, Any]:
    return {"items": preset_table()}


@router.get("/ranges")
def list_ranges(ctx: Ctx) -> dict[str, Any]:
    return {"items": [r.to_json_dict() for r in RangeService(ctx).ranges()]}


@router.post("/ranges")
def create_range(request: CreateRange, ctx: Ctx) -> dict[str, Any]:
    run = RangeService(ctx).create(
        request.name,
        preset=request.preset,
        seed=request.seed,
        config=request.config or None,
        start=parse_timestamp(request.start) if request.start else None,
    )
    data: dict[str, Any] = run.to_json_dict()
    return data


@router.get("/ranges/{name}")
def range_status(name: str, ctx: Ctx) -> dict[str, Any]:
    return RangeService(ctx).status(name)


@router.post("/ranges/{name}/start")
def start_range(name: str, ctx: Ctx, request: Advance | None = None) -> dict[str, Any]:
    data: dict[str, Any] = RangeService(ctx).start(name, hours=(request or Advance()).hours).to_json_dict()
    return data


@router.post("/ranges/{name}/tick")
def tick_range(name: str, ctx: Ctx, request: Advance | None = None) -> dict[str, Any]:
    data: dict[str, Any] = RangeService(ctx).tick(name, hours=(request or Advance()).hours).to_json_dict()
    return data


@router.post("/ranges/{name}/stop")
def stop_range(name: str, ctx: Ctx) -> dict[str, Any]:
    data: dict[str, Any] = RangeService(ctx).stop(name).to_json_dict()
    return data


@router.post("/ranges/{name}/reset")
def reset_range(name: str, ctx: Ctx) -> dict[str, Any]:
    data: dict[str, Any] = RangeService(ctx).reset(name).to_json_dict()
    return data


@router.delete("/ranges/{name}")
def destroy_range(name: str, ctx: Ctx) -> dict[str, Any]:
    data: dict[str, Any] = RangeService(ctx).destroy(name).to_json_dict()
    return data
