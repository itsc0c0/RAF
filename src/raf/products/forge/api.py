"""R$F Forge API routes (mounted at /api/v1/forge). Results are always imported (no server-side files)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from raf.core.timeutil import parse_timestamp
from raf.products.forge.service import ForgeService, catalog
from raf.sdk.api import Ctx

router = APIRouter()

API_MAX_COUNT = 100_000


class GenerateRequest(BaseModel):
    kind: str = Field(..., max_length=20)
    count: int = Field(1000, ge=1, le=API_MAX_COUNT)
    seed: int = Field(42, ge=0, le=2**31)
    start: str | None = Field(None, max_length=40)
    hours: float = Field(24.0, gt=0, le=24 * 90)
    noise: float = Field(0.05, ge=0.0, le=1.0)
    population: str = Field("auto", max_length=20)


class ScenarioRequest(BaseModel):
    name: str = Field(..., max_length=40)
    seed: int = Field(42, ge=0, le=2**31)
    start: str | None = Field(None, max_length=40)
    population: str = Field("auto", max_length=20)


@router.get("/catalog")
def get_catalog() -> dict[str, Any]:
    return catalog()


@router.post("/generate")
def generate(request: GenerateRequest, ctx: Ctx) -> dict[str, Any]:
    result = ForgeService(ctx).telemetry(
        request.kind,
        count=request.count,
        seed=request.seed,
        start=parse_timestamp(request.start) if request.start else None,
        hours=request.hours,
        noise=request.noise,
        population=request.population,
    )
    data: dict[str, Any] = result.to_json_dict()
    return data


@router.post("/scenario")
def run_scenario(request: ScenarioRequest, ctx: Ctx) -> dict[str, Any]:
    result = ForgeService(ctx).scenario(
        request.name,
        seed=request.seed,
        start=parse_timestamp(request.start) if request.start else None,
        population=request.population,
    )
    data: dict[str, Any] = result.to_json_dict()
    return data
