"""R$F Exposure API routes (mounted at /api/v1/exposure)."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Query

from raf.apps.api.deps import Ctx
from raf.products.exposure.service import ExposureService, level_rank, parse_level

router = APIRouter()


@router.get("")
def list_exposure(
    ctx: Ctx, limit: Annotated[int, Query(ge=1, le=1000)] = 100, min_level: str | None = None, type: str | None = None
) -> dict[str, Any]:
    """Ranked assets with explainable factors (read-only: findings are recorded by POST /exposure/analyze)."""
    threshold = parse_level(min_level)
    report = ExposureService(ctx).report(persist=False)
    items = [
        i
        for i in report.items
        if (threshold is None or level_rank(i.level) >= level_rank(threshold))
        and (type is None or i.object["type"] == type)
    ]
    return {
        "items": [i.to_json_dict() for i in items[:limit]],
        "total": len(items),
        "metrics": report.metrics.to_json_dict(),
        "by_level": report.by_level,
        "notes": report.notes,
    }


@router.post("/analyze")
def analyze(ctx: Ctx) -> dict[str, Any]:
    report = ExposureService(ctx).report(persist=True)
    ctx.audit.record(
        "exposure.analyze",
        affected=[i.object["id"] for i in report.items[:20]],
        details={"assets": len(report.items), "findings": report.findings, "via": "api"},
    )
    return {
        "findings": report.findings,
        "resolved": report.resolved,
        "by_level": report.by_level,
        "metrics": report.metrics.to_json_dict(),
    }


@router.get("/{ref:path}")
def get_exposure(ref: str, ctx: Ctx) -> dict[str, Any]:
    resolved = ctx.resolve(ref)
    data: dict[str, Any] = ExposureService(ctx).assess(resolved.id).to_json_dict()
    return data
