"""R$F IAM API routes (mounted at /api/v1/iam)."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Query

from raf.products.iam.service import IamReport, IamService
from raf.sdk.api import Ctx

router = APIRouter()


def _report_payload(report: IamReport) -> dict[str, Any]:
    data: dict[str, Any] = report.to_json_dict()
    data["summary"] = {
        "principals": report.principals,
        "privileged_principals": report.privileged_principals,
        "findings": len(report.findings),
        "by_rule": report.by_rule,
        "resolved": report.resolved,
        "reference_time": data.get("reference_time"),
        "generated_at": data.get("generated_at"),
    }
    return data


@router.post("/analyze")
def analyze(ctx: Ctx, persist: bool = True) -> dict[str, Any]:
    """Run all IAM analyzers; findings are recorded unless ``persist=false``."""
    report = IamService(ctx).analyze(persist=persist)
    if persist:
        ctx.audit.record(
            "iam.analyze",
            affected=[f.id for f in report.findings[:50]],
            details={"findings": len(report.findings), "resolved": report.resolved, "via": "api"},
        )
    return _report_payload(report)


@router.get("/analyze")
def analyze_preview(ctx: Ctx) -> dict[str, Any]:
    """Dry run: compute IAM findings without recording them."""
    return _report_payload(IamService(ctx).analyze(persist=False))


@router.get("/path")
def path(
    ctx: Ctx,
    source: str,
    target: str,
    max_depth: Annotated[int, Query(ge=1, le=16)] = 10,
    limit: Annotated[int, Query(ge=1, le=10)] = 3,
) -> dict[str, Any]:
    a, b = ctx.resolve(source), ctx.resolve(target)
    paths = IamService(ctx).paths(a.id, b.id, max_depth=max_depth, limit=limit)
    return {"source": a.id, "target": b.id, "paths": [p.to_json_dict() for p in paths]}


@router.get("/principals/{ref:path}")
def principal(ref: str, ctx: Ctx) -> dict[str, Any]:
    resolved = ctx.resolve(ref)
    data: dict[str, Any] = IamService(ctx).effective_access(resolved.id, findings=True).to_json_dict()
    return data
