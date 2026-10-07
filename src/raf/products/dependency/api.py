"""R$F Dependency API routes (mounted at /api/v1/dependency).

Read-only by design: scanning a directory, importing advisories and importing
SBOMs read paths on the machine running R$F, so they are CLI-only
(``raf dependency scan|advisories import|sbom import``). The API never accepts a
server path.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from raf.apps.api.deps import Ctx
from raf.products.dependency.service import DependencyService

router = APIRouter()


@router.get("/projects")
def projects(ctx: Ctx) -> dict[str, Any]:
    items = DependencyService(ctx).projects()
    return {"items": items, "total": len(items)}


@router.get("/projects/{ref:path}/graph")
def project_graph(ref: str, ctx: Ctx) -> dict[str, Any]:
    return DependencyService(ctx).project_graph(ref)


@router.get("/vulnerable")
def vulnerable(ctx: Ctx, include_unused: bool = False) -> dict[str, Any]:
    items = DependencyService(ctx).vulnerable(include_unused=include_unused)
    return {"items": items, "total": len(items)}


@router.get("/advisories")
def advisories(ctx: Ctx) -> dict[str, Any]:
    items = DependencyService(ctx).advisories()
    return {"items": items, "total": len(items)}
