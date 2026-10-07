"""R$F Ghost API routes (mounted at /api/v1/ghost)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from raf.products.ghost.service import GhostService, operation_help
from raf.sdk.api import Ctx

router = APIRouter()


class CreateRequest(BaseModel):
    name: str = Field(..., max_length=63)
    base: str = Field("current", max_length=120)
    description: str = Field("", max_length=500)


class CloneRequest(BaseModel):
    name: str = Field(..., max_length=63)


class OpRequest(BaseModel):
    op: str = Field(..., max_length=40)
    arg: str | None = Field(None, max_length=500)
    params: dict[str, Any] = Field(default_factory=dict)

    def argument(self) -> str:
        if self.arg:
            return self.arg
        value = self.params.get("arg") or self.params.get("target") or ""
        return str(value)


def _summary(model: Any) -> dict[str, Any]:
    """A model without its operations log (same field names as the full model, plus ``ops_count``)."""
    return {
        "name": model.name,
        "base_snapshot": model.base_snapshot,
        "base_label": model.base_label,
        "parent": model.parent,
        "ops_count": len(model.ops),
        "created_at": model.created_at,
        "updated_at": model.updated_at,
        "description": model.description,
    }


@router.get("/models")
def list_models(ctx: Ctx) -> dict[str, Any]:
    return {"items": [_summary(m) for m in GhostService(ctx).models()]}


@router.post("/models", status_code=201)
def create_model(request: CreateRequest, ctx: Ctx) -> dict[str, Any]:
    data: dict[str, Any] = (
        GhostService(ctx).create(request.name, base=request.base, description=request.description).to_json_dict()
    )
    return data


@router.get("/operations")
def operations() -> dict[str, Any]:
    return {"items": [{"op": op, "argument": arg, "effect": effect} for op, arg, effect in operation_help()]}


@router.get("/compare")
def compare(ctx: Ctx, a: str, b: str) -> dict[str, Any]:
    data: dict[str, Any] = GhostService(ctx).compare(a, b).to_json_dict()
    data["a_metrics"], data["b_metrics"] = data["a"]["metrics"], data["b"]["metrics"]
    return data


@router.get("/models/{name}")
def get_model(name: str, ctx: Ctx) -> dict[str, Any]:
    data: dict[str, Any] = GhostService(ctx).get(name).to_json_dict()
    return data


@router.post("/models/{name}/clone", status_code=201)
def clone_model(name: str, request: CloneRequest, ctx: Ctx) -> dict[str, Any]:
    data: dict[str, Any] = GhostService(ctx).clone(name, request.name).to_json_dict()
    return data


@router.post("/models/{name}/ops")
def apply_op(name: str, request: OpRequest, ctx: Ctx) -> dict[str, Any]:
    model, applied = GhostService(ctx).modify(name, [(request.op.strip().lower(), request.argument())])
    return {"model": model.to_json_dict(), "applied": [a.to_json_dict() for a in applied]}


@router.post("/models/{name}/undo")
def undo(name: str, ctx: Ctx) -> dict[str, Any]:
    model, removed = GhostService(ctx).undo(name)
    return {"model": model.to_json_dict(), "removed": removed.to_json_dict()}


@router.get("/models/{name}/simulate")
def simulate(name: str, ctx: Ctx, limit: int = 20) -> dict[str, Any]:
    service = GhostService(ctx)
    summary, items, _control = service.summarize(service.state_for(name, lean=True))
    return {"summary": summary.to_json_dict(), "items": [i.to_json_dict() for i in items[: max(1, min(limit, 200))]]}


@router.delete("/models/{name}")
def delete_model(name: str, ctx: Ctx) -> dict[str, Any]:
    return GhostService(ctx).delete(name)
