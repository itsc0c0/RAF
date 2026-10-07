"""Snapshot API routes (core capability, mounted at /api/v1/snapshots)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from raf.analysis.providers import install_state_providers
from raf.apps.api.deps import Ctx
from raf.core.snapshots.service import SnapshotService, resolve_state

router = APIRouter(prefix="/snapshots", tags=["snapshots"])


class SnapshotCreate(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    source: str = "current"
    description: str = Field(default="", max_length=2000)


@router.get("")
def list_snapshots(ctx: Ctx) -> dict[str, Any]:
    return {"items": [s.to_json_dict() for s in SnapshotService(ctx.store).list()]}


@router.post("", status_code=201)
def create_snapshot(body: SnapshotCreate, ctx: Ctx) -> dict[str, Any]:
    service = SnapshotService(ctx.store)
    if body.source in ("current", "workspace"):
        snap = service.create(body.name, source="workspace", description=body.description)
    else:
        install_state_providers(ctx)
        snap = service.create_from_state(
            body.name, resolve_state(ctx, body.source), source=body.source, description=body.description
        )
    ctx.audit.record("snapshot.create", affected=[snap.id], details={"source": snap.source})
    return snap.to_json_dict()


@router.get("/{name}")
def get_snapshot(name: str, ctx: Ctx) -> dict[str, Any]:
    return SnapshotService(ctx.store).require(name).to_json_dict()


@router.delete("/{name}")
def delete_snapshot(name: str, ctx: Ctx) -> dict[str, Any]:
    service = SnapshotService(ctx.store)
    snap = service.require(name)
    result = service.delete(name)
    ctx.audit.record("snapshot.delete", affected=[snap.id], details=result)
    return {"name": snap.name, **result}
