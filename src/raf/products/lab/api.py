"""R$F Lab API routes (mounted at /api/v1/lab).

There is deliberately no shell or exec route. Running commands in a lab over HTTP would turn
the API into a remote command execution service: ``raf serve`` can be exposed beyond loopback
with a token, and a browser on the same machine can reach a loopback API. Commands run in a
lab only through the local CLI (``raf lab shell`` / ``raf lab exec``).

Mount paths are validated exactly like on the command line (same function), and must be
absolute because they are resolved on the server.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Query
from pydantic import BaseModel, ConfigDict, Field, StrictBool

from raf.apps.api.deps import Ctx
from raf.products.lab.service import MAX_DESCRIPTION, MAX_MOUNTS, LabService, LifecycleResult

router = APIRouter()

MountPath = Annotated[str, Field(min_length=1, max_length=4096)]
BackendChoice = Annotated[str | None, Query(max_length=16, description="auto, docker or podman")]


class CreateLabRequest(BaseModel):
    """``POST /labs``. Unknown fields are rejected; flags must be JSON booleans."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=64)
    image: str | None = Field(None, max_length=255)
    mounts: list[MountPath] = Field(default_factory=list, max_length=MAX_MOUNTS)
    allow_outbound: StrictBool = False
    memory: str | None = Field(None, max_length=16)
    cpus: str | float | None = None
    root: StrictBool = False
    description: str = Field("", max_length=MAX_DESCRIPTION)
    backend: str | None = Field(None, max_length=16)


def _lifecycle(service: LabService, result: LifecycleResult) -> dict[str, Any]:
    data = service.payload(result.lab, live=True, note=result.note)
    data["changed"] = result.changed
    data["created"] = result.created
    return data


@router.get("/status")
def status(ctx: Ctx, backend: BackendChoice = None) -> dict[str, Any]:
    """Container backend availability: ``{backend, available, reason, version}``."""
    return LabService(ctx).backend_status(backend)


@router.get("/labs")
def list_labs(ctx: Ctx) -> dict[str, Any]:
    """Labs of the workspace, with live state when the backend is available (``live`` says which)."""
    service = LabService(ctx)
    data = service.status()
    items = data["labs"]
    result: dict[str, Any] = {"items": items, "total": len(items)}
    if data.get("invalid"):
        result["invalid"] = data["invalid"]
    return result


@router.post("/labs", status_code=201)
def create_lab(ctx: Ctx, request: CreateLabRequest) -> dict[str, Any]:
    """Validate and record a lab definition; no container is created until ``start``."""
    service = LabService(ctx)
    lab = service.create(
        request.name,
        image=request.image,
        mounts=request.mounts,
        allow_outbound=request.allow_outbound,
        memory=request.memory,
        cpus=request.cpus,
        root=request.root,
        description=request.description,
        backend=request.backend,
        require_absolute_mounts=True,
    )
    return service.payload(lab, detail=True)


@router.get("/labs/{name}")
def get_lab(ctx: Ctx, name: str) -> dict[str, Any]:
    """One lab in detail (live state when possible, plus the exact container arguments)."""
    service = LabService(ctx)
    return service.observe(service.get(name), detail=True)


@router.post("/labs/{name}/start")
def start_lab(ctx: Ctx, name: str) -> dict[str, Any]:
    service = LabService(ctx)
    return _lifecycle(service, service.start(name))


@router.post("/labs/{name}/stop")
def stop_lab(ctx: Ctx, name: str) -> dict[str, Any]:
    service = LabService(ctx)
    return _lifecycle(service, service.stop(name))


@router.delete("/labs/{name}")
def destroy_lab(ctx: Ctx, name: str, forget: bool = False) -> dict[str, Any]:
    """Remove the container (if any) and the definition. ``forget=true`` deletes the definition even
    when the backend is unavailable (an existing container is then left in place)."""
    return LabService(ctx).destroy(name, forget=forget)
