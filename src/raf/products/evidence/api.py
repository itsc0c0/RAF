"""R$F Evidence API routes (mounted at /api/v1/evidence)."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, File, Form, UploadFile
from pydantic import BaseModel, Field

from raf.core.errors import InvalidInputError
from raf.products.evidence.service import EvidenceService
from raf.sdk.api import Ctx

router = APIRouter()


class CreateCase(BaseModel):
    name: str = Field(..., max_length=64)
    title: str = Field("", max_length=200)
    description: str = Field("", max_length=2000)
    incident: str | None = Field(None, max_length=200)


class VerifyRequest(BaseModel):
    items: list[str] = Field(default_factory=list, max_length=1000)


class NoteRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=4000)


@router.get("/cases")
def list_cases(ctx: Ctx) -> dict[str, Any]:
    service = EvidenceService(ctx)
    return {"items": [c.to_json_dict() | {"item_count": len(service.items(c.name))} for c in service.cases()]}


@router.post("/cases")
def create_case(request: CreateCase, ctx: Ctx) -> dict[str, Any]:
    data: dict[str, Any] = (
        EvidenceService(ctx)
        .create_case(request.name, title=request.title, description=request.description, incident=request.incident)
        .to_json_dict()
    )
    return data


@router.get("/cases/{case}")
def get_case(case: str, ctx: Ctx) -> dict[str, Any]:
    service = EvidenceService(ctx)
    found = service.get_case(case)
    items = service.items(found.name)
    return found.to_json_dict() | {"items": [i.to_json_dict() for i in items], "item_count": len(items)}


@router.post("/cases/{case}/items")
def upload_item(
    case: str,
    ctx: Ctx,
    file: Annotated[UploadFile, File(description="Evidence file (size limited by api.max_upload_mb).")],
    note: Annotated[str | None, Form(max_length=4000)] = None,
    parse: Annotated[bool, Form()] = True,
) -> dict[str, Any]:
    """Upload one artifact: it is hashed, stored read-only and parsed like a CLI import."""
    service = EvidenceService(ctx)
    service.get_case(case)
    name = Path(file.filename or "upload.bin").name
    if not name or name.startswith("."):
        raise InvalidInputError("The uploaded file needs a regular file name.")
    with tempfile.TemporaryDirectory(prefix="raf-evidence-") as tmp:
        target = Path(tmp) / name
        with target.open("wb") as out:
            shutil.copyfileobj(file.file, out, length=1024 * 1024)
        result = service.import_path(target, case, parse=parse, note=note)
    data: dict[str, Any] = result.to_json_dict()
    return data


@router.post("/cases/{case}/verify")
def verify_case(case: str, ctx: Ctx, request: VerifyRequest | None = None) -> dict[str, Any]:
    items = request.items if request and request.items else None
    data: dict[str, Any] = EvidenceService(ctx).verify(case=case, item_ids=items).to_json_dict()
    return data


@router.get("/items")
def list_items(ctx: Ctx, case: str | None = None) -> dict[str, Any]:
    return {"items": [i.to_json_dict() for i in EvidenceService(ctx).items(case)]}


@router.get("/items/{item_id}")
def get_item(item_id: str, ctx: Ctx) -> dict[str, Any]:
    data: dict[str, Any] = EvidenceService(ctx).get_item(item_id).to_json_dict()
    return data


@router.post("/items/{item_id}/notes")
def add_note(item_id: str, request: NoteRequest, ctx: Ctx) -> dict[str, Any]:
    data: dict[str, Any] = EvidenceService(ctx).note(item_id, request.text).to_json_dict()
    return data
