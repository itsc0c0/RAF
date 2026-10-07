"""R$F Oracle API routes (mounted at /api/v1/oracle).

Oracle only reads: there is no route that lets an answer, a model or retrieved data change
anything in the workspace.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict, Field

from raf.apps.api.deps import Ctx
from raf.products.oracle.service import MAX_QUESTION, OracleService

router = APIRouter()


class AskRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    question: str = Field(..., min_length=1, max_length=MAX_QUESTION)


@router.post("/ask")
def ask(ctx: Ctx, request: AskRequest) -> dict[str, Any]:
    """``{answer, provider, mode, intent, citations: [{id, label, type}], invalid_references, facts:
    [{key, kind, text, refs, source, untrusted}], suggestions, warnings, notice}``."""
    data: dict[str, Any] = OracleService(ctx).ask(request.question).to_json_dict()
    return data


@router.get("/status")
def status(ctx: Ctx) -> dict[str, Any]:
    """Provider configuration and readiness; never the API key."""
    return OracleService(ctx).status()
