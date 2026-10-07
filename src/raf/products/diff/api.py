"""R$F Diff API routes (mounted at /api/v1/diff)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from raf.products.diff.service import DiffService, validate_category
from raf.sdk.api import Ctx

router = APIRouter()


@router.get("")
def diff(ctx: Ctx, a: str, b: str, category: str | None = None, limit: int = 500) -> dict[str, Any]:
    category = validate_category(category) if category is not None else None
    result = DiffService(ctx).diff(a, b)
    data = result.to_json_dict()
    changes = [c for c in data["changes"] if category is None or c["category"] == category]
    data["changes"] = changes[: max(1, min(limit, 5000))]
    data["truncated"] = len(changes) > len(data["changes"])
    return data
