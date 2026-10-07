"""R$F OS screen routes (``/api/v1/tui/...``) used by the ``raf-os`` terminal control panel.

Read-only: every route builds a screen from the same services the CLI uses (see
:mod:`raf.analysis.screens` and docs/tui.md). Ghost experiments run in an unsaved, in-memory model.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Query

from raf.analysis import screens
from raf.apps.api.deps import Ctx

router = APIRouter(prefix="/tui", tags=["tui"])

Param = Annotated[str | None, Query(max_length=500)]


@router.get("/pages")
def pages(ctx: Ctx) -> dict[str, Any]:
    """System status, workspace statistics, the default focus and the page list."""
    return screens.pages_index(ctx)


@router.get("/screen/{page}")
def screen(ctx: Ctx, page: str, ref: Param = None, question: Param = None) -> dict[str, Any]:
    """One page as a screen document: ``{page, title, subtitle, param, blocks, notes}``."""
    return screens.screen(ctx, page, question if page == "oracle" else ref)


@router.get("/inspect")
def inspect(ctx: Ctx, ref: Annotated[str, Query(min_length=1, max_length=500)]) -> dict[str, Any]:
    """An object, event or finding as a screen document (the inspector popup)."""
    return screens.inspect(ctx, ref).to_dict()
