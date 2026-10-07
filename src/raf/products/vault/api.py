"""R$F Vault API routes (mounted at /api/v1/vault).

Read-only by design: scanning reads files on the machine running R$F, so it is
only available from the CLI (``raf vault scan``). The API never accepts a server
path to scan and only ever returns redacted values and fingerprints.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Query

from raf.apps.api.deps import Ctx
from raf.core.objects.types import Severity
from raf.products.vault.service import VaultService

router = APIRouter()


@router.get("/findings")
def findings(
    ctx: Ctx,
    status: str = "OPEN",
    severity: str | None = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict[str, Any]:
    items, total = VaultService(ctx).findings(
        status=status, min_severity=Severity.parse(severity) if severity else None, limit=limit, offset=offset
    )
    return {"items": [f.to_json_dict() for f in items], "total": total, "limit": limit, "offset": offset}


@router.get("/secrets")
def secrets(
    ctx: Ctx,
    include_removed: bool = False,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict[str, Any]:
    items, total = VaultService(ctx).secrets(include_removed=include_removed, limit=limit, offset=offset)
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/rules")
def rules(ctx: Ctx) -> dict[str, Any]:
    return {"items": VaultService(ctx).rules()}
