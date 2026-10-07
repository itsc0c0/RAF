"""R$F Graph API routes (mounted at /api/v1/graph)."""

from __future__ import annotations

from typing import Annotated, Any, cast

from fastapi import APIRouter, Query
from fastapi.responses import PlainTextResponse

from raf.core.errors import InvalidInputError
from raf.core.graph.export import export_subgraph
from raf.core.graph.source import Direction
from raf.core.query.scope import resolve_scope
from raf.core.timeutil import parse_timestamp
from raf.products.graph.service import GraphService
from raf.sdk.api import Ctx

router = APIRouter()

_MEDIA = {
    "json": "application/json",
    "cytoscape": "application/json",
    "graphml": "application/xml",
    "dot": "text/vnd.graphviz",
    "csv": "text/csv",
}


def _scope_words(ref: str | None) -> list[str]:
    if not ref or ref == "workspace":
        return []
    return [ref]


@router.get("/view")
def view(
    ctx: Ctx,
    ref: str | None = None,
    depth: Annotated[int | None, Query(ge=1, le=6)] = None,
    rel: Annotated[list[str] | None, Query()] = None,
    type: Annotated[list[str] | None, Query()] = None,
    at: str | None = None,
    max_nodes: Annotated[int | None, Query(ge=1, le=5000)] = None,
    direction: str = "both",
) -> dict[str, Any]:
    if direction not in ("in", "out", "both"):
        raise InvalidInputError("direction must be in, out or both")
    scope = resolve_scope(ctx, _scope_words(ref))
    graph = GraphService(ctx).view(
        scope,
        depth=depth,
        rel_types=rel,
        node_types=type,
        at=parse_timestamp(at) if at else None,
        max_nodes=max_nodes,
        direction=cast(Direction, direction),
    )
    return graph.to_json_dict() | {"scope": scope.to_dict()}


@router.get("/neighbors")
def neighbors(
    ctx: Ctx,
    ref: str,
    direction: str = "both",
    rel: Annotated[list[str] | None, Query()] = None,
    at: str | None = None,
    limit: Annotated[int | None, Query(ge=1, le=5000)] = None,
) -> dict[str, Any]:
    if direction not in ("in", "out", "both"):
        raise InvalidInputError("direction must be in, out or both")
    target = ctx.resolve(ref)
    return (
        GraphService(ctx)
        .neighbors(
            target.id,
            direction=cast(Direction, direction),
            rel_types=rel,
            at=parse_timestamp(at) if at else None,
            limit=limit,
        )
        .to_json_dict()
    )


@router.get("/path")
def path(
    ctx: Ctx,
    source: str,
    target: str,
    directed: bool = False,
    rel: Annotated[list[str] | None, Query()] = None,
    at: str | None = None,
    max_depth: Annotated[int, Query(ge=1, le=12)] = 8,
) -> dict[str, Any]:
    a, b = ctx.resolve(source), ctx.resolve(target)
    result = GraphService(ctx).path(
        a.id, b.id, directed=directed, rel_types=rel, max_depth=max_depth, at=parse_timestamp(at) if at else None
    )
    return result.to_json_dict() | {"length": result.length}


@router.get("/export")
def export(
    ctx: Ctx, ref: str | None = None, format: str = "graphml", depth: Annotated[int | None, Query(ge=1, le=6)] = None
) -> PlainTextResponse:
    scope = resolve_scope(ctx, _scope_words(ref))
    graph = GraphService(ctx).view(scope, depth=depth)
    return PlainTextResponse(export_subgraph(graph, format), media_type=_MEDIA.get(format, "text/plain"))


@router.get("/stats")
def stats(ctx: Ctx) -> dict[str, Any]:
    return GraphService(ctx).stats()
