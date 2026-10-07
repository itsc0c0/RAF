"""R$F Graph service: views of the shared security graph."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any

from pydantic import Field
from sqlalchemy import select

from raf.core.context.app import RafContext
from raf.core.graph.algorithms import (
    GraphEdge,
    PathStep,
    Subgraph,
    degree_ranking,
    induced_subgraph,
    neighborhood,
    shortest_path,
    to_graph_node,
)
from raf.core.graph.source import Direction, StoreGraphSource
from raf.core.ids import digest
from raf.core.objects.models import RafModel
from raf.core.objects.types import ObjectType
from raf.core.query.scope import Scope
from raf.core.storage import schema as s
from raf.core.storage.database import chunks

OVERVIEW_TYPES = (
    ObjectType.HOST,
    ObjectType.USER,
    ObjectType.IDENTITY,
    ObjectType.GROUP,
    ObjectType.ROLE,
    ObjectType.SERVICE,
    ObjectType.NETWORK,
    ObjectType.CLOUD_RESOURCE,
    ObjectType.VULNERABILITY,
    ObjectType.SECRET,
)


class PathHop(RafModel):
    source: str
    source_name: str
    target: str
    target_name: str
    relationship: GraphEdge
    forward: bool


class PathResult(RafModel):
    source: str
    target: str
    found: bool
    directed: bool
    hops: list[PathHop] = Field(default_factory=list)
    at: datetime | None = None

    @property
    def length(self) -> int:
        return len(self.hops)


class GraphService:
    def __init__(self, ctx: RafContext) -> None:
        self.ctx = ctx
        self.store = ctx.store

    def source(self, at: datetime | None = None) -> StoreGraphSource:
        return StoreGraphSource(self.store, at)

    def _max_nodes(self, value: int | None) -> int:
        return int(value or self.ctx.settings.get("graph.max_nodes"))

    # ------------------------------------------------------------------ views
    def view(
        self,
        scope: Scope,
        *,
        depth: int | None = None,
        rel_types: Sequence[str] | None = None,
        node_types: Sequence[str] | None = None,
        at: datetime | None = None,
        max_nodes: int | None = None,
        direction: Direction = "both",
    ) -> Subgraph:
        src = self.source(at)
        limit = self._max_nodes(max_nodes)
        if scope.kind == "object":
            return neighborhood(
                src,
                [scope.id],
                depth=depth or int(self.ctx.settings.get("graph.default_depth")),
                direction=direction,
                rel_types=rel_types,
                node_types=node_types,
                max_nodes=limit,
            )
        if scope.kind == "incident":
            return self._incident_view(scope, rel_types=rel_types, max_nodes=limit, at=at)
        if scope.kind in ("analysis", "job"):
            ids = self._job_objects(scope.job_ids, scope.source)
            graph = induced_subgraph(src, ids, rel_types=rel_types, max_nodes=limit)
            graph.roots = [scope.id]
            return graph
        types = list(node_types) if node_types else [t.value for t in OVERVIEW_TYPES]
        ids = [o.id for o in self.store.objects.list(types=types, limit=limit + 1, order="id")]
        graph = induced_subgraph(src, ids, rel_types=rel_types, max_nodes=limit)
        graph.roots = []
        return graph

    def _incident_view(
        self, scope: Scope, *, rel_types: Sequence[str] | None, max_nodes: int, at: datetime | None
    ) -> Subgraph:
        eo, ie = s.event_objects.c, s.incident_events.c
        stmt = (
            select(eo.object_id)
            .where(eo.event_id.in_(select(ie.event_id).where(ie.incident_id == scope.id)))
            .distinct()
        )
        with self.store.engine.connect() as conn:
            ids = sorted({r[0] for r in conn.execute(stmt)})
        graph = induced_subgraph(self.source(at), ids, rel_types=rel_types, max_nodes=max_nodes)
        incident_node = to_graph_node(scope.obj, scope.id, 0)
        graph.nodes.insert(0, incident_node)
        for node in graph.nodes[1:]:
            node.depth = 1
            graph.edges.append(
                GraphEdge(
                    id="virtual:" + digest(scope.id, node.id),
                    type="INVOLVES",
                    source=scope.id,
                    target=node.id,
                    confidence=1.0,
                    metadata={"virtual": True, "reason": "involved in incident events"},
                )
            )
        graph.roots = [scope.id]
        return graph

    def _job_objects(self, job_ids: Sequence[str], source: str | None = None) -> list[str]:
        if not job_ids:
            return []
        ids = self.store.provenance.subjects_for_jobs(job_ids, kind="object", source=source)
        eo, ev = s.event_objects.c, s.events.c
        with self.store.engine.connect() as conn:
            for batch in chunks(list(job_ids), 100):
                events = select(ev.id).where(ev.job_id.in_(batch))
                if source:
                    events = events.where(ev.source == source)
                stmt = select(eo.object_id).where(eo.event_id.in_(events)).distinct()
                ids.update(r[0] for r in conn.execute(stmt))
        return sorted(ids)

    def neighbors(
        self,
        object_id: str,
        *,
        direction: Direction = "both",
        rel_types: Sequence[str] | None = None,
        at: datetime | None = None,
        limit: int | None = None,
    ) -> Subgraph:
        return neighborhood(
            self.source(at),
            [object_id],
            depth=1,
            direction=direction,
            rel_types=rel_types,
            max_nodes=self._max_nodes(limit),
        )

    def path(
        self,
        source_id: str,
        target_id: str,
        *,
        directed: bool = False,
        rel_types: Sequence[str] | None = None,
        max_depth: int = 8,
        at: datetime | None = None,
    ) -> PathResult:
        src = self.source(at)
        steps = shortest_path(src, source_id, target_id, directed=directed, rel_types=rel_types, max_depth=max_depth)
        if steps is None:
            return PathResult(source=source_id, target=target_id, found=False, directed=directed, at=at)
        return PathResult(
            source=source_id,
            target=target_id,
            found=True,
            directed=directed,
            hops=self._hops(steps, source_id, src),
            at=at,
        )

    def _hops(self, steps: list[PathStep], start: str, src: StoreGraphSource) -> list[PathHop]:
        ids = {start} | {st.edge.source for st in steps} | {st.edge.target for st in steps}
        names = {i: o.name for i, o in src.nodes(ids).items()}
        hops: list[PathHop] = []
        current = start
        for step in steps:
            nxt = step.edge.target if step.forward else step.edge.source
            hops.append(
                PathHop(
                    source=current,
                    source_name=names.get(current, current),
                    target=nxt,
                    target_name=names.get(nxt, nxt),
                    relationship=step.edge,
                    forward=step.forward,
                )
            )
            current = nxt
        return hops

    def stats(self) -> dict[str, Any]:
        objects = self.store.objects.count_by_type()
        relationships = self.store.relationships.count_by_type()
        hubs_ids = [
            o.id for o in self.store.objects.list(types=[t.value for t in OVERVIEW_TYPES], limit=2000, order="id")
        ]
        ranking = degree_ranking(self.source(), hubs_ids, limit=10)
        names = {o.id: o.name for o in self.store.objects.get_many([i for i, _ in ranking]).values()}
        return {
            "objects": objects,
            "relationships": relationships,
            "total_objects": sum(objects.values()),
            "total_relationships": sum(relationships.values()),
            "most_connected": [{"id": i, "name": names.get(i, i), "degree": d} for i, d in ranking],
        }
