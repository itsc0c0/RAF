"""Graph algorithms over :class:`GraphSource` (deterministic, bounded)."""

from __future__ import annotations

from collections import deque
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from pydantic import Field

from raf.core.graph.source import Direction, GraphSource
from raf.core.objects.models import RafModel, Relationship, SecurityObject
from raf.core.objects.types import Criticality


class GraphNode(RafModel):
    id: str
    type: str
    name: str
    depth: int = 0
    criticality: str | None = None
    tags: list[str] = Field(default_factory=list)
    synthetic: bool = False
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    missing: bool = False  # referenced by a relationship but not stored as an object


class GraphEdge(RafModel):
    id: str
    type: str
    source: str
    target: str
    confidence: float
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    valid_to: datetime | None = None
    observations: int = 1
    metadata: dict[str, Any] = Field(default_factory=dict)


class Subgraph(RafModel):
    roots: list[str]
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    truncated: bool = False
    at: datetime | None = None
    depth: int = 0

    def node_index(self) -> dict[str, GraphNode]:
        return {n.id: n for n in self.nodes}


_META_KEEP = (
    "criticality",
    "internet_facing",
    "privileged",
    "ip",
    "os",
    "role",
    "kind",
    "cvss",
    "path",
    "port",
    "display_name",
    "disabled",
    "aliases",
    "cidr",
    "zone",
    "redacted",
    "full_name",
    "department",
)


def to_graph_node(obj: SecurityObject | None, object_id: str, depth: int) -> GraphNode:
    if obj is None:
        otype = object_id.split(":", 1)[0] if ":" in object_id else "unknown"
        return GraphNode(id=object_id, type=otype, name=object_id.split(":", 1)[-1], depth=depth, missing=True)
    crit = Criticality.of(obj.metadata, obj.tags)
    return GraphNode(
        id=obj.id,
        type=obj.type,
        name=obj.name,
        depth=depth,
        criticality=crit.value if crit else None,
        tags=obj.tags,
        synthetic=obj.synthetic,
        first_seen=obj.first_seen,
        last_seen=obj.last_seen,
        metadata={k: obj.metadata[k] for k in _META_KEEP if k in obj.metadata},
    )


def to_graph_edge(rel: Relationship) -> GraphEdge:
    return GraphEdge(
        id=rel.id,
        type=rel.relationship_type,
        source=rel.source_object,
        target=rel.target_object,
        confidence=rel.confidence,
        first_seen=rel.first_seen,
        last_seen=rel.last_seen,
        valid_to=rel.valid_to,
        observations=rel.observations,
        metadata=rel.metadata,
    )


def neighborhood(
    source: GraphSource,
    roots: Sequence[str],
    *,
    depth: int = 1,
    direction: Direction = "both",
    rel_types: Sequence[str] | None = None,
    node_types: Sequence[str] | None = None,
    max_nodes: int = 500,
) -> Subgraph:
    """Breadth-first expansion from ``roots`` (layer by layer, bounded by ``max_nodes``)."""
    depths: dict[str, int] = dict.fromkeys(roots, 0)
    edges: dict[str, Relationship] = {}
    frontier = sorted(set(roots))
    truncated = False
    wanted_types = set(node_types) if node_types else None
    for level in range(1, depth + 1):
        if not frontier:
            break
        next_frontier: list[str] = []
        for rel in source.edges(frontier, direction, rel_types):
            for endpoint in (rel.source_object, rel.target_object):
                if endpoint in depths:
                    continue
                if wanted_types is not None and endpoint.split(":", 1)[0] not in wanted_types:
                    continue
                if len(depths) >= max_nodes:
                    truncated = True
                    break
                depths[endpoint] = level
                next_frontier.append(endpoint)
            if rel.source_object in depths and rel.target_object in depths:
                edges[rel.id] = rel
        frontier = sorted(set(next_frontier))
        if truncated:
            break
    nodes = source.nodes(depths)
    return Subgraph(
        roots=list(roots),
        nodes=[to_graph_node(nodes.get(i), i, d) for i, d in sorted(depths.items(), key=lambda kv: (kv[1], kv[0]))],
        edges=[to_graph_edge(r) for r in sorted(edges.values(), key=lambda r: r.id)],
        truncated=truncated,
        at=source.at,
        depth=depth,
    )


def induced_subgraph(
    source: GraphSource, ids: Sequence[str], *, rel_types: Sequence[str] | None = None, max_nodes: int = 2000
) -> Subgraph:
    """Nodes ``ids`` plus every relationship among them."""
    members = sorted(set(ids))
    truncated = len(members) > max_nodes
    members = members[:max_nodes]
    member_set = set(members)
    edges = [r for r in source.edges(members, "out", rel_types) if r.target_object in member_set]
    nodes = source.nodes(members)
    return Subgraph(
        roots=[],
        nodes=[to_graph_node(nodes.get(i), i, 0) for i in members],
        edges=[to_graph_edge(r) for r in sorted(edges, key=lambda r: r.id)],
        truncated=truncated,
        at=source.at,
    )


class PathStep(RafModel):
    edge: GraphEdge
    forward: bool  # traversed in the relationship's own direction


def shortest_path(
    source: GraphSource,
    start: str,
    goal: str,
    *,
    directed: bool = False,
    rel_types: Sequence[str] | None = None,
    max_depth: int = 8,
    max_visits: int = 50_000,
) -> list[PathStep] | None:
    """Breadth-first shortest path. Undirected by default ("how are these connected?")."""
    if start == goal:
        return []
    parents: dict[str, tuple[str, Relationship, bool]] = {}
    seen = {start}
    queue: deque[tuple[str, int]] = deque([(start, 0)])
    direction: Direction = "out" if directed else "both"
    visits = 0
    while queue:
        layer_node, dist = queue.popleft()
        if dist >= max_depth:
            continue
        visits += 1
        if visits > max_visits:
            return None
        for rel in source.edges([layer_node], direction, rel_types):
            forward = rel.source_object == layer_node
            nxt = rel.target_object if forward else rel.source_object
            if nxt in seen:
                continue
            seen.add(nxt)
            parents[nxt] = (layer_node, rel, forward)
            if nxt == goal:
                steps: list[PathStep] = []
                cur = goal
                while cur != start:
                    prev, prel, pfwd = parents[cur]
                    steps.append(PathStep(edge=to_graph_edge(prel), forward=pfwd))
                    cur = prev
                return list(reversed(steps))
            queue.append((nxt, dist + 1))
    return None


def degree_ranking(source: GraphSource, ids: Sequence[str], limit: int = 10) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    for rel in source.edges(ids, "both"):
        for endpoint in (rel.source_object, rel.target_object):
            if endpoint in counts or endpoint in ids:
                counts[endpoint] = counts.get(endpoint, 0) + 1
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]
