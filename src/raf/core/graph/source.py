"""Graph sources: one traversal API over different representations of security state.

* :class:`StoreGraphSource` - the live workspace, expanded lazily with indexed
  queries (never loads the whole graph), optionally "as of" a point in time.
* :class:`MemoryGraphSource` - an in-memory graph (snapshots, Ghost models,
  Replay states).

Every algorithm in :mod:`raf.core.graph.algorithms` and every product that
traverses relationships (Graph, Trace, Blast, IAM, Exposure, Ghost) works
against this protocol, which is what makes results comparable across
"current", "snapshot", "what-if" and "at time T".
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Sequence
from datetime import datetime
from typing import Literal, Protocol, runtime_checkable

from raf.core.objects.models import Relationship, SecurityObject
from raf.core.objects.semantics import NON_PROPAGATING_TYPES, PROPAGATION_RELATIONSHIPS
from raf.core.storage.store import Store

Direction = Literal["out", "in", "both"]


@runtime_checkable
class GraphSource(Protocol):
    @property
    def at(self) -> datetime | None: ...

    def nodes(self, ids: Iterable[str]) -> dict[str, SecurityObject]: ...

    def edges(
        self, ids: Sequence[str], direction: Direction = "both", types: Sequence[str] | None = None
    ) -> list[Relationship]: ...

    def find_nodes(
        self, types: Sequence[str] | None = None, tag: str | None = None, metadata_flag: str | None = None
    ) -> list[SecurityObject]: ...


class StoreGraphSource:
    def __init__(self, store: Store, at: datetime | None = None) -> None:
        self.store = store
        self._at = at
        self._node_cache: dict[str, SecurityObject] = {}

    @property
    def at(self) -> datetime | None:
        return self._at

    def nodes(self, ids: Iterable[str]) -> dict[str, SecurityObject]:
        wanted = set(ids)
        missing = [i for i in wanted if i not in self._node_cache]
        if missing:
            self._node_cache.update(self.store.objects.get_many(missing))
        return {i: self._node_cache[i] for i in wanted if i in self._node_cache}

    def edges(
        self, ids: Sequence[str], direction: Direction = "both", types: Sequence[str] | None = None
    ) -> list[Relationship]:
        return self.store.relationships.edges(ids, direction=direction, types=types, at=self._at)

    def find_nodes(
        self, types: Sequence[str] | None = None, tag: str | None = None, metadata_flag: str | None = None
    ) -> list[SecurityObject]:
        result = []
        for obj in self.store.objects.iter_all(types=types):
            if tag is not None and tag not in obj.tags:
                continue
            if metadata_flag is not None and not obj.metadata.get(metadata_flag):
                continue
            result.append(obj)
            self._node_cache[obj.id] = obj
        return result


class MemoryGraphSource:
    def __init__(
        self, objects: Iterable[SecurityObject], relationships: Iterable[Relationship], at: datetime | None = None
    ) -> None:
        self._at = at
        self._nodes: dict[str, SecurityObject] = {o.id: o for o in objects}
        self._edges: dict[str, Relationship] = {}
        self._out: dict[str, list[str]] = defaultdict(list)
        self._in: dict[str, list[str]] = defaultdict(list)
        for rel in relationships:
            if not rel.active_at(at):
                continue
            self._edges[rel.id] = rel
            self._out[rel.source_object].append(rel.id)
            self._in[rel.target_object].append(rel.id)

    @property
    def at(self) -> datetime | None:
        return self._at

    @property
    def all_nodes(self) -> dict[str, SecurityObject]:
        return self._nodes

    @property
    def all_edges(self) -> dict[str, Relationship]:
        return self._edges

    def nodes(self, ids: Iterable[str]) -> dict[str, SecurityObject]:
        return {i: self._nodes[i] for i in ids if i in self._nodes}

    def edges(
        self, ids: Sequence[str], direction: Direction = "both", types: Sequence[str] | None = None
    ) -> list[Relationship]:
        wanted = set(types) if types else None
        found: dict[str, Relationship] = {}
        for node in ids:
            rel_ids: list[str] = []
            if direction in ("out", "both"):
                rel_ids.extend(self._out.get(node, ()))
            if direction in ("in", "both"):
                rel_ids.extend(self._in.get(node, ()))
            for rid in rel_ids:
                rel = self._edges[rid]
                if wanted is None or rel.relationship_type in wanted:
                    found[rid] = rel
        return sorted(found.values(), key=lambda r: (r.source_object, r.relationship_type, r.target_object))

    def find_nodes(
        self, types: Sequence[str] | None = None, tag: str | None = None, metadata_flag: str | None = None
    ) -> list[SecurityObject]:
        wanted = set(types) if types else None
        result = []
        for obj in self._nodes.values():
            if wanted is not None and obj.type not in wanted:
                continue
            if tag is not None and tag not in obj.tags:
                continue
            if metadata_flag is not None and not obj.metadata.get(metadata_flag):
                continue
            result.append(obj)
        return sorted(result, key=lambda o: o.id)


def propagation_source(
    objects: Iterable[SecurityObject], relationships: Iterable[Relationship], at: datetime | None = None
) -> MemoryGraphSource:
    """An in-memory graph restricted to what propagation can use (see
    :data:`~raf.core.objects.semantics.PROPAGATION_RELATIONSHIPS`): same results as the full graph,
    without activity records that only make Blast, Exposure, IAM paths, Ghost and Oracle slower."""

    def keep(rel: Relationship) -> bool:
        return (
            rel.relationship_type in PROPAGATION_RELATIONSHIPS
            and rel.source_object.split(":", 1)[0] not in NON_PROPAGATING_TYPES
            and rel.target_object.split(":", 1)[0] not in NON_PROPAGATING_TYPES
        )

    return MemoryGraphSource(
        (o for o in objects if o.type not in NON_PROPAGATING_TYPES), (r for r in relationships if keep(r)), at
    )


def load_propagation_source(store: Store, at: datetime | None = None) -> MemoryGraphSource:
    """:func:`propagation_source` for the live workspace, filtered in the database."""
    excluded = sorted(NON_PROPAGATING_TYPES)
    return MemoryGraphSource(
        store.objects.iter_all(exclude_types=excluded),
        store.relationships.iter_all(types=sorted(PROPAGATION_RELATIONSHIPS), exclude_endpoint_types=excluded),
        at,
    )
