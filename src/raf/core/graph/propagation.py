"""Compromise propagation over the security graph (defensive exposure model).

Starting from one or more objects assumed compromised, find what an attacker
could control or reach, with the most plausible (highest-confidence) path to
each object. Uses :mod:`raf.core.objects.semantics` for traversal rules.

* confidence of a path = product over hops of ``rule factor * (0.5 + 0.5 *
  relationship confidence)``; paths below ``min_confidence`` are pruned;
* reach-mode states only continue through network structure; a reached object
  affected by an exploitable vulnerability (CVSS >= 7 or exploit available) is
  upgraded to control with reduced confidence - and the hop says why;
* disabled identities are not usable;
* deterministic: ties are broken by depth then object ID.
"""

from __future__ import annotations

import heapq
import itertools
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from raf.core.graph.source import GraphSource
from raf.core.objects.models import Relationship
from raf.core.objects.semantics import (
    CONTROL,
    NON_PROPAGATING_TYPES,
    PROPAGATION_RELATIONSHIPS,
    REACH,
    TRUST,
    Traversal,
    traversals,
)

UPGRADE_FACTOR = 0.6
_TYPES = sorted(PROPAGATION_RELATIONSHIPS)
_EXPOSED_SERVICES = Traversal(REACH, 1.0, "services of {frm} are exposed to whoever can reach it")


@dataclass(frozen=True, slots=True)
class Hop:
    frm: str
    to: str
    relationship: Relationship | None  # None for vulnerability upgrades
    forward: bool
    mode: str
    factor: float
    why: str  # template with {frm}/{to} (names substituted for display)
    vulnerability: str | None = None


@dataclass(slots=True)
class Reached:
    node: str
    mode: str
    confidence: float
    depth: int
    path: tuple[Hop, ...] = field(default_factory=tuple)

    @property
    def via_vulnerability(self) -> str | None:
        for hop in self.path:
            if hop.vulnerability:
                return hop.vulnerability
        return None


def _type(object_id: str) -> str:
    return object_id.split(":", 1)[0]


class Propagator:
    def __init__(
        self,
        source: GraphSource,
        *,
        max_depth: int = 6,
        min_confidence: float = 0.2,
        upgrade_vulnerabilities: bool = True,
    ) -> None:
        self.source = source
        self.max_depth = max_depth
        self.min_confidence = min_confidence
        self.upgrade = upgrade_vulnerabilities
        self._edges: dict[str, list[Relationship]] = {}
        self._vulns: dict[str, tuple[str, float] | None] = {}
        self._disabled: dict[str, bool] = {}

    def _edges_of(self, node: str) -> list[Relationship]:
        cached = self._edges.get(node)
        if cached is None:
            cached = [
                rel
                for rel in self.source.edges([node], "both", types=_TYPES)
                if _type(rel.source_object) not in NON_PROPAGATING_TYPES
                and _type(rel.target_object) not in NON_PROPAGATING_TYPES
            ]
            self._edges[node] = cached
        return cached

    def prefetch(self, nodes: Iterable[str]) -> None:
        missing = [n for n in nodes if n not in self._edges]
        if not missing:
            return
        found: dict[str, list[Relationship]] = {n: [] for n in missing}
        for rel in self.source.edges(missing, "both", types=_TYPES):
            if _type(rel.source_object) in NON_PROPAGATING_TYPES or _type(rel.target_object) in NON_PROPAGATING_TYPES:
                continue
            for endpoint in (rel.source_object, rel.target_object):
                if endpoint in found:
                    found[endpoint].append(rel)
        self._edges.update(found)

    def _exploitable(self, node: str) -> tuple[str, float] | None:
        if node in self._vulns:
            return self._vulns[node]
        best: tuple[str, float] | None = None
        vuln_rels = [r for r in self._edges_of(node) if r.relationship_type == "AFFECTS" and r.target_object == node]
        if vuln_rels:
            vulns = self.source.nodes([r.source_object for r in vuln_rels])
            for vid, vuln in sorted(vulns.items()):
                cvss = float(vuln.metadata.get("cvss") or 0)
                exploit = bool(vuln.metadata.get("exploit_available"))
                if cvss >= 7 or exploit:
                    score = max(cvss, 7.0 if exploit else 0.0)
                    if best is None or score > best[1]:
                        best = (vid, score)
        self._vulns[node] = best
        return best

    def _is_disabled(self, node: str) -> bool:
        if node not in self._disabled:
            obj = self.source.nodes([node]).get(node)
            self._disabled[node] = bool(obj and obj.metadata.get("disabled"))
        return self._disabled[node]

    def run(self, starts: Sequence[str], *, start_mode: str = CONTROL) -> dict[str, Reached]:
        """Best-first search keeping, per (object, mode), the Pareto front of (confidence, depth).

        A state is only discarded when another state reached the same object in the same mode with
        at least the same confidence AND no greater depth; otherwise a shorter-but-weaker path that
        can still extend within ``max_depth`` would be lost.
        """
        fronts: dict[tuple[str, str], list[tuple[float, int]]] = {}
        results: dict[tuple[str, str], Reached] = {}
        counter = itertools.count()
        heap: list[tuple[float, int, str, int, Reached]] = []

        def admit(state: Reached) -> bool:
            key = (state.node, state.mode)
            front = fronts.setdefault(key, [])
            for conf, depth in front:
                if conf >= state.confidence - 1e-12 and depth <= state.depth:
                    return False
            front[:] = [(c, d) for c, d in front if not (state.confidence >= c - 1e-12 and state.depth <= d)]
            front.append((state.confidence, state.depth))
            best = results.get(key)
            if best is None or (state.confidence, -state.depth) > (best.confidence, -best.depth):
                results[key] = state
            heapq.heappush(heap, (-state.confidence, state.depth, state.node, next(counter), state))
            return True

        for start in sorted(set(starts)):
            admit(Reached(node=start, mode=start_mode, confidence=1.0, depth=0))
        while heap:
            _neg, depth, node, _, state = heapq.heappop(heap)
            front = fronts.get((node, state.mode), [])
            if (state.confidence, depth) not in front or depth >= self.max_depth:
                continue
            for cand in self._expand(state):
                admit(cand)
        merged: dict[str, Reached] = {}
        for (node, _mode), reached in sorted(results.items()):
            current = merged.get(node)
            if current is None or _rank(reached) > _rank(current):
                merged[node] = reached
        for start in starts:
            merged.pop(start, None)
        return merged

    def _expand(self, state: Reached) -> list[Reached]:
        node, depth = state.node, state.depth
        candidates: list[Reached] = []
        for rel in self._edges_of(node):
            forward = rel.source_object == node
            nxt = rel.target_object if forward else rel.source_object
            if nxt == node:
                continue
            fwd, rev = traversals(rel.relationship_type, _type(rel.source_object), _type(rel.target_object))
            rule = fwd if forward else rev
            if state.mode == REACH and forward and rel.relationship_type == "RUNS":
                rule = _EXPOSED_SERVICES  # services of a reachable host are reachable (not controlled)
            if rule is None or (state.mode == REACH and rule.mode != REACH):
                continue
            if rule.mode == CONTROL and _type(nxt) in ("identity", "user") and self._is_disabled(nxt):
                continue
            factor = rule.factor * (0.5 + 0.5 * rel.confidence)
            confidence = state.confidence * factor
            if confidence < self.min_confidence:
                continue
            hop = Hop(frm=node, to=nxt, relationship=rel, forward=forward, mode=rule.mode, factor=factor, why=rule.why)
            candidates.append(
                Reached(node=nxt, mode=rule.mode, confidence=confidence, depth=depth + 1, path=(*state.path, hop))
            )
        if state.mode == REACH and self.upgrade:
            vuln = self._exploitable(node)
            if vuln is not None:
                vid, score = vuln
                factor = UPGRADE_FACTOR * min(score, 10.0) / 10.0
                confidence = state.confidence * factor
                if confidence >= self.min_confidence:
                    hop = Hop(
                        frm=node,
                        to=node,
                        relationship=None,
                        forward=True,
                        mode=CONTROL,
                        factor=factor,
                        why="{to} is reachable and affected by an exploitable vulnerability "
                        f"({vid.split(':', 1)[-1]}, score {score})",
                        vulnerability=vid,
                    )
                    candidates.append(
                        Reached(node=node, mode=CONTROL, confidence=confidence, depth=depth, path=(*state.path, hop))
                    )
        return candidates


def _rank(reached: Reached) -> tuple[int, float, int]:
    mode_rank = {CONTROL: 2, TRUST: 2, REACH: 1}.get(reached.mode, 0)
    return (mode_rank, reached.confidence, -reached.depth)


def propagate(
    source: GraphSource,
    starts: Sequence[str],
    *,
    max_depth: int = 6,
    min_confidence: float = 0.2,
    start_mode: str = CONTROL,
) -> dict[str, Reached]:
    return Propagator(source, max_depth=max_depth, min_confidence=min_confidence).run(starts, start_mode=start_mode)
