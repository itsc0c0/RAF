"""Ghost what-if operations.

Every operation is computed against the model's current state and returns explicit *effects*
(relationships removed/added, object metadata patched). Effects are stored with the operation, so
replaying a model is exact and cheap, and every change is explainable. Nothing here touches a
real environment: models are in-memory copies of a snapshot.

Operations
----------
``remove-access A:B``        cut every control path from A to B with a minimum-cost set of
                             relationship removals (max-flow / min-cut; credential exposure is the
                             cheapest thing to remove, structural facts the most expensive)
``remove-relationship R``    remove one relationship (ID or "SOURCE TYPE TARGET")
``add-segmentation S:D``     block network reachability from zone S to zone D
``disable-identity X``       mark a user/identity disabled (cannot be taken over)
``change-role P:OLD:NEW``    replace a directly held role; ``add-role P:R`` / ``remove-role P:R``
``remove-exposure X``        no direct Internet exposure for a host/service (moved to an internal
                             segment of its zone that keeps all other connectivity)
``patch-vuln V[:ASSET]``     the vulnerability no longer affects the asset(s)
``isolate X``                remove every network relationship of a host
``disable-rule P:RULE``      disable a firewall rule in the policy model; reachability derived
                             from that rule is removed
``deny-flow S:D[:PORTS]``    insert a deny rule at the top of the network policy model and remove
                             (or trim) the matching zone reachability
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from raf.core.errors import AmbiguousReferenceError, InvalidInputError, NotFoundError
from raf.core.graph.propagation import Propagator
from raf.core.ids import object_id
from raf.core.objects.models import Relationship
from raf.core.objects.semantics import CONTROL, TRUST, explain, traversals
from raf.core.ports import remaining_ports
from raf.core.timeutil import utcnow
from raf.products.ghost.state import AddedObject, AddedRelationship, ModelState, OpEffects

#: cost of cutting a relationship in ``remove-access`` (lower = preferred)
CUT_COST = {
    "USES": 1,
    "CONTAINS_SECRET": 1,
    "AUTHENTICATES_AS": 1,
    "LOGGED_INTO": 1,
    "CAN_ACCESS": 3,
    "ADMIN_OF": 3,
    "HAS_ROLE": 3,
    "CAN_ASSUME": 3,
    "HAS_IDENTITY": 3,
    "HAS_PERMISSION": 3,
    "OWNS": 3,
    "TRUSTS": 3,
    "MEMBER_OF": 4,
}
STRUCTURAL_COST = 50
_COST_LABEL = {1: "credential exposure", 3: "access grant", 4: "membership"}
NETWORK_RELS = ("CAN_REACH", "CONNECTED_TO", "MEMBER_OF", "HAS_ADDRESS")


@dataclass
class OpResult:
    effects: OpEffects
    summary: str
    explanation: list[str] = field(default_factory=list)


OpFunction = Callable[[ModelState, str, str], OpResult]


def _external_zones(state: ModelState) -> list[str]:
    zones = []
    for obj in state.objects.values():
        if obj.type != "network":
            continue
        cidr = str(obj.metadata.get("cidr") or "")
        zone = str(obj.metadata.get("zone") or "").lower()
        if obj.id == "network:internet" or cidr in ("0.0.0.0/0", "::/0") or zone in ("external", "internet"):
            zones.append(obj.id)
    return sorted(zones)


def _describe(state: ModelState, rel: Relationship) -> str:
    return f"{state.name(rel.source_object)} {rel.relationship_type} {state.name(rel.target_object)}"


# --------------------------------------------------------------------------- remove-access (min cut)


@dataclass
class _Arc:
    u: str
    v: str
    cap: int
    rel: str
    forward: bool
    why: str


def _control_arcs(state: ModelState, nodes: set[str]) -> list[_Arc]:
    arcs: list[_Arc] = []
    for rel in state.active():
        a, b = rel.source_object, rel.target_object
        if a not in nodes or b not in nodes or a == b:
            continue
        fwd, rev = traversals(rel.relationship_type, a.split(":", 1)[0], b.split(":", 1)[0])
        cost = CUT_COST.get(rel.relationship_type, STRUCTURAL_COST)
        if fwd is not None and fwd.mode in (CONTROL, TRUST):
            arcs.append(_Arc(a, b, cost, rel.id, True, fwd.why))
        if rev is not None and rev.mode in (CONTROL, TRUST):
            arcs.append(_Arc(b, a, cost, rel.id, False, rev.why))
    return sorted(arcs, key=lambda x: (x.rel, x.forward))


def min_cut(arcs: list[_Arc], source: str, sink: str) -> list[_Arc]:
    """Edmonds-Karp max flow; returns the saturated arcs crossing the minimum cut."""
    graph: dict[str, list[list[Any]]] = {}  # node -> [to, residual capacity, reverse index, arc index]

    def add(u: str, v: str, cap: int, index: int) -> None:
        graph.setdefault(u, [])
        graph.setdefault(v, [])
        graph[u].append([v, cap, len(graph[v]), index])
        graph[v].append([u, 0, len(graph[u]) - 1, -1])

    for i, arc in enumerate(arcs):
        add(arc.u, arc.v, arc.cap, i)
    if source not in graph or sink not in graph:
        return []
    while True:
        parent: dict[str, tuple[str, int]] = {}
        queue = deque([source])
        seen = {source}
        while queue and sink not in seen:
            node = queue.popleft()
            for idx, (nxt, cap, _rev, _arc) in enumerate(graph[node]):
                if cap > 0 and nxt not in seen:
                    seen.add(nxt)
                    parent[nxt] = (node, idx)
                    queue.append(nxt)
        if sink not in seen:
            break
        bottleneck = None
        node = sink
        while node != source:
            prev, idx = parent[node]
            cap = graph[prev][idx][1]
            bottleneck = cap if bottleneck is None else min(bottleneck, cap)
            node = prev
        assert bottleneck is not None
        node = sink
        while node != source:
            prev, idx = parent[node]
            edge = graph[prev][idx]
            edge[1] -= bottleneck
            graph[node][edge[2]][1] += bottleneck
            node = prev
    reachable = {source}
    queue = deque([source])
    while queue:
        node = queue.popleft()
        for nxt, cap, _rev, _arc in graph[node]:
            if cap > 0 and nxt not in reachable:
                reachable.add(nxt)
                queue.append(nxt)
    return [arc for arc in arcs if arc.u in reachable and arc.v not in reachable]


def _controls(state: ModelState, source: str, target: str) -> bool:
    reached = Propagator(state.graph(), max_depth=12, min_confidence=0.0, upgrade_vulnerabilities=False).run([source])
    found = reached.get(target)
    return found is not None and found.mode in (CONTROL, TRUST)


def op_remove_access(state: ModelState, arg: str, model: str) -> OpResult:
    source, target = state.resolve_pair(arg)
    if not _controls(state, source, target):
        raise InvalidInputError(
            f"{state.name(source)} has no control path to {state.name(target)} in this model.",
            hint=f"Check with: raf iam path {source} {target}",
        )
    removed: list[str] = []
    explanation: list[str] = []
    working = ModelState(state.label, state.objects.values(), state.relationships.values())
    for _round in range(6):
        reached = Propagator(working.graph(), max_depth=12, min_confidence=0.0, upgrade_vulnerabilities=False).run(
            [source]
        )
        if target not in reached or reached[target].mode not in (CONTROL, TRUST):
            break
        nodes = set(reached) | {source}
        cut = min_cut(_control_arcs(working, nodes), source, target)
        if not cut:
            break
        rel_ids = sorted({arc.rel for arc in cut})
        for arc in sorted(cut, key=lambda a: a.rel):
            rel = working.relationships.get(arc.rel)
            if rel is None or arc.rel in removed:
                continue
            kind = _COST_LABEL.get(arc.cap, "structural relationship")
            reason = explain(arc.why, working.name(arc.u), working.name(arc.v), rel.metadata)
            explanation.append(f"remove {_describe(working, rel)} ({kind}): {reason}")
        removed.extend(r for r in rel_ids if r not in removed)
        working.apply(OpEffects(removed_relationships=rel_ids), model=model, when=utcnow())
    if _controls(working, source, target):
        raise InvalidInputError(f"Could not cut every path from {state.name(source)} to {state.name(target)}.")
    summary = f"cut {len(removed)} relationship(s) so that {state.name(source)} no longer controls {state.name(target)}"
    return OpResult(OpEffects(removed_relationships=removed), summary, explanation)


# --------------------------------------------------------------------------- simple relationship / identity ops


def op_remove_relationship(state: ModelState, arg: str, model: str) -> OpResult:
    text = arg.strip()
    if text.startswith("rel:"):
        rel = state.relationships.get(text)
        if rel is None or rel.valid_to is not None:
            raise InvalidInputError(f"Relationship {text} is not an active relationship in this model.")
        found = [rel]
    else:
        parts = text.split()
        if len(parts) != 3:
            raise InvalidInputError("Use a relationship ID (rel:...) or 'SOURCE TYPE TARGET'.")
        src, rtype, dst = state.resolve(parts[0]), parts[1].upper(), state.resolve(parts[2])
        found = state.rels(source=src, target=dst, types=[rtype])
        if not found:
            raise InvalidInputError(f"No {rtype} relationship from {state.name(src)} to {state.name(dst)}.")
    return OpResult(
        OpEffects(removed_relationships=[r.id for r in found]),
        f"removed {', '.join(_describe(state, r) for r in found)}",
    )


def op_disable_identity(state: ModelState, arg: str, model: str) -> OpResult:
    oid = state.resolve(arg, ["user", "identity"])
    if state.objects[oid].metadata.get("disabled") is True:
        raise InvalidInputError(f"{state.name(oid)} is already disabled in this model.")
    return OpResult(
        OpEffects(patched_objects={oid: {"disabled": True}}),
        f"disabled {state.name(oid)}",
        [f"{state.name(oid)} can no longer be taken over or used along any path"],
    )


def _split_refs(state: ModelState, arg: str, kinds: list[list[str]]) -> list[str]:
    """Split ``A:B[:C]`` into resolvable references; parts may be typed IDs that contain ':'."""
    from itertools import combinations

    positions = [i for i, ch in enumerate(arg) if ch == ":"]
    found: set[tuple[str, ...]] = set()
    for cut in combinations(positions, len(kinds) - 1):
        bounds = [-1, *cut, len(arg)]
        parts = [arg[bounds[i] + 1 : bounds[i + 1]] for i in range(len(kinds))]
        try:
            found.add(tuple(state.resolve(part, kind) for part, kind in zip(parts, kinds, strict=True)))
        except (InvalidInputError, NotFoundError, AmbiguousReferenceError):
            continue
    if len(found) == 1:
        return list(next(iter(found)))
    shape = ":".join(["PRINCIPAL", "OLD_ROLE", "NEW_ROLE"][: len(kinds)]) if len(kinds) == 3 else "PRINCIPAL:ROLE"
    if not found:
        raise InvalidInputError(f"Could not resolve '{arg}' as {shape} in this model.")
    raise AmbiguousReferenceError(arg, [" / ".join(f) for f in sorted(found)])


_PRINCIPALS = ["user", "identity", "group"]


def op_remove_role(state: ModelState, arg: str, model: str) -> OpResult:
    principal, role = _split_refs(state, arg, [_PRINCIPALS, ["role"]])
    found = state.rels(source=principal, target=role, types=["HAS_ROLE"])
    if not found:
        raise InvalidInputError(
            f"{state.name(principal)} does not hold {state.name(role)} directly.",
            hint=f"Roles inherited through groups are removed from the group: remove-role <group>:{state.name(role)}",
        )
    return OpResult(
        OpEffects(removed_relationships=[r.id for r in found]),
        f"{state.name(principal)} no longer holds {state.name(role)}",
    )


def op_add_role(state: ModelState, arg: str, model: str) -> OpResult:
    principal, role = _split_refs(state, arg, [_PRINCIPALS, ["role"]])
    if state.rels(source=principal, target=role, types=["HAS_ROLE"]):
        raise InvalidInputError(f"{state.name(principal)} already holds {state.name(role)}.")
    return OpResult(
        OpEffects(added_relationships=[AddedRelationship(source=principal, type="HAS_ROLE", target=role)]),
        f"{state.name(principal)} now holds {state.name(role)}",
    )


def op_change_role(state: ModelState, arg: str, model: str) -> OpResult:
    principal, old_role, new_role = _split_refs(state, arg, [_PRINCIPALS, ["role"], ["role"]])
    removed = op_remove_role(state, f"{principal}:{old_role}", model)
    effects = removed.effects.model_copy(deep=True)
    if not state.rels(source=principal, target=new_role, types=["HAS_ROLE"]):
        effects.added_relationships.append(AddedRelationship(source=principal, type="HAS_ROLE", target=new_role))
    return OpResult(effects, f"{state.name(principal)}: role {state.name(old_role)} → {state.name(new_role)}")


# --------------------------------------------------------------------------- network ops


def op_add_segmentation(state: ModelState, arg: str, model: str) -> OpResult:
    src, dst = state.resolve_pair(arg, ["network"], ["network"])
    found = state.rels(source=src, target=dst, types=["CAN_REACH"])
    if not found:
        raise InvalidInputError(f"{state.name(src)} has no reachability to {state.name(dst)} to segment.")
    effects = OpEffects(removed_relationships=[r.id for r in found])
    notes = [
        f"removed {_describe(state, r)} (ports: {', '.join(map(str, r.metadata.get('ports') or ['any']))})"
        for r in found
    ]
    patch = _policy_insert_deny(state, src, dst, ["any"], "Ghost segmentation")
    if patch is not None:
        effects.patched_objects.update(patch[0])
        notes.append(patch[1])
    return OpResult(effects, f"segmented {state.name(src)} from {state.name(dst)}", notes)


def op_isolate(state: ModelState, arg: str, model: str) -> OpResult:
    host = state.resolve(arg, ["host"])
    found = [
        r
        for r in state.touching(host, NETWORK_RELS)
        if r.relationship_type != "MEMBER_OF" or r.target_object.startswith("network:")
    ]
    found = [r for r in found if r.relationship_type != "HAS_ADDRESS"]
    if not found:
        raise InvalidInputError(f"{state.name(host)} has no network relationships; it is already isolated.")
    return OpResult(
        OpEffects(
            removed_relationships=[r.id for r in found],
            patched_objects={host: {"isolated": True, "internet_facing": False}},
        ),
        f"isolated {state.name(host)} ({len(found)} network relationship(s) removed)",
        [f"removed {_describe(state, r)}" for r in found],
    )


def op_remove_exposure(state: ModelState, arg: str, model: str) -> OpResult:
    asset = state.resolve(arg, ["host", "service"])
    externals = set(_external_zones(state))
    host = asset
    if asset.startswith("service:"):
        runs = state.rels(target=asset, types=["RUNS"])
        host = runs[0].source_object if runs else asset
    services = [r.target_object for r in state.rels(source=host, types=["RUNS"])]
    targets = {asset, host, *services}
    effects = OpEffects()
    notes: list[str] = []
    for rel in state.rels(types=["CAN_REACH"]):
        if rel.source_object in externals and rel.target_object in targets:
            effects.removed_relationships.append(rel.id)
            notes.append(f"removed {_describe(state, rel)}")
    for oid in sorted(targets):
        if oid in state.objects and state.objects[oid].metadata.get("internet_facing"):
            effects.patched_objects[oid] = {"internet_facing": False}
    # zone-level exposure: move the host into an internal segment of its zone
    for membership in state.rels(source=host, types=["MEMBER_OF"]):
        zone = membership.target_object
        inbound_external = [r for r in state.rels(target=zone, types=["CAN_REACH"]) if r.source_object in externals]
        if not zone.startswith("network:") or not inbound_external:
            continue
        segment = object_id("network", f"{state.name(zone)}-internal")
        if segment not in state.objects:
            effects.added_objects.append(
                AddedObject(
                    id=segment,
                    type="network",
                    name=f"{state.name(zone)}-internal",
                    metadata={
                        "zone": "internal-segment",
                        "segment_of": zone,
                        "description": f"Ghost: {state.name(zone)} without Internet exposure",
                    },
                )
            )
            for rel in state.rels(source=zone, types=["CAN_REACH"]):
                effects.added_relationships.append(
                    AddedRelationship(
                        source=segment, type="CAN_REACH", target=rel.target_object, metadata=dict(rel.metadata)
                    )
                )
            for rel in state.rels(target=zone, types=["CAN_REACH"]):
                if rel.source_object not in externals:
                    effects.added_relationships.append(
                        AddedRelationship(
                            source=rel.source_object, type="CAN_REACH", target=segment, metadata=dict(rel.metadata)
                        )
                    )
        effects.removed_relationships.append(membership.id)
        effects.added_relationships.append(AddedRelationship(source=host, type="MEMBER_OF", target=segment))
        notes.append(
            f"moved {state.name(host)} from {state.name(zone)} to {state.name(zone)}-internal, which keeps "
            f"{state.name(zone)}'s other reachability but accepts no traffic from external zones"
        )
    if effects.is_empty():
        raise InvalidInputError(f"{state.name(asset)} is not exposed to an external zone in this model.")
    effects.removed_relationships = sorted(set(effects.removed_relationships))
    return OpResult(effects, f"removed Internet exposure of {state.name(asset)}", notes)


def op_patch_vuln(state: ModelState, arg: str, model: str) -> OpResult:
    if ":" in arg and not arg.lower().startswith("vulnerability:"):
        vuln_ref, asset_ref = arg.split(":", 1)
    elif arg.lower().startswith("vulnerability:") and arg.count(":") >= 2:
        head, _, rest = arg.partition(":")
        vuln_ref, _, asset_ref = rest.partition(":")
        vuln_ref = f"{head}:{vuln_ref}"
    else:
        vuln_ref, asset_ref = arg, ""
    vuln = state.resolve(vuln_ref, ["vulnerability"])
    found = state.rels(source=vuln, types=["AFFECTS"])
    if asset_ref:
        asset = state.resolve(asset_ref)
        found = [r for r in found if r.target_object == asset]
    if not found:
        raise InvalidInputError(f"{state.name(vuln)} affects nothing{' there' if asset_ref else ''} in this model.")
    effects = OpEffects(removed_relationships=[r.id for r in found])
    if not asset_ref:
        effects.patched_objects[vuln] = {"status": "patched", "patched_by": f"ghost:{model}"}
    return OpResult(effects, f"patched {state.name(vuln)} on " + ", ".join(state.name(r.target_object) for r in found))


# --------------------------------------------------------------------------- policy model ops


def _network_policy(state: ModelState) -> tuple[str, dict[str, Any]] | None:
    for obj in sorted(state.objects.values(), key=lambda o: o.id):
        policy = obj.metadata.get("policy")
        if obj.type == "policy" and isinstance(policy, dict) and policy.get("domain") == "network":
            return obj.id, policy
    return None


def _renumber(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{**rule, "order": index} for index, rule in enumerate(rules)]


def _policy_insert_deny(
    state: ModelState, src: str, dst: str, ports: list[str], description: str
) -> tuple[dict[str, dict[str, Any]], str] | None:
    found = _network_policy(state)
    if found is None:
        return None
    oid, policy = found
    rules = list(policy.get("rules") or [])
    existing = {str(r.get("id")) for r in rules}
    index = 1
    while f"ghost-deny-{index}" in existing:
        index += 1
    rule = {
        "id": f"ghost-deny-{index}",
        "policy": policy.get("id"),
        "order": 0,
        "effect": "deny",
        "sources": [src],
        "destinations": [dst],
        "ports": ports,
        "actions": ["*"],
        "description": description,
        "enabled": True,
        "metadata": {"ghost": True},
    }
    new_policy = {**policy, "rules": _renumber([rule, *rules])}
    return {oid: {"policy": new_policy}}, f"inserted deny rule ghost-deny-{index} at the top of {state.name(oid)}"


def op_disable_rule(state: ModelState, arg: str, model: str) -> OpResult:
    if ":" not in arg:
        raise InvalidInputError("Use POLICY:RULE, e.g. raven-fw:r40-dev-to-prod.")
    policy_ref, rule_id = arg.rsplit(":", 1)
    oid = state.resolve(policy_ref, ["policy"])
    policy = state.objects[oid].metadata.get("policy")
    if not isinstance(policy, dict):
        raise InvalidInputError(f"{state.name(oid)} has no rule model in this state.")
    rules = list(policy.get("rules") or [])
    target = next((r for r in rules if str(r.get("id")) == rule_id), None)
    if target is None:
        raise InvalidInputError(f"Rule '{rule_id}' is not in {state.name(oid)}.")
    if target.get("enabled") is False:
        raise InvalidInputError(f"Rule '{rule_id}' is already disabled.")
    new_rules = [{**r, "enabled": False} if str(r.get("id")) == rule_id else r for r in rules]
    ref = f"{policy.get('id')}:{rule_id}"
    derived = [r for r in state.rels(types=["CAN_REACH"]) if r.metadata.get("policy") == ref]
    notes = [f"disabled {ref}"] + [f"removed {_describe(state, r)} (reachability derived from {ref})" for r in derived]
    return OpResult(
        OpEffects(
            removed_relationships=[r.id for r in derived],
            patched_objects={oid: {"policy": {**policy, "rules": new_rules}}},
        ),
        f"disabled rule {rule_id} in {state.name(oid)}",
        notes,
    )


def op_deny_flow(state: ModelState, arg: str, model: str) -> OpResult:
    parts = arg.split(":")
    ports = ["any"]
    if len(parts) >= 3:
        ports = [p.strip() for p in parts[-1].split(",") if p.strip()] or ["any"]
        arg = ":".join(parts[:-1])
    src, dst = state.resolve_pair(arg)
    effects = OpEffects()
    notes: list[str] = []
    patch = _policy_insert_deny(state, src, dst, ports, "Ghost deny flow")
    if patch is not None:
        effects.patched_objects.update(patch[0])
        notes.append(patch[1])
    for rel in state.rels(source=src, target=dst, types=["CAN_REACH"]):
        left = remaining_ports(list(map(str, rel.metadata.get("ports") or ["any"])), ports)
        effects.removed_relationships.append(rel.id)
        if left:
            effects.added_relationships.append(
                AddedRelationship(source=src, type="CAN_REACH", target=dst, metadata={**rel.metadata, "ports": left})
            )
            notes.append(f"trimmed {_describe(state, rel)} to ports {', '.join(left)}")
        else:
            notes.append(f"removed {_describe(state, rel)}")
    if effects.is_empty():
        raise InvalidInputError(
            f"Nothing to deny: no network policy model and no reachability from {state.name(src)} to {state.name(dst)}."
        )
    return OpResult(effects, f"denied {state.name(src)} → {state.name(dst)} ({', '.join(ports)})", notes)


OPERATIONS: dict[str, tuple[OpFunction, str, str]] = {
    "remove-access": (op_remove_access, "A:B", "cut every control path from A to B (minimum-cost cut)"),
    "remove-relationship": (op_remove_relationship, "REL_ID | 'SRC TYPE DST'", "remove one relationship"),
    "add-segmentation": (op_add_segmentation, "SRC_ZONE:DST_ZONE", "block reachability between zones"),
    "disable-identity": (op_disable_identity, "USER|IDENTITY", "disable an account"),
    "change-role": (op_change_role, "PRINCIPAL:OLD:NEW", "replace a directly held role"),
    "add-role": (op_add_role, "PRINCIPAL:ROLE", "grant a role"),
    "remove-role": (op_remove_role, "PRINCIPAL:ROLE", "revoke a directly held role"),
    "remove-exposure": (op_remove_exposure, "HOST|SERVICE", "remove direct Internet exposure"),
    "patch-vuln": (op_patch_vuln, "VULN[:ASSET]", "the vulnerability no longer applies"),
    "isolate": (op_isolate, "HOST", "remove every network relationship of a host"),
    "disable-rule": (op_disable_rule, "POLICY:RULE", "disable a firewall rule in the policy model"),
    "deny-flow": (op_deny_flow, "SRC:DST[:PORTS]", "insert a deny rule and remove/trim the reachability"),
}


def run_operation(state: ModelState, op: str, arg: str, model: str) -> OpResult:
    if op not in OPERATIONS:
        raise InvalidInputError(f"Unknown Ghost operation '{op}'.", details={"operations": sorted(OPERATIONS)})
    if not arg or len(arg) > 500:
        raise InvalidInputError(f"Operation {op} needs an argument ({OPERATIONS[op][1]}).")
    return OPERATIONS[op][0](state, arg, model)


__all__ = ["OPERATIONS", "OpResult", "min_cut", "run_operation"]
