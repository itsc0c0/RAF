"""Policy semantics: selector resolution, flow evaluation, rule-set analysis and revision diffs.

Address selectors are interpreted against workspace facts (:class:`PolicyWorld`) with **zone
semantics**: ``network:internet`` (0.0.0.0/0) means "addresses not inside a more specific known
network", so an INTERNET rule never silently covers CORP. Hosts belong to the zones they are
``MEMBER_OF`` (or, without explicit membership, the most specific network containing their IPs).

Network policies use first-match over port *sets*: each matching rule decides the still-undecided
part of the requested port space, so one evaluation explains every port at once. Identity policies
use deny-overrides (explicit deny > allow > default).

Rule anomalies follow the classic firewall taxonomy (Al-Shaer & Hamed): **shadowing** (a later rule
fully covered by an earlier rule with the opposite effect - it can never apply), **redundancy**
(covered by an earlier rule with the same effect), **correlation** (partial overlap with opposite
effects - order-dependent). *Generalization* (a broad rule after a specific exception) is the normal
exception pattern and is not reported.
"""

from __future__ import annotations

import fnmatch
import ipaddress
from collections import defaultdict, deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from pydantic import Field

from raf.core.ids import finding_id
from raf.core.objects.models import EvidenceRef, Finding, RafModel, Relationship, SecurityObject
from raf.core.objects.types import Criticality, Severity
from raf.core.ports import ANY, PortSet
from raf.core.timeutil import utcnow
from raf.products.policy.model import Policy, PolicyRule, PolicySet, action_covers, action_matches

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

PRODUCT = "policy"
RULES = (
    "overly-broad-rule",
    "shadowed-rule",
    "redundant-rule",
    "conflicting-rules",
    "stale-reference",
    "default-allow",
)
WORLD_OBJECT_TYPES = [
    "network",
    "host",
    "ip",
    "service",
    "user",
    "identity",
    "group",
    "role",
    "cloud_resource",
    "container",
    "project",
]
WORLD_REL_TYPES = [
    "MEMBER_OF",
    "HAS_ADDRESS",
    "CONTAINS",
    "RUNS",
    "HAS_ROLE",
    "HAS_IDENTITY",
    "OWNS",
    "LOGGED_INTO",
    "USES",
]
_CRIT_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _networks(value: Any) -> list[IPNetwork]:
    out: list[IPNetwork] = []
    for item in value if isinstance(value, list) else [value]:
        try:
            out.append(ipaddress.ip_network(str(item), strict=False))
        except ValueError:
            continue
    return out


def _addresses(value: Any) -> list[IPAddress]:
    out: list[IPAddress] = []
    for item in value if isinstance(value, list) else [value]:
        try:
            out.append(ipaddress.ip_address(str(item)))
        except ValueError:
            continue
    return out


def _within(inner: IPNetwork, outer: IPNetwork) -> bool:
    return inner.version == outer.version and inner.subnet_of(outer)  # type: ignore[arg-type]


def _overlap(a: IPNetwork, b: IPNetwork) -> bool:
    return a.version == b.version and a.overlaps(b)


# --------------------------------------------------------------------------- workspace facts


class PolicyWorld:
    """Workspace facts used to interpret selectors (networks, addresses, memberships, containment)."""

    def __init__(self, objects: Iterable[SecurityObject], relationships: Iterable[Relationship]) -> None:
        self.objects: dict[str, SecurityObject] = {o.id: o for o in objects}
        self.zone_nets: dict[str, list[IPNetwork]] = {}
        for obj in self.objects.values():
            if obj.type == "network":
                nets = _networks(obj.metadata.get("cidr") or obj.metadata.get("cidrs") or [])
                if nets:
                    self.zone_nets[obj.id] = nets
        self.addresses: dict[str, list[IPAddress]] = defaultdict(list)
        for obj in self.objects.values():
            if obj.type == "host":
                for key in ("ip", "public_ip", "addresses", "ips"):
                    if obj.metadata.get(key):
                        self.addresses[obj.id].extend(_addresses(obj.metadata[key]))
            elif obj.type == "ip":
                self.addresses[obj.id].extend(_addresses(obj.id.split(":", 1)[1]))
        self.zones_of: dict[str, set[str]] = defaultdict(set)
        self.zone_members: dict[str, set[str]] = defaultdict(set)
        self.parents: dict[str, set[str]] = defaultdict(set)
        self.service_host: dict[str, str] = {}
        self.groups_of: dict[str, set[str]] = defaultdict(set)
        self.roles_of: dict[str, set[str]] = defaultdict(set)
        self.identities_of: dict[str, set[str]] = defaultdict(set)
        self.owned_hosts: dict[str, list[str]] = defaultdict(list)
        self.session_hosts: dict[str, list[str]] = defaultdict(list)
        self.identity_hosts: dict[str, list[str]] = defaultdict(list)
        for rel in relationships:
            if not rel.active_at(None):
                continue
            src, dst, kind = rel.source_object, rel.target_object, rel.relationship_type
            if kind == "MEMBER_OF" and dst.startswith("network:"):
                self.zones_of[src].add(dst)
                self.zone_members[dst].add(src)
            elif kind == "MEMBER_OF" and dst.startswith("group:"):
                self.groups_of[src].add(dst)
            elif kind == "HAS_ADDRESS" and dst.startswith("ip:"):
                self.addresses[src].extend(_addresses(dst.split(":", 1)[1]))
            elif kind == "CONTAINS":
                self.parents[dst].add(src)
            elif kind == "RUNS":
                self.parents[dst].add(src)
                if src.startswith("host:"):
                    self.service_host.setdefault(dst, src)
            elif kind == "HAS_ROLE":
                self.roles_of[src].add(dst)
            elif kind == "HAS_IDENTITY":
                self.identities_of[src].add(dst)
            elif kind == "OWNS" and dst.startswith("host:"):
                self.owned_hosts[src].append(dst)
            elif kind == "LOGGED_INTO" and dst.startswith("host:"):
                self.session_hosts[src].append(dst)
            elif kind == "USES" and src.startswith("host:"):
                self.identity_hosts[dst].append(src)
        for oid in list(self.addresses):
            self.addresses[oid] = list(dict.fromkeys(self.addresses[oid]))
        # hosts without explicit zone membership belong to the most specific network containing an address
        for oid, addrs in self.addresses.items():
            if self.zones_of.get(oid):
                continue
            for addr in addrs:
                zone = self.zone_for_address(addr)
                if zone:
                    self.zones_of[oid].add(zone)
                    self.zone_members[zone].add(oid)

    @classmethod
    def from_store(cls, store: Any) -> PolicyWorld:
        objects = list(store.objects.iter_all(types=WORLD_OBJECT_TYPES))
        relationships = list(store.relationships.iter_all(types=WORLD_REL_TYPES))
        return cls(objects, relationships)

    @classmethod
    def empty(cls) -> PolicyWorld:
        return cls([], [])

    @property
    def is_empty(self) -> bool:
        return not self.objects

    def name(self, ref: str) -> str:
        obj = self.objects.get(ref)
        if obj is not None:
            return obj.name
        return ref.split(":", 1)[-1] if ":" in ref else ref

    def zone_for_address(self, addr: IPAddress) -> str | None:
        best: tuple[int, str] | None = None
        for zone, nets in self.zone_nets.items():
            for net in nets:
                if net.version == addr.version and addr in net and (best is None or net.prefixlen > best[0]):
                    best = (net.prefixlen, zone)
        return best[1] if best else None

    def zone_exclusions(self, zone: str) -> list[IPNetwork]:
        """Known networks strictly inside ``zone`` (zone semantics: they are not part of it)."""
        own = self.zone_nets.get(zone, [])
        out = []
        for other, nets in self.zone_nets.items():
            if other == zone:
                continue
            for net in nets:
                if any(_within(net, mine) and net != mine for mine in own):
                    out.append(net)
        return out

    def criticality(self, ref: str) -> str | None:
        obj = self.objects.get(ref)
        if obj is None:
            return None
        level = Criticality.of(obj.metadata, obj.tags)
        return level.value if level else None

    def zone_criticality(self, zone: str) -> str | None:
        levels = [self.criticality(zone)] + [self.criticality(m) for m in self.zone_members.get(zone, ())]
        known = [lv for lv in levels if lv]
        return max(known, key=lambda lv: _CRIT_RANK[lv]) if known else None

    def principal_closure(self, principal: str) -> set[str]:
        """The principal, its groups (transitively) and the roles held by any of them."""
        closure = {principal}
        queue = deque([principal])
        while queue:
            node = queue.popleft()
            for group in self.groups_of.get(node, ()):
                if group not in closure:
                    closure.add(group)
                    queue.append(group)
        for holder in list(closure):
            closure |= self.roles_of.get(holder, set())
        return closure

    def ancestors(self, resource: str) -> set[str]:
        """The resource plus everything that contains or runs it (transitively)."""
        seen = {resource}
        queue = deque([resource])
        while queue:
            node = queue.popleft()
            for parent in self.parents.get(node, ()):
                if parent not in seen:
                    seen.add(parent)
                    queue.append(parent)
        return seen

    def source_hosts(self, subject: str) -> list[str]:
        if subject.startswith("user:"):
            hosts = self.owned_hosts.get(subject, []) + self.session_hosts.get(subject, [])
        elif subject.startswith("identity:"):
            hosts = self.identity_hosts.get(subject, []) + self.session_hosts.get(subject, [])
        else:
            hosts = []
        return list(dict.fromkeys(hosts))


# --------------------------------------------------------------------------- address sets


@dataclass(frozen=True, slots=True)
class AddrElement:
    kind: str  # zone | object | cidr
    id: str
    nets: tuple[IPNetwork, ...] = ()
    zones: frozenset[str] = frozenset()
    exclude: tuple[IPNetwork, ...] = ()
    resolved: bool = True


@dataclass(frozen=True, slots=True)
class AddressSet:
    any: bool = False
    elements: tuple[AddrElement, ...] = ()

    @property
    def unresolved(self) -> list[str]:
        return [e.id for e in self.elements if not e.resolved]


def element_for(world: PolicyWorld, selector: str) -> AddrElement:
    if selector.startswith("cidr:"):
        return AddrElement("cidr", selector, tuple(_networks(selector[5:])))
    if selector.startswith("network:"):
        known = selector in world.objects or selector in world.zone_nets
        return AddrElement(
            "zone",
            selector,
            tuple(world.zone_nets.get(selector, ())),
            frozenset({selector}),
            tuple(world.zone_exclusions(selector)),
            known,
        )
    target = selector
    if selector.startswith("service:") and selector in world.service_host:
        target = world.service_host[selector]
    nets = tuple(ipaddress.ip_network(a) for a in world.addresses.get(target, ()))
    zones = frozenset(world.zones_of.get(target, set()))
    known = selector in world.objects or bool(nets)
    if selector.startswith("ip:") and not nets:
        nets = tuple(_networks(selector.split(":", 1)[1]))
        known = known or bool(nets)
    return AddrElement("object", selector, nets, zones, (), known)


def address_set(world: PolicyWorld, selectors: Iterable[str]) -> AddressSet:
    items = list(selectors)
    if any(s == ANY for s in items):
        return AddressSet(any=True)
    return AddressSet(False, tuple(element_for(world, s) for s in items))


def _nets_in(element_nets: tuple[IPNetwork, ...], outer: AddrElement) -> bool:
    if not element_nets or not outer.nets:
        return False
    for net in element_nets:
        if not any(_within(net, o) for o in outer.nets):
            return False
        if any(_overlap(net, ex) for ex in outer.exclude):
            return False
    return True


def element_covers(a: AddrElement, e: AddrElement) -> bool:
    """True when selector element ``a`` includes everything element ``e`` stands for."""
    if a.id == e.id:
        return True
    if a.kind == "zone":
        if e.kind == "object" and e.zones:
            return a.id in e.zones
        return _nets_in(e.nets, a)
    if a.kind == "cidr":
        return _nets_in(e.nets, a)
    # an object covers another element only when they denote the same addresses
    return e.kind != "zone" and bool(e.nets) and _nets_in(e.nets, a)


def element_overlaps(a: AddrElement, b: AddrElement) -> bool:
    if a.id == b.id:
        return True
    if a.kind == "zone" and b.kind == "object" and b.zones:
        return a.id in b.zones
    if b.kind == "zone" and a.kind == "object" and a.zones:
        return b.id in a.zones
    for x in a.nets:
        for y in b.nets:
            if not _overlap(x, y):
                continue
            if any(_within(y, ex) for ex in a.exclude) or any(_within(x, ex) for ex in b.exclude):
                continue
            return True
    return False


def set_covers(a: AddressSet, b: AddressSet) -> bool:
    if a.any:
        return True
    if b.any or not b.elements:
        return False
    return all(any(element_covers(x, e) for x in a.elements) for e in b.elements)


def set_overlaps(a: AddressSet, b: AddressSet) -> bool:
    if a.any or b.any:
        return True
    return any(element_overlaps(x, y) for x in a.elements for y in b.elements)


def set_contains(selector_set: AddressSet, endpoint: AddrElement) -> bool:
    return selector_set.any or any(element_covers(x, endpoint) for x in selector_set.elements)


# --------------------------------------------------------------------------- identity selectors


def principal_covers(a: str, b: str, world: PolicyWorld) -> bool:
    if a == "*" or a == b:
        return True
    if b == "*":
        return False
    return a in world.principal_closure(b)


def resource_matches(selector: str, resource: str, ancestors: set[str]) -> bool:
    if selector == "*":
        return True
    if selector.endswith(":*") and resource.startswith(selector[:-1]):
        return True
    if "*" in selector:
        return any(fnmatch.fnmatchcase(candidate, selector) for candidate in ancestors)
    return selector in ancestors


def resource_covers(a: str, b: str, world: PolicyWorld) -> bool:
    if a == "*" or a == b:
        return True
    if b == "*":
        return False
    if a.endswith(":*") and b.startswith(a[:-1]):
        return True
    if b.endswith(":*") or "*" in b:
        return "*" in a and fnmatch.fnmatchcase(b, a)
    return resource_matches(a, b, world.ancestors(b))


def _all_covered(a: list[str], b: list[str], covers: Any) -> bool:
    return all(any(covers(x, y) for x in a) for y in b)


def rule_covers(world: PolicyWorld, domain: str, a: PolicyRule, b: PolicyRule) -> bool:
    if domain == "network":
        return (
            set_covers(address_set(world, a.sources), address_set(world, b.sources))
            and set_covers(address_set(world, a.destinations), address_set(world, b.destinations))
            and a.port_set().covers(b.port_set())
        )
    return (
        _all_covered(a.sources, b.sources, lambda x, y: principal_covers(x, y, world))
        and _all_covered(a.destinations, b.destinations, lambda x, y: resource_covers(x, y, world))
        and _all_covered(a.actions, b.actions, action_covers)
    )


def rule_overlaps(world: PolicyWorld, domain: str, a: PolicyRule, b: PolicyRule) -> bool:
    if domain == "network":
        return (
            set_overlaps(address_set(world, a.sources), address_set(world, b.sources))
            and set_overlaps(address_set(world, a.destinations), address_set(world, b.destinations))
            and a.port_set().overlaps(b.port_set())
        )
    principals = any(
        principal_covers(x, y, world) or principal_covers(y, x, world) for x in a.sources for y in b.sources
    )
    resources = any(
        resource_covers(x, y, world) or resource_covers(y, x, world) for x in a.destinations for y in b.destinations
    )
    actions = any(action_covers(x, y) or action_covers(y, x) for x in a.actions for y in b.actions)
    return principals and resources and actions


# --------------------------------------------------------------------------- evaluation


class RuleDecision(RafModel):
    policy: str
    rule: str | None  # None = policy default
    effect: str
    ports: list[str] = Field(default_factory=list)
    actions: list[str] = Field(default_factory=list)
    summary: str
    description: str = ""


class PartVerdict(RafModel):
    part: str  # network | identity
    policy: str
    decision: str  # allow | deny
    source: str | None = None
    target: str | None = None
    allowed_ports: list[str] = Field(default_factory=list)
    decisions: list[RuleDecision] = Field(default_factory=list)
    preempted: list[RuleDecision] = Field(default_factory=list)
    explanation: list[str] = Field(default_factory=list)


@dataclass
class _NetworkOutcome:
    allowed: PortSet
    decisions: list[RuleDecision]
    preempted: list[RuleDecision]
    applicable: bool = True
    extra: list[str] = field(default_factory=list)


def policy_applies(world: PolicyWorld, policy: Policy, src: AddrElement, dst: AddrElement) -> bool:
    scope = policy_scope(policy)
    if not scope:
        return True
    selectors = address_set(world, scope)
    return set_contains(selectors, src) or set_contains(selectors, dst)


def policy_scope(policy: Policy) -> list[str]:
    return [s for s in policy.scope if s != ANY]


def evaluate_network_policy(
    world: PolicyWorld, policy: Policy, src: AddrElement, dst: AddrElement, requested: PortSet
) -> _NetworkOutcome:
    remaining = requested
    allowed = PortSet.empty()
    decisions: list[RuleDecision] = []
    preempted: list[RuleDecision] = []
    for rule in policy.active_rules():
        if not (
            set_contains(address_set(world, rule.sources), src)
            and set_contains(address_set(world, rule.destinations), dst)
        ):
            continue
        rule_ports = rule.port_set()
        hit = remaining.intersect(rule_ports)
        if hit.is_empty():
            overlap = requested.intersect(rule_ports)
            if not overlap.is_empty() and not _catch_all(rule):
                preempted.append(
                    RuleDecision(
                        policy=policy.id,
                        rule=rule.id,
                        effect=rule.effect,
                        ports=overlap.labels(),
                        summary=rule.summary("network"),
                        description=rule.description,
                    )
                )
            continue
        decisions.append(
            RuleDecision(
                policy=policy.id,
                rule=rule.id,
                effect=rule.effect,
                ports=hit.labels(),
                summary=rule.summary("network"),
                description=rule.description,
            )
        )
        if rule.effect == "allow":
            allowed = allowed.union(hit)
        remaining = remaining.subtract(hit)
    if not remaining.is_empty():
        decisions.append(
            RuleDecision(
                policy=policy.id, rule=None, effect=policy.default, ports=remaining.labels(), summary="no rule matched"
            )
        )
        if policy.default == "allow":
            allowed = allowed.union(remaining)
    return _NetworkOutcome(allowed, decisions, preempted)


def evaluate_network(
    world: PolicyWorld, policies: list[Policy], src_ref: str, dst_ref: str, requested: PortSet
) -> list[PartVerdict]:
    src, dst = element_for(world, src_ref), element_for(world, dst_ref)
    verdicts = []
    for policy in policies:
        if policy.domain != "network" or not policy_applies(world, policy, src, dst):
            continue
        outcome = evaluate_network_policy(world, policy, src, dst, requested)
        decision = "allow" if not outcome.allowed.is_empty() else "deny"
        explanation = [_zone_note(world, src), _zone_note(world, dst)]
        for d in outcome.decisions:
            label = f"rule {d.rule}" if d.rule else "default (no rule matched)"
            explanation.append(
                f"{policy.id} {label}: {d.effect} {', '.join(d.ports)}"
                + (f"  ({d.description})" if d.description else "")
            )
        for p in outcome.preempted:
            explanation.append(
                f"{policy.id} rule {p.rule} would {p.effect} {', '.join(p.ports)} but an earlier "
                "rule already decided those ports (first match wins)"
            )
        verdicts.append(
            PartVerdict(
                part="network",
                policy=policy.id,
                decision=decision,
                source=src_ref,
                target=dst_ref,
                allowed_ports=outcome.allowed.labels(),
                decisions=outcome.decisions,
                preempted=outcome.preempted,
                explanation=[e for e in explanation if e],
            )
        )
    return verdicts


def _zone_note(world: PolicyWorld, element: AddrElement) -> str:
    name = world.name(element.id)
    if element.kind == "zone":
        nets = ", ".join(str(n) for n in element.nets)
        return f"{name} is a network zone{f' ({nets})' if nets else ''}"
    zones = ", ".join(sorted(world.name(z) for z in element.zones))
    addrs = ", ".join(str(n.network_address) for n in element.nets[:3])
    if not element.resolved:
        return f"{name} is not known in this workspace (matched only by exact references)"
    return f"{name}{f' ({addrs})' if addrs else ''} is in {zones or 'no known network zone'}"


def evaluate_identity(
    world: PolicyWorld, policies: list[Policy], principal: str, resource: str, action: str | None
) -> PartVerdict | None:
    identity_policies = [p for p in policies if p.domain in ("identity", "service")]
    if not identity_policies:
        return None
    closure = world.principal_closure(principal)
    ancestors = world.ancestors(resource)
    allows: list[RuleDecision] = []
    denies: list[RuleDecision] = []
    for policy in identity_policies:
        for rule in policy.active_rules():
            if not any(s == "*" or s in closure for s in rule.sources):
                continue
            if not any(resource_matches(d, resource, ancestors) for d in rule.destinations):
                continue
            actions = [a for a in rule.actions if action_matches(a, action)]
            if not actions:
                continue
            entry = RuleDecision(
                policy=policy.id,
                rule=rule.id,
                effect=rule.effect,
                actions=actions,
                summary=rule.summary(policy.domain),
                description=rule.description,
            )
            (allows if rule.effect == "allow" else denies).append(entry)
    explanation = []
    via = sorted(closure - {principal})
    if via:
        explanation.append(f"{world.name(principal)} acts as: " + ", ".join(world.name(v) for v in via))
    if len(ancestors) > 1:
        explanation.append(
            f"{world.name(resource)} is part of: " + ", ".join(world.name(a) for a in sorted(ancestors - {resource}))
        )
    if denies and (action is not None or not _allow_survives(allows, denies)):
        decision, decisive = "deny", denies
        explanation.append("explicit deny overrides any allow")
    elif allows:
        decision, decisive = "allow", allows
    else:
        default = identity_policies[0].default
        decision = default
        decisive = [
            RuleDecision(
                policy=identity_policies[0].id,
                rule=None,
                effect=default,
                summary=f"no statement grants {action or 'any action'} on {world.name(resource)}",
            )
        ]
    for d in decisive:
        label = f"statement {d.rule}" if d.rule else f"default {d.effect}"
        explanation.append(f"{d.policy} {label}: {d.summary}" + (f"  ({d.description})" if d.description else ""))
    return PartVerdict(
        part="identity",
        policy=",".join(p.id for p in identity_policies),
        decision=decision,
        source=principal,
        target=resource,
        decisions=decisive,
        preempted=denies if decision == "allow" else [],
        explanation=explanation,
    )


def _allow_survives(allows: list[RuleDecision], denies: list[RuleDecision]) -> bool:
    denied = [a for d in denies for a in d.actions]
    return any(not any(action_covers(d, a) for d in denied) for allow in allows for a in allow.actions)


# --------------------------------------------------------------------------- analysis


class PolicyAnalysis(RafModel):
    policies: list[dict[str, Any]] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    by_rule: dict[str, int] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    workspace_aware: bool = True


def _finding(
    rule: str,
    policy: Policy,
    subject: str,
    title: str,
    description: str,
    severity: Severity,
    confidence: float,
    affected: list[str],
    rules: list[PolicyRule],
    recommendation: str,
    explanation: list[str],
) -> Finding:
    now = utcnow()
    return Finding(
        id=finding_id(PRODUCT, rule, f"{policy.id}|{subject}"),
        title=title,
        description=description,
        severity=severity,
        confidence=confidence,
        product=PRODUCT,
        rule_id=rule,
        affected_objects=list(dict.fromkeys([policy.object_id, *affected])),
        evidence=[
            EvidenceRef(kind="policy", id=f"{policy.object_id}#{r.id}", note=r.summary(policy.domain)) for r in rules
        ],
        recommendation=recommendation,
        explanation=[{"factor": rule, "label": text, "sign": "+"} for text in explanation],
        created_at=now,
        updated_at=now,
        tags=["policy", policy.domain],
        metadata={"policy": policy.id, "rules": [r.id for r in rules], "revision": policy.revision},
    )


def _existing(world: PolicyWorld, selectors: Iterable[str]) -> list[str]:
    return [s for s in selectors if s in world.objects]


def analyze_policy(world: PolicyWorld, policy: Policy) -> list[Finding]:
    findings: list[Finding] = []
    rules = policy.active_rules()
    if policy.default == "allow":
        findings.append(
            _finding(
                "default-allow",
                policy,
                "default",
                f"{policy.name}: default action is allow",
                f"Anything not matched by a rule in {policy.name} is allowed. Policies should fail closed.",
                Severity.MEDIUM,
                0.9,
                [],
                [],
                "Set the default action to deny and allow required traffic explicitly.",
                ["default allow"],
            )
        )
    for index, rule in enumerate(rules):
        findings += _broad(world, policy, rule)
        earlier = rules[:index] if policy.evaluation == "first-match" else [r for r in rules if r is not rule]
        findings += _anomalies(world, policy, rule, earlier)
        if not world.is_empty:
            stale = [
                s
                for s in [*rule.sources, *rule.destinations]
                if ":" in s
                and not s.startswith(("cidr:", "*"))
                and "*" not in s
                and not s.split(":", 1)[1].startswith("arn:")
                and s not in world.objects
                and s not in world.zone_nets
            ]
            if stale:
                findings.append(
                    _finding(
                        "stale-reference",
                        policy,
                        rule.id,
                        f"{policy.name} rule {rule.id} references unknown objects",
                        f"Rule {rule.id} ({rule.summary(policy.domain)}) references objects not present in this "
                        f"workspace: {', '.join(stale)}. They may be decommissioned, renamed or not yet imported.",
                        Severity.LOW,
                        0.6,
                        [],
                        [rule],
                        "Remove the rule if the objects are gone, or import the inventory that defines them.",
                        [f"unknown: {s}" for s in stale],
                    )
                )
    return findings


def _broad(world: PolicyWorld, policy: Policy, rule: PolicyRule) -> list[Finding]:
    if rule.effect != "allow":
        return []
    reasons: list[str] = []
    severity: Severity | None = None
    if policy.domain == "network":
        src, dst = address_set(world, rule.sources), address_set(world, rule.destinations)
        ports = rule.port_set()
        all_ports = ports.is_everything()
        external_src = src.any or any(e.kind == "zone" and any(n.prefixlen == 0 for n in e.nets) for e in src.elements)
        dst_crit = max(
            (world.zone_criticality(e.id) if e.kind == "zone" else world.criticality(e.id) for e in dst.elements),
            key=lambda c: _CRIT_RANK.get(c or "", -1),
            default=None,
        )
        if src.any and dst.any:
            severity, reasons = Severity.HIGH, ["any source to any destination"]
        elif external_src and all_ports:
            severity, reasons = Severity.HIGH, ["external/any source with every port open"]
        elif all_ports and dst_crit in ("high", "critical"):
            severity, reasons = Severity.HIGH, [f"every port open towards a {dst_crit}-criticality destination"]
        elif all_ports:
            severity, reasons = Severity.MEDIUM, ["every port open"]
        elif ports.size() > 1024:
            severity, reasons = Severity.LOW, [f"{ports.size():,} ports open ({', '.join(ports.labels())})"]
        if severity is not None and dst_crit and f"{dst_crit}-criticality" not in " ".join(reasons):
            reasons.append(f"destination criticality: {dst_crit}")
    else:
        wildcard_actions = "*" in rule.actions
        wildcard_resources = "*" in rule.destinations
        anyone = "*" in rule.sources and not rule.metadata.get("principal_unspecified")
        if wildcard_actions and wildcard_resources:
            severity, reasons = Severity.HIGH, ["all actions on all resources"]
        elif anyone and (wildcard_actions or "admin" in rule.actions):
            severity, reasons = Severity.HIGH, ["every principal gets wildcard/admin actions"]
        elif wildcard_actions and any(world.criticality(d) in ("high", "critical") for d in rule.destinations):
            severity, reasons = Severity.MEDIUM, ["all actions on a high/critical resource"]
        elif wildcard_resources and any(a.endswith("*") or a == "admin" for a in rule.actions):
            severity, reasons = Severity.MEDIUM, ["privileged actions on every resource"]
    if severity is None:
        return []
    return [
        _finding(
            "overly-broad-rule",
            policy,
            rule.id,
            f"Overly broad rule {rule.id} in {policy.name}",
            f"Rule {rule.id} allows {rule.summary(policy.domain).removeprefix('allow ')}: "
            + "; ".join(reasons)
            + "."
            + (f" Stated purpose: {rule.description}." if rule.description else ""),
            severity,
            0.85,
            _existing(world, [*rule.sources, *rule.destinations]),
            [rule],
            "Restrict the rule to the sources, destinations, ports or actions that are actually required.",
            reasons,
        )
    ]


def _anomalies(world: PolicyWorld, policy: Policy, rule: PolicyRule, earlier: list[PolicyRule]) -> list[Finding]:
    domain = policy.domain
    if policy.evaluation == "first-match":
        for prior in earlier:
            if not rule_covers(world, domain, prior, rule):
                continue
            if prior.effect != rule.effect:
                return [
                    _finding(
                        "shadowed-rule",
                        policy,
                        rule.id,
                        f"Rule {rule.id} in {policy.name} can never apply",
                        f"Rule {rule.id} ({rule.summary(domain)}) is fully covered by the earlier rule {prior.id} "
                        f"({prior.summary(domain)}) with the opposite effect. Because the first match wins, "
                        f"{rule.id} is unreachable"
                        + (f" - its intent ('{rule.description}') is not enforced." if rule.description else "."),
                        Severity.HIGH if rule.effect == "deny" else Severity.MEDIUM,
                        0.9,
                        _existing(world, [*rule.sources, *rule.destinations]),
                        [rule, prior],
                        f"Move {rule.id} above {prior.id} or narrow {prior.id}.",
                        [f"covered by {prior.id}", "opposite effect", "first match wins"],
                    )
                ]
            return [
                _finding(
                    "redundant-rule",
                    policy,
                    rule.id,
                    f"Rule {rule.id} in {policy.name} is redundant",
                    f"Rule {rule.id} ({rule.summary(domain)}) is fully covered by the earlier rule {prior.id} "
                    f"({prior.summary(domain)}) with the same effect, so it never changes a decision.",
                    Severity.LOW,
                    0.85,
                    [],
                    [rule, prior],
                    f"Remove {rule.id} (or {prior.id} if it is too broad).",
                    [f"covered by {prior.id}", "same effect"],
                )
            ]
        for prior in earlier:
            if (
                prior.effect != rule.effect
                and rule_overlaps(world, domain, prior, rule)
                and not rule_covers(world, domain, rule, prior)
                and not _catch_all(rule)
            ):
                return [
                    _finding(
                        "conflicting-rules",
                        policy,
                        rule.id,
                        f"Rules {prior.id} and {rule.id} in {policy.name} conflict",
                        f"Rules {prior.id} ({prior.summary(domain)}) and {rule.id} ({rule.summary(domain)}) partially "
                        f"overlap with opposite effects; for the overlapping traffic the outcome depends on rule order "
                        f"and {prior.id} wins.",
                        Severity.LOW,
                        0.7,
                        [],
                        [rule, prior],
                        "Make the rules disjoint or document the intended precedence.",
                        ["partial overlap", "opposite effects", "order-dependent"],
                    )
                ]
        return []
    # deny-overrides: an allow fully covered by a deny never takes effect; allow covered by allow is redundant
    if rule.effect == "allow":
        for other in earlier:
            if other.effect == "deny" and rule_covers(world, domain, other, rule):
                return [
                    _finding(
                        "shadowed-rule",
                        policy,
                        rule.id,
                        f"Statement {rule.id} in {policy.name} never takes effect",
                        f"Allow statement {rule.id} ({rule.summary(domain)}) is fully covered by deny statement "
                        f"{other.id} ({other.summary(domain)}); explicit deny always wins.",
                        Severity.MEDIUM,
                        0.9,
                        _existing(world, rule.sources),
                        [rule, other],
                        f"Remove {rule.id} or narrow {other.id}.",
                        [f"covered by deny {other.id}"],
                    )
                ]
        for other in earlier:
            if other.effect == "allow" and rule_covers(world, domain, other, rule):
                mutual = rule_covers(world, domain, rule, other)
                if mutual and other.order > rule.order:
                    continue  # identical statements: report only the later one
                return [
                    _finding(
                        "redundant-rule",
                        policy,
                        rule.id,
                        f"Statement {rule.id} in {policy.name} is redundant",
                        f"Allow statement {rule.id} ({rule.summary(domain)}) grants nothing beyond statement "
                        f"{other.id} ({other.summary(domain)}).",
                        Severity.LOW,
                        0.85,
                        [],
                        [rule, other],
                        f"Remove {rule.id} or narrow {other.id} if it is broader than intended.",
                        [f"covered by {other.id}"],
                    )
                ]
    return []


def _catch_all(rule: PolicyRule) -> bool:
    return rule.sources == [ANY] and rule.destinations == [ANY] and rule.ports == [ANY]


def analyze_set(world: PolicyWorld, policies: list[Policy]) -> PolicyAnalysis:
    findings: list[Finding] = []
    summaries = []
    for policy in policies:
        policy_findings = analyze_policy(world, policy)
        findings += policy_findings
        summaries.append(
            {
                "id": policy.id,
                "object_id": policy.object_id,
                "name": policy.name,
                "domain": policy.domain,
                "evaluation": policy.evaluation,
                "default": policy.default,
                "revision": policy.revision,
                "rules": len(policy.rules),
                "active_rules": len(policy.active_rules()),
                "findings": len(policy_findings),
                "digest": policy.digest(),
                "source": policy.source,
            }
        )
    unique = {f.id: f for f in findings}
    ordered = sorted(unique.values(), key=lambda f: (-f.severity.rank, f.metadata.get("policy", ""), f.id))
    by_rule: dict[str, int] = {}
    for f in ordered:
        by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1
    return PolicyAnalysis(policies=summaries, findings=ordered, by_rule=by_rule, workspace_aware=not world.is_empty)


# --------------------------------------------------------------------------- revision diff


class RuleChange(RafModel):
    policy: str
    rule: str
    change: str  # added | removed | modified | moved
    impact: str  # access-expanded | access-reduced | changed
    fields: dict[str, dict[str, Any]] = Field(default_factory=dict)
    before: str | None = None
    after: str | None = None


class PolicyDiff(RafModel):
    before: str
    after: str
    policies_added: list[str] = Field(default_factory=list)
    policies_removed: list[str] = Field(default_factory=list)
    defaults_changed: list[dict[str, Any]] = Field(default_factory=list)
    changes: list[RuleChange] = Field(default_factory=list)
    findings_introduced: list[Finding] = Field(default_factory=list)
    findings_resolved: list[Finding] = Field(default_factory=list)

    @property
    def expanded(self) -> int:
        return sum(1 for c in self.changes if c.impact == "access-expanded")


def _impact(world: PolicyWorld, domain: str, old: PolicyRule | None, new: PolicyRule | None) -> str:
    if old is None and new is not None:
        return "access-expanded" if new.effect == "allow" else "access-reduced"
    if new is None and old is not None:
        return "access-reduced" if old.effect == "allow" else "access-expanded"
    assert old is not None and new is not None
    if old.enabled != new.enabled:
        grants = (new.enabled and new.effect == "allow") or (old.enabled and old.effect == "deny")
        return "access-expanded" if grants else "access-reduced"
    if old.effect != new.effect:
        return "access-expanded" if new.effect == "allow" else "access-reduced"
    wider = rule_covers(world, domain, new, old) and not rule_covers(world, domain, old, new)
    narrower = rule_covers(world, domain, old, new) and not rule_covers(world, domain, new, old)
    if wider:
        return "access-expanded" if new.effect == "allow" else "access-reduced"
    if narrower:
        return "access-reduced" if new.effect == "allow" else "access-expanded"
    return "changed"


def diff_sets(
    world: PolicyWorld, before: list[Policy], after: list[Policy], *, before_label: str, after_label: str
) -> PolicyDiff:
    old = {p.id: p for p in before}
    new = {p.id: p for p in after}
    result = PolicyDiff(
        before=before_label,
        after=after_label,
        policies_added=sorted(set(new) - set(old)),
        policies_removed=sorted(set(old) - set(new)),
    )
    for pid in sorted(set(old) & set(new)):
        o, n = old[pid], new[pid]
        if o.default != n.default:
            result.defaults_changed.append({"policy": pid, "before": o.default, "after": n.default})
        o_rules = {r.id: r for r in o.rules}
        n_rules = {r.id: r for r in n.rules}
        o_order = [r.id for r in o.active_rules() if r.id in n_rules]
        n_order = [r.id for r in n.active_rules() if r.id in o_rules]
        for rid in sorted(set(o_rules) | set(n_rules), key=lambda r: (n_rules.get(r) or o_rules[r]).order):
            a, b = o_rules.get(rid), n_rules.get(rid)
            if a is None and b is not None:
                result.changes.append(
                    RuleChange(
                        policy=pid,
                        rule=rid,
                        change="added",
                        impact=_impact(world, n.domain, None, b),
                        after=b.summary(n.domain),
                    )
                )
            elif b is None and a is not None:
                result.changes.append(
                    RuleChange(
                        policy=pid,
                        rule=rid,
                        change="removed",
                        impact=_impact(world, o.domain, a, None),
                        before=a.summary(o.domain),
                    )
                )
            elif a is not None and b is not None:
                sa, sb = a.signature(), b.signature()
                fields = {k: {"before": sa[k], "after": sb[k]} for k in sa if sa[k] != sb[k]}
                if fields:
                    result.changes.append(
                        RuleChange(
                            policy=pid,
                            rule=rid,
                            change="modified",
                            impact=_impact(world, n.domain, a, b),
                            fields=fields,
                            before=a.summary(o.domain),
                            after=b.summary(n.domain),
                        )
                    )
        if o.evaluation == "first-match" and o_order != n_order:
            moved = [rid for rid in n_order if o_order.index(rid) != n_order.index(rid)]
            for rid in moved[:20]:
                if not any(c.rule == rid and c.policy == pid for c in result.changes):
                    result.changes.append(
                        RuleChange(
                            policy=pid,
                            rule=rid,
                            change="moved",
                            impact="changed",
                            fields={"position": {"before": o_order.index(rid), "after": n_order.index(rid)}},
                        )
                    )
    before_findings = {f.id: f for f in analyze_set(world, before).findings}
    after_findings = {f.id: f for f in analyze_set(world, after).findings}
    result.findings_introduced = [f for fid, f in after_findings.items() if fid not in before_findings]
    result.findings_resolved = [f for fid, f in before_findings.items() if fid not in after_findings]
    return result


def policies_of(sets: Iterable[PolicySet]) -> list[Policy]:
    out: list[Policy] = []
    for policy_set in sets:
        out.extend(policy_set.policies)
    return out
