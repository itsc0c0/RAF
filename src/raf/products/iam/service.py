"""R$F IAM: identity and access analysis over the shared graph.

Read-only analysis - nothing is changed in any external identity system.

Two views of the graph are used:

* the **grant graph** (memberships, roles, permissions, access/admin grants, owned identities and
  resource containment) answers "what is this principal *entitled* to" (effective access);
* the **access graph** additionally follows credential placement and use (``USES``, ``LOGGED_INTO``,
  ``CONTAINS_SECRET``, ``AUTHENTICATES_AS``, ``TRUSTS``) and answers "how *could* A obtain B"
  (privilege paths), which is where unexpected access paths show up.

Analyzers (rule ids) - each produces explainable findings with evidence:

* ``excessive-privilege``      control over several high/critical assets, or a wildcard role
* ``dormant-privileged``       privileged identity with no activity for ``iam.dormant_days``, measured
                               against the newest event in the workspace (reproducible)
* ``inherited-privilege``      privileged role obtained through *nested* groups (two or more group hops)
* ``broad-role``               privileged role that is wildcard or held by ``iam.broad_role_threshold``+
                               principals
* ``credential-exposure-path`` credentials of a privileged identity placed on a host other principals
                               can log into or access
* ``risky-trust``              transitive (length >= 2) or external trust relationships
* ``privileged-without-mfa``   privileged human/admin identities with MFA recorded as disabled
"""

from __future__ import annotations

import contextlib
from collections import deque
from collections.abc import Iterable, Sequence
from datetime import datetime, timedelta
from typing import Any

from pydantic import Field

from raf.core.context.app import RafContext
from raf.core.graph.propagation import Propagator, Reached
from raf.core.graph.source import Direction, GraphSource, MemoryGraphSource
from raf.core.ids import finding_id
from raf.core.objects.models import EvidenceRef, Finding, RafModel, Relationship, SecurityObject
from raf.core.objects.semantics import CONTROL, NON_PROPAGATING_TYPES, TRUST, explain, is_privileged
from raf.core.objects.types import Criticality, ObjectType, Severity
from raf.core.timeutil import parse_timestamp, utcnow

PRODUCT = "iam"
RULES = (
    "excessive-privilege",
    "dormant-privileged",
    "inherited-privilege",
    "broad-role",
    "credential-exposure-path",
    "risky-trust",
    "privileged-without-mfa",
)
GRANT_RELS = (
    "MEMBER_OF",
    "HAS_ROLE",
    "HAS_PERMISSION",
    "CAN_ACCESS",
    "ADMIN_OF",
    "CAN_ASSUME",
    "HAS_IDENTITY",
    "CONTAINS",
    "DEPLOYS_TO",
)
ACCESS_RELS = (*GRANT_RELS, "USES", "LOGGED_INTO", "CONTAINS_SECRET", "AUTHENTICATES_AS", "TRUSTS", "RUNS", "OWNS")
RESOURCE_TYPES = (
    "host",
    "service",
    "cloud_resource",
    "container",
    "identity",
    "secret",
    "project",
    "repository",
    "database",
    "application",
)


class AccessHop(RafModel):
    source: str
    source_name: str
    target: str
    target_name: str
    relationship_type: str
    relationship_id: str | None
    forward: bool
    confidence: float
    why: str


class AccessPath(RafModel):
    source: str
    source_name: str
    target: str
    target_name: str
    confidence: float
    hops: list[AccessHop]


class EffectiveAccess(RafModel):
    principal: dict[str, Any]
    privileged: bool
    groups: list[dict[str, Any]] = Field(default_factory=list)
    roles: list[dict[str, Any]] = Field(default_factory=list)
    identities: list[dict[str, Any]] = Field(default_factory=list)
    resources: list[dict[str, Any]] = Field(default_factory=list)
    last_activity: datetime | None = None
    findings: list[Finding] = Field(default_factory=list)


class IamReport(RafModel):
    generated_at: datetime
    reference_time: datetime | None
    principals: int
    privileged_principals: int
    findings: list[Finding] = Field(default_factory=list)
    by_rule: dict[str, int] = Field(default_factory=dict)
    resolved: int = 0


class _ExcludingSource:
    """A graph source view that hides some relationships (used to find alternative paths)."""

    def __init__(self, base: GraphSource, excluded: set[str]) -> None:
        self.base = base
        self.excluded = excluded

    @property
    def at(self) -> datetime | None:
        return self.base.at

    def nodes(self, ids: Iterable[str]) -> dict[str, SecurityObject]:
        return self.base.nodes(ids)

    def edges(
        self, ids: Sequence[str], direction: Direction = "both", types: Sequence[str] | None = None
    ) -> list[Relationship]:
        return [r for r in self.base.edges(ids, direction, types) if r.id not in self.excluded]

    def find_nodes(
        self, types: Sequence[str] | None = None, tag: str | None = None, metadata_flag: str | None = None
    ) -> list[SecurityObject]:
        return self.base.find_nodes(types, tag, metadata_flag)


def _crit(obj: SecurityObject | None) -> str | None:
    if obj is None:
        return None
    level = Criticality.of(obj.metadata, obj.tags)
    return level.value if level else None


class IamService:
    def __init__(self, ctx: RafContext, *, at: datetime | None = None) -> None:
        self.ctx = ctx
        self.store = ctx.store
        self.at = at
        self._objects: dict[str, SecurityObject] | None = None
        self._relationships: list[Relationship] | None = None
        self._graphs: dict[tuple[str, ...], MemoryGraphSource] = {}

    # ------------------------------------------------------------------ graph views
    def _load(self) -> tuple[dict[str, SecurityObject], list[Relationship]]:
        if self._objects is None or self._relationships is None:
            self._objects = {o.id: o for o in self.store.objects.iter_all(exclude_types=sorted(NON_PROPAGATING_TYPES))}
            self._relationships = list(self.store.relationships.iter_all(types=list(ACCESS_RELS)))
        return self._objects, self._relationships

    def graph(self, types: Sequence[str] = ACCESS_RELS) -> MemoryGraphSource:
        key = tuple(types)
        if key not in self._graphs:
            objects, rels = self._load()
            wanted = set(types)
            self._graphs[key] = MemoryGraphSource(
                objects.values(), [r for r in rels if r.relationship_type in wanted], self.at
            )
        return self._graphs[key]

    def _obj(self, object_id: str) -> SecurityObject | None:
        return self._load()[0].get(object_id)

    def _meta(self, object_id: str) -> dict[str, Any]:
        obj = self._obj(object_id)
        return obj.metadata if obj else {}

    def name(self, object_id: str) -> str:
        obj = self._obj(object_id)
        return obj.name if obj else object_id.split(":", 1)[-1]

    def _out(self, node: str, types: Iterable[str]) -> list[Relationship]:
        return self.graph().edges([node], "out", list(types))

    def _in(self, node: str, types: Iterable[str]) -> list[Relationship]:
        return self.graph().edges([node], "in", list(types))

    def _privileged_object(self, object_id: str) -> bool:
        obj = self._obj(object_id)
        return bool(obj and is_privileged(obj.type, obj.metadata, obj.tags))

    def is_privileged_principal(self, principal: str) -> bool:
        if self._privileged_object(principal) or any(self._privileged_object(r) for r, _ in self.roles(principal)):
            return True
        return any(self._privileged_object(r.target_object) for r in self._out(principal, ["HAS_IDENTITY"]))

    def principals(self) -> list[SecurityObject]:
        objects = self._load()[0]
        return sorted(
            (o for o in objects.values() if o.type in (ObjectType.USER, ObjectType.IDENTITY)), key=lambda o: o.id
        )

    # ------------------------------------------------------------------ memberships and roles
    def memberships(self, principal: str) -> list[tuple[str, list[str]]]:
        """Groups reachable through MEMBER_OF (transitively), each with its shortest membership chain."""
        seen: dict[str, list[str]] = {}
        queue: deque[tuple[str, list[str]]] = deque([(principal, [principal])])
        while queue:
            node, chain = queue.popleft()
            if len(chain) > 10:
                continue
            for rel in self._out(node, ["MEMBER_OF"]):
                group = rel.target_object
                if not group.startswith("group:") or group in seen or group == principal:
                    continue
                seen[group] = [*chain, group]
                queue.append((group, [*chain, group]))
        return sorted(seen.items())

    def roles(self, principal: str) -> list[tuple[str, list[str]]]:
        """Roles held directly or through groups, each with the shortest chain principal → ... → role."""
        found: dict[str, list[str]] = {}
        for holder, chain in [(principal, [principal]), *self.memberships(principal)]:
            for rel in self._out(holder, ["HAS_ROLE"]):
                role = rel.target_object
                if role not in found or len(chain) + 1 < len(found[role]):
                    found[role] = [*chain, role]
        return sorted(found.items())

    def members(self, holder: str) -> set[str]:
        """Users/identities that hold ``holder`` (a group, transitively; any other principal is itself)."""
        if not holder.startswith("group:"):
            return {holder}
        members: set[str] = set()
        queue = deque([holder])
        seen = {holder}
        while queue:
            group = queue.popleft()
            for rel in self._in(group, ["MEMBER_OF"]):
                src = rel.source_object
                if src in seen:
                    continue
                seen.add(src)
                if src.startswith("group:"):
                    queue.append(src)
                elif src.startswith(("user:", "identity:")):
                    members.add(src)
        return members

    def holders_of(self, role: str) -> set[str]:
        holders: set[str] = set()
        for rel in self._in(role, ["HAS_ROLE"]):
            holders |= self.members(rel.source_object)
        return holders

    def access_holders(self, resource: str) -> set[str]:
        """Principals granted CAN_ACCESS/ADMIN_OF on ``resource`` directly, via groups or via roles."""
        holders: set[str] = set()
        for rel in self._in(resource, ["CAN_ACCESS", "ADMIN_OF"]):
            src = rel.source_object
            if src.startswith("role:"):
                holders |= self.holders_of(src)
            elif src.startswith("group:"):
                holders |= self.members(src)
            elif src.startswith(("user:", "identity:")):
                holders.add(src)
        return holders

    # ------------------------------------------------------------------ effective access and paths
    def _hops(self, reached: Reached) -> list[AccessHop]:
        hops = []
        for hop in reached.path:
            rel = hop.relationship
            hops.append(
                AccessHop(
                    source=hop.frm,
                    source_name=self.name(hop.frm),
                    target=hop.to,
                    target_name=self.name(hop.to),
                    relationship_type=rel.relationship_type if rel else "EXPLOITABLE",
                    relationship_id=rel.id if rel else None,
                    forward=hop.forward,
                    confidence=round(hop.factor, 3),
                    why=explain(hop.why, self.name(hop.frm), self.name(hop.to), rel.metadata if rel else None),
                )
            )
        return hops

    def effective_access(self, principal: str, *, max_depth: int = 8, findings: bool = False) -> EffectiveAccess:
        obj = self._obj(principal)
        reached = Propagator(
            self.graph(GRANT_RELS), max_depth=max_depth, min_confidence=0.2, upgrade_vulnerabilities=False
        ).run([principal])
        resources = []
        for node, r in sorted(reached.items(), key=lambda kv: (-kv[1].confidence, kv[1].depth, kv[0])):
            otype = node.split(":", 1)[0]
            if r.mode not in (CONTROL, TRUST) or otype not in RESOURCE_TYPES:
                continue
            hops = self._hops(r)
            resources.append(
                {
                    "id": node,
                    "name": self.name(node),
                    "type": otype,
                    "confidence": round(r.confidence, 3),
                    "depth": r.depth,
                    "criticality": _crit(self._obj(node)),
                    "admin": any(h.relationship_type == "ADMIN_OF" for h in hops),
                    "via": " → ".join([self.name(principal)] + [h.target_name for h in hops]),
                    "grant": hops[-1].why if hops else "",
                }
            )
        groups = [
            {"id": g, "name": self.name(g), "chain": [self.name(c) for c in chain], "nested": len(chain) > 2}
            for g, chain in self.memberships(principal)
        ]
        roles = [
            {
                "id": r,
                "name": self.name(r),
                "privileged": self._privileged_object(r),
                "wildcard": bool(self._meta(r).get("wildcard")),
                "chain": [self.name(c) for c in chain],
                "via_nested_group": len(chain) > 3,
            }
            for r, chain in self.roles(principal)
        ]
        identities = [
            {
                "id": rel.target_object,
                "name": self.name(rel.target_object),
                "privileged": self._privileged_object(rel.target_object),
            }
            for rel in self._out(principal, ["HAS_IDENTITY", "CAN_ASSUME"])
        ]
        activity = self.store.events.object_activity([principal]).get(principal)
        last = max(
            (t for t in ((obj.last_seen if obj else None), activity[1] if activity else None) if t), default=None
        )
        result = EffectiveAccess(
            principal={
                "id": principal,
                "name": self.name(principal),
                "type": principal.split(":", 1)[0],
                "metadata": obj.metadata if obj else {},
            },
            privileged=self._privileged_object(principal)
            or any(r["privileged"] for r in roles)
            or any(i["privileged"] for i in identities),
            groups=groups,
            roles=roles,
            identities=identities,
            resources=resources[:500],
            last_activity=last,
        )
        if findings:
            result.findings = self.store.findings.list(product=PRODUCT, object_id=principal, limit=100)
        return result

    def paths(self, source: str, target: str, *, max_depth: int = 10, limit: int = 3) -> list[AccessPath]:
        """Privilege paths from ``source`` to control of ``target`` over the access graph.

        The best path comes first; alternatives are found by removing one relationship of the best
        path at a time (a simplified Yen's algorithm), deduplicated and ordered by confidence.
        """
        graph = self.graph(ACCESS_RELS)

        def best(excluded: set[str]) -> Reached | None:
            view: GraphSource = _ExcludingSource(graph, excluded) if excluded else graph
            found = (
                Propagator(view, max_depth=max_depth, min_confidence=0.01, upgrade_vulnerabilities=False)
                .run([source])
                .get(target)
            )
            if found is None or found.mode not in (CONTROL, TRUST) or not found.path:
                return None
            return found

        first = best(set())
        if first is None:
            return []
        candidates: dict[tuple[str, ...], Reached] = {self._signature(first): first}
        for hop in first.path:
            if hop.relationship is None:
                continue
            alternative = best({hop.relationship.id})
            if alternative is not None:
                candidates.setdefault(self._signature(alternative), alternative)
        ordered = sorted(candidates.values(), key=lambda r: (-r.confidence, r.depth))[:limit]
        return [
            AccessPath(
                source=source,
                source_name=self.name(source),
                target=target,
                target_name=self.name(target),
                confidence=round(r.confidence, 3),
                hops=self._hops(r),
            )
            for r in ordered
        ]

    @staticmethod
    def _signature(reached: Reached) -> tuple[str, ...]:
        return tuple(h.relationship.id if h.relationship else f"vuln:{h.vulnerability}" for h in reached.path)

    # ------------------------------------------------------------------ analysis
    def reference_time(self) -> datetime | None:
        return self.store.events.bounds()[1]

    def analyze(self, *, persist: bool = True) -> IamReport:
        now = utcnow()
        reference = self.reference_time()
        findings: list[Finding] = []
        principals = self.principals()
        activity = self.store.events.object_activity([p.id for p in principals])
        privileged = [p for p in principals if self.is_privileged_principal(p.id)]
        for p in privileged:
            findings += self._excessive(p)
            findings += self._dormant(p, reference, activity.get(p.id))
            findings += self._mfa(p)
        for p in principals:
            findings += self._inherited(p)
        findings += self._broad_roles()
        findings += self._credential_exposure()
        findings += self._trusts()
        unique = {f.id: f for f in findings}
        findings = sorted(unique.values(), key=lambda f: (-f.severity.rank, f.rule_id, f.id))
        resolved = 0
        if persist:
            self.store.findings.upsert(findings)
            resolved = self.store.findings.resolve_absent(PRODUCT, list(RULES), [f.id for f in findings])
        by_rule: dict[str, int] = {}
        for f in findings:
            by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1
        return IamReport(
            generated_at=now,
            reference_time=reference,
            principals=len(principals),
            privileged_principals=len(privileged),
            findings=findings,
            by_rule=by_rule,
            resolved=resolved,
        )

    def _finding(
        self,
        rule: str,
        subject: str,
        title: str,
        description: str,
        severity: Severity,
        confidence: float,
        affected: list[str],
        evidence: list[EvidenceRef],
        recommendation: str,
        explanation: list[dict[str, Any]],
    ) -> Finding:
        now = utcnow()
        # explanation entries share the finding-wide shape {factor, label, sign} (see render_finding)
        normalized = [
            {"sign": "+", "factor": e.get("factor", rule), "label": e.get("label") or e.get("detail", "")}
            for e in explanation
        ]
        return Finding(
            id=finding_id(PRODUCT, rule, subject),
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            product=PRODUCT,
            rule_id=rule,
            affected_objects=list(dict.fromkeys(affected)),
            evidence=evidence,
            recommendation=recommendation,
            explanation=normalized,
            created_at=now,
            updated_at=now,
            tags=["iam"],
        )

    def _excessive(self, p: SecurityObject) -> list[Finding]:
        access = self.effective_access(p.id)
        critical = [
            r
            for r in access.resources
            if r["criticality"] in ("high", "critical")
            and r["type"] in ("host", "service", "cloud_resource", "database")
        ]
        wildcard = [r for r in access.roles if r["wildcard"]]
        if len(critical) < 3 and not wildcard:
            return []
        names = ", ".join(r["name"] for r in critical[:6]) + (" ..." if len(critical) > 6 else "")
        explanation: list[dict[str, Any]] = [
            {"factor": "critical-assets", "detail": f"control over {len(critical)} high/critical assets: {names}"}
        ]
        if wildcard:
            explanation.append(
                {
                    "factor": "wildcard-role",
                    "detail": "wildcard role(s): "
                    + ", ".join(f"{r['name']} via {' → '.join(r['chain'])}" for r in wildcard),
                }
            )
        severity = Severity.HIGH if wildcard or len(critical) >= 5 else Severity.MEDIUM
        return [
            self._finding(
                "excessive-privilege",
                p.id,
                f"{p.name} has broad privileged access",
                f"{p.name} is entitled to control {len(critical)} high or critical assets ({names})"
                + (" and holds wildcard role(s) " + ", ".join(r["name"] for r in wildcard) if wildcard else "")
                + ".",
                severity,
                0.75,
                [p.id] + [r["id"] for r in critical[:20]],
                [EvidenceRef(kind="object", id=r["id"], note=r["via"]) for r in critical[:10]]
                + [EvidenceRef(kind="object", id=r["id"], note="wildcard role") for r in wildcard],
                "Review whether this principal needs standing access; prefer narrower roles and just-in-time "
                "elevation.",
                explanation,
            )
        ]

    def _dormant(
        self,
        p: SecurityObject,
        reference: datetime | None,
        activity: tuple[datetime | None, datetime | None, int] | None,
    ) -> list[Finding]:
        if reference is None:
            return []  # no events at all: activity cannot be judged
        candidates = [p.last_seen, activity[1] if activity else None]
        explicit = p.metadata.get("last_login") or p.metadata.get("last_logon")
        if isinstance(explicit, str):
            with contextlib.suppress(ValueError):
                candidates.append(parse_timestamp(explicit))
        last = max((t for t in candidates if t is not None), default=None)
        days = int(self.ctx.settings.get("iam.dormant_days"))
        if last is not None and reference - last < timedelta(days=days):
            return []
        if last is None:
            age, confidence = "no recorded activity in this workspace", 0.5
        else:
            age, confidence = f"inactive for {(reference - last).days} days", 0.85
        return [
            self._finding(
                "dormant-privileged",
                p.id,
                f"Dormant privileged identity: {p.name}",
                f"{p.name} holds privileged access but shows {age} (threshold {days} days, measured against the "
                f"newest event in this workspace, {reference.isoformat()}).",
                Severity.MEDIUM,
                confidence,
                [p.id],
                [EvidenceRef(kind="object", id=p.id, note=f"last activity: {last.isoformat() if last else 'none'}")],
                "Disable or remove the account, or document why it must remain privileged and enabled.",
                [
                    {"factor": "inactivity", "detail": age},
                    {"factor": "privileged", "detail": "holds privileged access"},
                ],
            )
        ]

    def _inherited(self, p: SecurityObject) -> list[Finding]:
        findings = []
        for role, chain in self.roles(p.id):
            if not self._privileged_object(role) or len(chain) < 4:  # principal, >=2 groups, role
                continue
            path = " → ".join(self.name(c) for c in chain)
            wildcard = bool(self._meta(role).get("wildcard"))
            findings.append(
                self._finding(
                    "inherited-privilege",
                    f"{p.id}|{role}",
                    f"{p.name} inherits privileged role {self.name(role)}",
                    f"{p.name} obtains the privileged{' wildcard' if wildcard else ''} role {self.name(role)} only "
                    f"through nested group membership: {path}. Nested inheritance is easy to miss in access reviews.",
                    Severity.HIGH if wildcard else Severity.MEDIUM,
                    0.9,
                    [p.id, role, *chain[1:-1]],
                    [EvidenceRef(kind="object", id=c, note="membership chain") for c in chain[1:]],
                    "Remove the group nesting or grant the needed (narrower) role directly to the nested group.",
                    [{"factor": "nested-groups", "detail": f"{len(chain) - 2} group hops: {path}"}]
                    + (
                        [{"factor": "wildcard-role", "detail": f"{self.name(role)} grants wildcard access"}]
                        if wildcard
                        else []
                    ),
                )
            )
        return findings

    def _mfa(self, p: SecurityObject) -> list[Finding]:
        kind = str(p.metadata.get("kind") or ("human" if p.type == ObjectType.USER else ""))
        if kind == "service" or p.metadata.get("mfa") is not False:
            return []
        return [
            self._finding(
                "privileged-without-mfa",
                p.id,
                f"Privileged account without MFA: {p.name}",
                f"{p.name} ({kind or p.type}) holds privileged access and MFA is recorded as disabled.",
                Severity.MEDIUM,
                0.8,
                [p.id],
                [EvidenceRef(kind="object", id=p.id, note="metadata.mfa = false")],
                "Enforce MFA for every privileged human or administrative account.",
                [{"factor": "no-mfa", "detail": "metadata.mfa is false"}],
            )
        ]

    def _broad_roles(self) -> list[Finding]:
        threshold = int(self.ctx.settings.get("iam.broad_role_threshold"))
        findings = []
        roles = [o for o in self._load()[0].values() if o.type == ObjectType.ROLE]
        for role in sorted(roles, key=lambda o: o.id):
            if not is_privileged(role.type, role.metadata, role.tags):
                continue
            holders = self.holders_of(role.id)
            wildcard = bool(role.metadata.get("wildcard"))
            if len(holders) < threshold and not wildcard:
                continue
            grants = [
                f"{r.relationship_type} {self.name(r.target_object)}"
                for r in self._out(role.id, ["CAN_ACCESS", "ADMIN_OF", "HAS_PERMISSION"])
            ]
            findings.append(
                self._finding(
                    "broad-role",
                    role.id,
                    f"Broad privileged role: {role.name}",
                    f"The privileged role {role.name} ({', '.join(grants) or 'no explicit grants'})"
                    + (" grants wildcard actions/resources and" if wildcard else "")
                    + f" is held by {len(holders)} principal(s): "
                    + ", ".join(sorted(self.name(h) for h in holders)[:12])
                    + ".",
                    Severity.HIGH if wildcard else Severity.MEDIUM,
                    0.85,
                    [role.id, *sorted(holders)[:20]],
                    [EvidenceRef(kind="object", id=role.id, note="role definition")]
                    + [EvidenceRef(kind="object", id=h, note="holder") for h in sorted(holders)[:10]],
                    "Scope the role's permissions and grant it just-in-time instead of through standing membership.",
                    [{"factor": "holders", "detail": f"{len(holders)} holder(s)"}]
                    + ([{"factor": "wildcard", "detail": "wildcard actions/resources"}] if wildcard else []),
                )
            )
        return findings

    def _credential_exposure(self) -> list[Finding]:
        findings = []
        uses = [r for r in self.graph().all_edges.values() if r.relationship_type == "USES"]
        for rel in sorted(uses, key=lambda r: r.id):
            host, identity = rel.source_object, rel.target_object
            if not host.startswith("host:") or not identity.startswith(("identity:", "user:")):
                continue
            if not self.is_privileged_principal(identity):
                continue
            logged = {
                r.source_object
                for r in self._in(host, ["LOGGED_INTO"])
                if r.source_object.startswith(("user:", "identity:"))
            }
            exposed_to = sorted((logged | self.access_holders(host)) - {identity})
            if not exposed_to:
                continue
            on_disk = bool(rel.metadata.get("credential_location"))
            location = rel.metadata.get("credential_location") or rel.metadata.get("credential") or "on the host"
            severity = Severity.HIGH if on_disk else Severity.MEDIUM
            findings.append(
                self._finding(
                    "credential-exposure-path",
                    rel.id,
                    f"Credentials of {self.name(identity)} exposed on {self.name(host)}",
                    f"Credentials for the privileged identity {self.name(identity)} are present on {self.name(host)} "
                    f"({location}). Anyone who can log into or access {self.name(host)} has an unexpected path to "
                    f"{self.name(identity)}'s privileges: "
                    + ", ".join(self.name(u) for u in exposed_to[:10])
                    + (" ..." if len(exposed_to) > 10 else "")
                    + ".",
                    severity,
                    0.75 if on_disk else 0.6,
                    [identity, host, *exposed_to[:20]],
                    [EvidenceRef(kind="relationship", id=rel.id, note=f"credential placement: {location}")]
                    + [EvidenceRef(kind="object", id=u, note=f"can access {self.name(host)}") for u in exposed_to[:10]],
                    "Move the credential into a secret manager, rotate it, and restrict who can access the host.",
                    [
                        {"factor": "credential-on-host", "detail": str(location)},
                        {"factor": "exposed-to", "detail": f"{len(exposed_to)} principal(s)"},
                    ],
                )
            )
        return findings

    def _trusts(self) -> list[Finding]:
        findings = []
        trusts = sorted(
            (r for r in self.graph().all_edges.values() if r.relationship_type == "TRUSTS"), key=lambda r: r.id
        )
        by_source: dict[str, list[Relationship]] = {}
        for rel in trusts:
            by_source.setdefault(rel.source_object, []).append(rel)
        for rel in trusts:
            external = bool(rel.metadata.get("external")) or bool(self._meta(rel.target_object).get("external"))
            onward = [r for r in by_source.get(rel.target_object, []) if r.target_object != rel.source_object]
            if not external and not onward:
                continue
            chain = [rel.source_object, rel.target_object] + ([onward[0].target_object] if onward else [])
            findings.append(
                self._finding(
                    "risky-trust",
                    rel.id,
                    f"Risky trust: {self.name(rel.source_object)} trusts {self.name(rel.target_object)}",
                    "Trust chain "
                    + " → ".join(self.name(c) for c in chain)
                    + (
                        " reaches into an external realm."
                        if external
                        else " is transitive (two or more hops), so "
                        f"{self.name(chain[-1])} is implicitly trusted by {self.name(chain[0])}."
                    ),
                    Severity.MEDIUM,
                    0.7,
                    chain,
                    [EvidenceRef(kind="relationship", id=r.id, note="trust") for r in [rel, *onward[:1]]],
                    "Restrict the trust (selective authentication, SID filtering, scoped federation) or remove it.",
                    [{"factor": "external" if external else "transitive", "detail": " → ".join(chain)}],
                )
            )
        return findings
