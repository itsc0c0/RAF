"""Contextual asset exposure (raf-risk/1.0, model ``exposure``).

Exposure is *not* a CVSS sort. Each asset's score is the clamped sum of named factors computed
from the shared graph (documented in docs/risk-model.md):

* business criticality of the asset
* Internet exposure: directly reachable (one network hop from an external zone or flagged
  internet-facing) versus reachable only through other zones
* reachability from user workstations (the other common entry point)
* vulnerabilities on the asset or the services it runs (highest CVSS, exploit availability),
  discounted when no entry point can reach the asset
* who can obtain control (principals with a control path), whether such paths pass through
  privileged roles/identities or exposed credentials
* credentials and secrets stored on the asset
* stepping stone value: control paths from the asset to *other* critical assets
* mitigations: unreachable/isolated assets are discounted

The computation works on any :class:`GraphSource` exposing ``all_nodes``/``all_edges`` (the live
workspace loaded in memory, a snapshot, or a Ghost what-if model), so scores are comparable.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from pydantic import Field

from raf.core.graph.propagation import Hop, Propagator, Reached
from raf.core.graph.source import MemoryGraphSource
from raf.core.objects.models import RafModel, SecurityObject
from raf.core.objects.semantics import CONTROL, REACH, TRUST, explain, is_privileged
from raf.core.objects.types import Criticality, ObjectType
from raf.core.risk.model import RiskAssessment, RiskFactor, assess, factor

EXPOSURE_ASSET_TYPES = (ObjectType.HOST, ObjectType.SERVICE, ObjectType.CLOUD_RESOURCE, ObjectType.CONTAINER)
CRITICALITY_POINTS = {"critical": 25, "high": 15, "medium": 5, "low": 0}
_CRIT_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}
_CREDENTIAL_RELS = {"USES", "AUTHENTICATES_AS", "CONTAINS_SECRET"}
MAX_ENTRY_HOSTS = 200
MAX_PRINCIPALS = 300


class EntryPointReach(RafModel):
    id: str
    name: str
    kind: str  # internet | workstation
    hops: int
    path: list[str]


class Controller(RafModel):
    id: str
    name: str
    type: str
    confidence: float
    privileged: bool
    via_credentials: bool
    path: list[str]


class AssetExposure(RafModel):
    object: dict[str, Any]
    score: int
    level: str
    factors: list[RiskFactor]
    methodology: str
    internet: str  # direct | indirect | none
    entry_points: list[EntryPointReach] = Field(default_factory=list)
    vulnerabilities: list[dict[str, Any]] = Field(default_factory=list)
    controllers: list[Controller] = Field(default_factory=list)
    stepping_stone_to: list[dict[str, Any]] = Field(default_factory=list)
    secrets: list[str] = Field(default_factory=list)

    @property
    def assessment(self) -> RiskAssessment:
        return RiskAssessment(
            subject=self.object["id"],
            score=self.score,
            level=self.level,
            factors=self.factors,
            methodology=self.methodology,
        )


class ExposureMetrics(RafModel):
    """Aggregate numbers used by Ghost comparisons and dashboards.

    * ``entry_points`` - external zones, user workstations and users (phishable principals)
    * ``reachable_assets`` - assets any entry point can reach (network) or control (users)
    * ``attack_paths`` - (entry point, high/critical asset) pairs that are connected
    * ``critical_paths`` - pairs where a *critical* asset can be controlled: a user's control path,
      or network reach upgraded through an exploitable vulnerability
    * ``exposed_critical_assets`` - high/critical assets whose exposure level is HIGH or CRITICAL
    """

    entry_points: int
    reachable_assets: int
    exposed_critical_assets: int
    attack_paths: int
    critical_paths: int


def _crit(obj: SecurityObject | None) -> str | None:
    if obj is None:
        return None
    level = Criticality.of(obj.metadata, obj.tags)
    return level.value if level else None


def _name(objects: dict[str, SecurityObject], oid: str) -> str:
    obj = objects.get(oid)
    return obj.name if obj else oid.split(":", 1)[-1]


def _hop_privileged(hop: Hop, objects: dict[str, SecurityObject]) -> bool:
    rel = hop.relationship
    if rel is not None and rel.relationship_type == "ADMIN_OF":
        return True
    target = objects.get(hop.to)
    return bool(
        target
        and target.type in (ObjectType.ROLE, ObjectType.IDENTITY, ObjectType.GROUP)
        and is_privileged(target.type, target.metadata, target.tags)
    )


def _credential_hop(hop: Hop) -> bool:
    """Hops that obtain someone else's credentials (stored secrets, credential files, captured sessions)."""
    rel = hop.relationship
    if rel is None:
        return False
    if rel.relationship_type in _CREDENTIAL_RELS:
        return hop.forward
    return rel.relationship_type == "LOGGED_INTO" and not hop.forward


def _path_names(objects: dict[str, SecurityObject], start: str, reached: Reached) -> list[str]:
    return [_name(objects, start)] + [_name(objects, hop.to) for hop in reached.path if hop.relationship is not None]


class ExposureModel:
    """Computes explainable exposure for every asset of a graph."""

    def __init__(self, graph: MemoryGraphSource, *, max_depth: int = 8) -> None:
        self.graph = graph
        self.objects = graph.all_nodes
        self.max_depth = max_depth
        self.notes: list[str] = []
        out: dict[str, list[Any]] = defaultdict(list)
        inc: dict[str, list[Any]] = defaultdict(list)
        for rel in graph.all_edges.values():
            out[rel.source_object].append(rel)
            inc[rel.target_object].append(rel)
        self._out, self._in = out, inc
        self._entry_cache: dict[str, dict[str, Reached]] | None = None
        self._control_cache: dict[str, dict[str, Reached]] | None = None
        self._exploit_cache: dict[str, dict[str, Reached]] | None = None

    # ------------------------------------------------------------------ inputs
    def assets(self) -> list[SecurityObject]:
        return sorted((o for o in self.objects.values() if o.type in EXPOSURE_ASSET_TYPES), key=lambda o: o.id)

    def internet_zones(self) -> list[str]:
        zones = []
        for obj in self.objects.values():
            if obj.type != ObjectType.NETWORK:
                continue
            cidr = str(obj.metadata.get("cidr") or "")
            zone = str(obj.metadata.get("zone") or "").lower()
            if obj.id == "network:internet" or cidr in ("0.0.0.0/0", "::/0") or zone in ("external", "internet"):
                zones.append(obj.id)
        return sorted(zones)

    def workstations(self) -> list[str]:
        hosts = set()
        for obj in self.objects.values():
            if obj.type != ObjectType.HOST:
                continue
            role = str(obj.metadata.get("role") or "").lower()
            if role in ("workstation", "laptop", "desktop") or "workstation" in obj.tags:
                hosts.add(obj.id)
        for rels in self._out.values():
            for rel in rels:
                if (
                    rel.relationship_type == "OWNS"
                    and rel.source_object.startswith("user:")
                    and rel.target_object.startswith("host:")
                ):
                    hosts.add(rel.target_object)
        ordered = sorted(hosts)
        if len(ordered) > MAX_ENTRY_HOSTS:
            self.notes.append(f"workstation entry points sampled: {MAX_ENTRY_HOSTS} of {len(ordered)}")
            ordered = ordered[:MAX_ENTRY_HOSTS]
        return ordered

    def principals(self) -> list[str]:
        humans = sorted(o.id for o in self.objects.values() if o.type == ObjectType.USER)
        identities = sorted(o.id for o in self.objects.values() if o.type == ObjectType.IDENTITY)
        combined = humans + identities
        if len(combined) > MAX_PRINCIPALS:
            self.notes.append(f"control paths computed for {MAX_PRINCIPALS} of {len(combined)} principals")
            combined = combined[:MAX_PRINCIPALS]
        return combined

    def entry_reach(self) -> dict[str, dict[str, Reached]]:
        if self._entry_cache is None:
            cache = {}
            for entry in self.internet_zones() + self.workstations():
                cache[entry] = Propagator(
                    self.graph, max_depth=self.max_depth, min_confidence=0.05, upgrade_vulnerabilities=False
                ).run([entry], start_mode=REACH)
            self._entry_cache = cache
        return self._entry_cache

    def control_reach(self) -> dict[str, dict[str, Reached]]:
        if self._control_cache is None:
            cache = {}
            for principal in self.principals():
                reached = Propagator(
                    self.graph, max_depth=self.max_depth, min_confidence=0.2, upgrade_vulnerabilities=False
                ).run([principal])
                cache[principal] = {k: v for k, v in reached.items() if v.mode in (CONTROL, TRUST)}
            self._control_cache = cache
        return self._control_cache

    def components(self, asset: str) -> set[str]:
        """The asset plus what it runs or contains (its own parts)."""
        seen = {asset}
        stack = [asset]
        while stack:
            node = stack.pop()
            for rel in self._out.get(node, ()):
                if rel.relationship_type in ("RUNS", "CONTAINS") and rel.target_object not in seen:
                    seen.add(rel.target_object)
                    stack.append(rel.target_object)
        return seen

    def vulnerabilities(self, asset: str) -> list[dict[str, Any]]:
        targets = {asset}
        targets |= {r.target_object for r in self._out.get(asset, ()) if r.relationship_type == "RUNS"}
        found: dict[str, dict[str, Any]] = {}
        for target in targets:
            for rel in self._in.get(target, ()):
                if rel.relationship_type != "AFFECTS" or not rel.active_at(None):
                    continue
                vuln = self.objects.get(rel.source_object)
                if vuln is None or vuln.metadata.get("status") in ("fixed", "resolved", "patched"):
                    continue
                try:
                    cvss = float(vuln.metadata.get("cvss") or 0.0)
                except (TypeError, ValueError):
                    cvss = 0.0
                found[vuln.id] = {
                    "id": vuln.id,
                    "name": vuln.name,
                    "cvss": cvss,
                    "exploit_available": bool(vuln.metadata.get("exploit_available")),
                    "via": None if target == asset else target,
                    "summary": str(vuln.metadata.get("summary") or "")[:200],
                }
        return sorted(found.values(), key=lambda v: (-v["cvss"], v["id"]))

    # ------------------------------------------------------------------ assessment
    def assess(self, asset: SecurityObject) -> AssetExposure:
        objects = self.objects
        aid = asset.id
        crit = _crit(asset)
        factors: list[RiskFactor] = []
        if crit:
            points = CRITICALITY_POINTS[crit]
            if points:
                factors.append(factor("exposure.criticality", f"business criticality {crit}", points, [aid]))

        # entry point reachability (for environments: the best of what they contain)
        probe = [aid]
        if asset.type in (ObjectType.CLOUD_RESOURCE, ObjectType.CONTAINER):
            probe = sorted(self.components(aid))
        entries: list[EntryPointReach] = []
        internet = "none"
        internet_path: list[str] = []
        internet_zones = set(self.internet_zones())
        for entry, reached_map in self.entry_reach().items():
            best: tuple[int, str, Reached] | None = None
            for node in probe:
                reached = reached_map.get(node)
                if reached is None:
                    continue
                hops = sum(
                    1
                    for h in reached.path
                    if h.relationship is not None and h.relationship.relationship_type in ("CAN_REACH", "CONNECTED_TO")
                )
                if best is None or hops < best[0]:
                    best = (hops, node, reached)
            if best is None:
                continue
            hops, node, reached = best
            kind = "internet" if entry in internet_zones else "workstation"
            entries.append(
                EntryPointReach(
                    id=entry,
                    name=_name(objects, entry),
                    kind=kind,
                    hops=hops,
                    path=_path_names(objects, entry, reached),
                )
            )
            if kind == "internet":
                tier = "direct" if hops <= 1 else "indirect"
                if internet != "direct":
                    internet, internet_path = tier, _path_names(objects, entry, reached)
        if asset.metadata.get("internet_facing") is True:
            internet = "direct"
            internet_path = internet_path or ["Internet", asset.name]
        if internet == "direct":
            factors.append(
                factor(
                    "exposure.internet-direct",
                    "directly reachable from the Internet (" + " → ".join(internet_path) + ")",
                    20,
                    [aid],
                )
            )
        elif internet == "indirect":
            factors.append(
                factor(
                    "exposure.internet-indirect",
                    "reachable from the Internet through other zones (" + " → ".join(internet_path) + ")",
                    8,
                    [aid],
                )
            )
        workstations = [e for e in entries if e.kind == "workstation"]
        if workstations:
            factors.append(
                factor(
                    "exposure.workstation-reach",
                    f"network-reachable from {len(workstations)} user workstation(s)",
                    min(10, 2 * len(workstations)),
                    [e.id for e in workstations],
                )
            )

        # vulnerabilities, discounted when nothing can reach the asset
        vulns = self.vulnerabilities(aid)
        reachable = bool(entries)
        if vulns:
            top = vulns[0]
            points = min(20, round(top["cvss"] * 2))
            label = f"vulnerability {top['name']} (CVSS {top['cvss']:.1f})" + (
                f" on {_name(objects, top['via'])}" if top["via"] else ""
            )
            extra = min(6, 2 * (len(vulns) - 1))
            exploit = any(v["exploit_available"] for v in vulns)
            if not reachable:
                points, extra = points // 2, extra // 2
                label += " - halved: no entry point reaches this asset"
            factors.append(factor("exposure.vulnerability", label, points, [v["id"] for v in vulns]))
            if extra:
                factors.append(
                    factor(
                        "exposure.more-vulnerabilities",
                        f"{len(vulns) - 1} further vulnerabilities",
                        extra,
                        [v["id"] for v in vulns[1:]],
                    )
                )
            if exploit:
                factors.append(
                    factor(
                        "exposure.exploit",
                        "a public exploit is available" + ("" if reachable else " (asset unreachable: halved)"),
                        8 if reachable else 4,
                        [v["id"] for v in vulns if v["exploit_available"]],
                    )
                )

        # who can obtain control
        controllers: list[Controller] = []
        for principal, reached_map in self.control_reach().items():
            reached = reached_map.get(aid)
            if reached is None:
                continue
            privileged = any(_hop_privileged(h, objects) for h in reached.path)
            via_credentials = any(_credential_hop(h) for h in reached.path)
            controllers.append(
                Controller(
                    id=principal,
                    name=_name(objects, principal),
                    type=principal.split(":", 1)[0],
                    confidence=round(reached.confidence, 3),
                    privileged=privileged,
                    via_credentials=via_credentials,
                    path=_path_names(objects, principal, reached),
                )
            )
        controllers.sort(key=lambda c: (-c.confidence, c.id))
        humans = [c for c in controllers if c.type == "user"]
        if humans:
            factors.append(
                factor(
                    "exposure.controllers",
                    f"{len(humans)} user(s) can obtain control (" + ", ".join(c.name for c in humans[:5]) + ")",
                    min(15, 3 * len(humans)),
                    [c.id for c in humans],
                )
            )
        credential_paths = [c for c in controllers if c.via_credentials]
        if credential_paths:
            sample = next((c for c in credential_paths if c.type == "user"), credential_paths[0])
            factors.append(
                factor(
                    "exposure.credential-path",
                    f"control is obtainable through exposed credentials (e.g. {' → '.join(sample.path)})",
                    5,
                    [c.id for c in credential_paths],
                )
            )

        # credentials and secrets stored on the asset
        secrets: list[str] = []
        stored_identities = []
        for rel in self._out.get(aid, ()):
            if rel.relationship_type == "USES" and rel.target_object.startswith(("identity:", "user:")):
                ident = objects.get(rel.target_object)
                if ident is not None and (
                    is_privileged(ident.type, ident.metadata, ident.tags) or self._holds_privileged_role(ident.id)
                ):
                    stored_identities.append(ident.id)
        for comp in self.components(aid):
            for rel in self._out.get(comp, ()):
                if rel.relationship_type == "CONTAINS_SECRET":
                    secrets.append(rel.target_object)
        if stored_identities:
            factors.append(
                factor(
                    "exposure.privileged-credentials",
                    "credentials of privileged identities stored "
                    "here: " + ", ".join(_name(objects, i) for i in stored_identities),
                    min(15, 10 * len(stored_identities)),
                    stored_identities,
                )
            )
        if secrets:
            factors.append(
                factor(
                    "exposure.secrets",
                    f"{len(secrets)} secret(s) stored on this asset",
                    min(10, 5 * len(secrets)),
                    secrets,
                )
            )

        # stepping stone: control paths to other critical assets
        stepping: list[dict[str, Any]] = []
        if asset.type in (ObjectType.HOST, ObjectType.SERVICE, ObjectType.CONTAINER):
            own = self.components(aid)
            reached_map = Propagator(
                self.graph, max_depth=self.max_depth, min_confidence=0.2, upgrade_vulnerabilities=False
            ).run([aid])
            for node, reached in sorted(reached_map.items()):
                if node in own or reached.mode not in (CONTROL, TRUST):
                    continue
                target = objects.get(node)
                if target is None or target.type not in EXPOSURE_ASSET_TYPES or _crit(target) != "critical":
                    continue
                stepping.append(
                    {
                        "id": node,
                        "name": target.name,
                        "confidence": round(reached.confidence, 3),
                        "path": _path_names(objects, aid, reached),
                        "why": [
                            explain(
                                h.why,
                                _name(objects, h.frm),
                                _name(objects, h.to),
                                h.relationship.metadata if h.relationship else None,
                            )
                            for h in reached.path
                        ],
                    }
                )
            listed = {s["id"] for s in stepping}
            stepping = [
                s for s in stepping if not (s["id"].startswith("service:") and self._host_of(s["id"]) in listed)
            ]
            if stepping:
                factors.append(
                    factor(
                        "exposure.stepping-stone",
                        "control path to critical asset(s): " + ", ".join(s["name"] for s in stepping[:4]),
                        min(15, 8 * len(stepping)),
                        [s["id"] for s in stepping],
                    )
                )

        # mitigation: nothing reaches it
        if not reachable and asset.type in (ObjectType.HOST, ObjectType.SERVICE):
            zone = next(
                (
                    objects[r.target_object]
                    for r in self._out.get(aid, ())
                    if r.relationship_type == "MEMBER_OF"
                    and r.target_object in objects
                    and objects[r.target_object].type == ObjectType.NETWORK
                ),
                None,
            )
            detail = f" (zone {zone.name}: {zone.metadata.get('zone')})" if zone and zone.metadata.get("zone") else ""
            factors.append(factor("exposure.isolated", f"not reachable from any entry point{detail}", -15, [aid]))
        assessment = assess(aid, factors)
        return AssetExposure(
            object={"id": aid, "name": asset.name, "type": asset.type, "criticality": crit},
            score=assessment.score,
            level=assessment.level,
            factors=assessment.factors,
            methodology=assessment.methodology,
            internet=internet,
            entry_points=entries,
            vulnerabilities=vulns,
            controllers=controllers[:50],
            stepping_stone_to=stepping,
            secrets=sorted(secrets),
        )

    def _host_of(self, service: str) -> str | None:
        return next((r.source_object for r in self._in.get(service, ()) if r.relationship_type == "RUNS"), None)

    def _holds_privileged_role(self, principal: str) -> bool:
        seen = {principal}
        stack = [principal]
        while stack:
            node = stack.pop()
            for rel in self._out.get(node, ()):
                if rel.relationship_type not in ("MEMBER_OF", "HAS_ROLE") or rel.target_object in seen:
                    continue
                target = self.objects.get(rel.target_object)
                if (
                    target is not None
                    and target.type == ObjectType.ROLE
                    and is_privileged(target.type, target.metadata, target.tags)
                ):
                    return True
                seen.add(rel.target_object)
                stack.append(rel.target_object)
        return False

    def assess_all(self) -> list[AssetExposure]:
        results = [self.assess(asset) for asset in self.assets()]
        return sorted(
            results, key=lambda r: (-r.score, -_CRIT_RANK.get(r.object["criticality"] or "", -1), r.object["id"])
        )

    def exploit_reach(self) -> dict[str, dict[str, Reached]]:
        """Network entry points with vulnerability upgrades enabled (reach can become control)."""
        if self._exploit_cache is None:
            cache = {}
            for entry in self.entry_reach():
                cache[entry] = Propagator(
                    self.graph, max_depth=self.max_depth, min_confidence=0.05, upgrade_vulnerabilities=True
                ).run([entry], start_mode=REACH)
            self._exploit_cache = cache
        return self._exploit_cache

    def attack_pairs(self) -> tuple[set[tuple[str, str]], set[tuple[str, str]]]:
        """(entry, asset) pairs: all high/critical assets an entry point can reach or control, and
        the subset where a *critical* asset can be controlled (user control paths, or network reach
        upgraded through an exploitable vulnerability)."""
        objects = self.objects
        high = {a.id for a in self.assets() if _crit(a) in ("high", "critical")}
        critical = {a.id for a in self.assets() if _crit(a) == "critical"}
        pairs: set[tuple[str, str]] = set()
        critical_pairs: set[tuple[str, str]] = set()
        for entry, reached in self.entry_reach().items():
            pairs |= {(entry, node) for node in reached if node in high}
        for entry, reached in self.exploit_reach().items():
            critical_pairs |= {
                (entry, node) for node, r in reached.items() if node in critical and r.mode in (CONTROL, TRUST)
            }
        for principal, reached in self.control_reach().items():
            obj = objects.get(principal)
            if obj is None or obj.type != ObjectType.USER:
                continue
            pairs |= {(principal, node) for node in reached if node in high}
            critical_pairs |= {(principal, node) for node in reached if node in critical}
        return pairs, critical_pairs

    def user_control(self) -> dict[str, list[str]]:
        """High/critical assets each user can obtain control of."""
        high = {a.id for a in self.assets() if _crit(a) in ("high", "critical")}
        out = {}
        for principal, reached in self.control_reach().items():
            if principal.startswith("user:"):
                out[principal] = sorted(node for node in reached if node in high)
        return out

    def metrics(self, results: list[AssetExposure] | None = None) -> ExposureMetrics:
        results = results if results is not None else self.assess_all()
        assets = {a.id for a in self.assets()}
        reachable = {node for reached in self.entry_reach().values() for node in reached}
        users = [p for p in self.control_reach() if p.startswith("user:")]
        reachable |= {node for p in users for node in self.control_reach()[p]}
        pairs, critical_pairs = self.attack_pairs()
        exposed = sum(
            1 for r in results if r.object["criticality"] in ("high", "critical") and r.level in ("HIGH", "CRITICAL")
        )
        return ExposureMetrics(
            entry_points=len(self.entry_reach()) + len(users),
            reachable_assets=len(reachable & assets),
            exposed_critical_assets=exposed,
            attack_paths=len(pairs),
            critical_paths=len(critical_pairs),
        )
