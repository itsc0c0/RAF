"""R$F Policy application service: import, analyze, evaluate and compare policies.

Imported policies live in the shared graph as ``policy`` objects whose metadata carries the
normalized policy (``metadata.policy``) plus a content digest, so snapshots, Diff and Ghost see
policy changes like any other state change. ``APPLIES_TO`` relationships link a policy to the
workspace objects it references.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from pydantic import Field, ValidationError

from raf.core.context.app import RafContext
from raf.core.errors import InvalidInputError, NotFoundError
from raf.core.ids import object_id
from raf.core.ingestion.pipeline import IngestionPipeline, IngestOptions, IngestReport
from raf.core.jobs.manager import JobContext
from raf.core.objects.models import RafModel
from raf.core.ports import ANY, PortSet
from raf.core.snapshots.service import resolve_state
from raf.products.policy.engine import (
    RULES,
    PartVerdict,
    PolicyAnalysis,
    PolicyDiff,
    PolicyWorld,
    analyze_set,
    diff_sets,
    evaluate_identity,
    evaluate_network,
    policies_of,
)
from raf.products.policy.formats import load_policy_path
from raf.products.policy.model import Policy, PolicySet
from raf.products.policy.parser import policy_object_record

log = logging.getLogger("raf.products.policy")

PRODUCT = "policy"
NETWORK_ONLY_VERBS = ("reach", "connect")
GENERIC_VERBS = ("access", "reach", "connect")
PIVOT_PORTS = ("tcp/22", "tcp/3389", "tcp/5985")
_PORT_VERBS = {
    "ssh": "tcp/22",
    "rdp": "tcp/3389",
    "https": "tcp/443",
    "http": "tcp/80",
    "dns": "udp/53",
    "ldap": "tcp/389",
    "ldaps": "tcp/636",
    "smb": "tcp/445",
    "postgres": "tcp/5432",
    "winrm": "tcp/5985",
}
_UDP_PROTOCOLS = ("udp", "dns", "openvpn", "syslog", "snmp", "ntp")


class PathLeg(RafModel):
    source: str
    target: str
    ports: list[str]
    rules: list[str]


class IndirectPath(RafModel):
    pivot: str
    pivot_name: str
    legs: list[PathLeg]
    summary: str


class Evaluation(RafModel):
    subject: dict[str, Any]
    target: dict[str, Any]
    verb: str
    action: str | None
    requested_ports: list[str]
    decision: str  # allow | deny | not-evaluated
    reason: str
    parts: list[PartVerdict] = Field(default_factory=list)
    network_sources: list[str] = Field(default_factory=list)
    indirect: list[IndirectPath] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class ImportResult(RafModel):
    policies: list[dict[str, Any]]
    job: str | None
    report: IngestReport | None = None
    warnings: list[str] = Field(default_factory=list)


def policy_from_object(metadata: dict[str, Any]) -> Policy | None:
    raw = metadata.get("policy")
    if not isinstance(raw, dict):
        return None
    try:
        return Policy.model_validate(raw)
    except ValidationError as exc:
        log.warning("stored policy is invalid: %s", exc.errors()[:1])
        return None


class PolicyService:
    def __init__(self, ctx: RafContext, *, world: PolicyWorld | None = None) -> None:
        self.ctx = ctx
        self._world = world

    def world(self) -> PolicyWorld:
        if self._world is None:
            self._world = PolicyWorld.from_store(self.ctx.store)
        return self._world

    # ------------------------------------------------------------------ stored policies
    def stored(self) -> list[Policy]:
        policies = []
        for obj in self.ctx.store.objects.iter_all(types=["policy"]):
            if obj.valid_to is not None:
                continue
            policy = policy_from_object(obj.metadata)
            if policy is not None:
                policies.append(policy)
        return sorted(policies, key=lambda p: p.id)

    def require_stored(self) -> list[Policy]:
        policies = self.stored()
        if not policies:
            raise NotFoundError(
                "No policies have been imported into this workspace.",
                suggestions=["raf policy import fixtures/policies/raven-policies.json", "raf policy check <file>"],
            )
        return policies

    def get(self, ref: str) -> Policy:
        wanted = ref.strip().lower()
        for policy in self.stored():
            if wanted in (policy.id, policy.object_id, policy.name.lower()):
                return policy
        raise NotFoundError(f"Policy '{ref}' is not in this workspace.", suggestions=["raf policy list"])

    # ------------------------------------------------------------------ import
    def _records(self, policies: list[Policy], source_label: str) -> list[dict[str, Any]]:
        world = self.world()
        records: list[dict[str, Any]] = []
        for policy in policies:
            records.append(policy_object_record(policy, source_label))
            referenced = sorted({s for r in policy.rules for s in [*r.sources, *r.destinations] if s in world.objects})
            for target in referenced[:500]:
                records.append(
                    {
                        "kind": "relationship",
                        "source": policy.object_id,
                        "type": "APPLIES_TO",
                        "target": target,
                        "confidence": 1.0,
                    }
                )
        return records

    def import_sets(self, sets: list[PolicySet], *, source_label: str) -> ImportResult:
        policies = policies_of(sets)
        if not policies:
            raise InvalidInputError("No policies found to import.")
        records = self._records(policies, source_label)

        def work(jc: JobContext) -> dict[str, Any]:
            pipeline = IngestionPipeline(self.ctx, job=jc)
            report = pipeline.ingest_records(
                records, source_name=f"policy:{source_label}", options=IngestOptions(), label="raf-policy/1.0"
            )
            return report.to_json_dict()

        job = self.ctx.jobs.run_inline(
            "import",
            f"Import policies from {source_label}",
            {"source": source_label, "policies": [p.id for p in policies]},
            work,
        )
        report = IngestReport.model_validate(job.result) if job.result else None
        summaries = [
            {
                "id": p.id,
                "object_id": p.object_id,
                "name": p.name,
                "domain": p.domain,
                "rules": len(p.rules),
                "revision": p.revision,
                "digest": p.digest(),
            }
            for p in policies
        ]
        self.ctx.audit.record(
            "policy.import",
            affected=[p.object_id for p in policies],
            result=job.status.value.lower(),
            details={"source": source_label, "job": job.id, "policies": len(policies)},
        )
        warnings = [w for s in sets for w in s.warnings]
        return ImportResult(policies=summaries, job=job.id, report=report, warnings=warnings)

    def import_path(self, path: Path, *, principal: str | None = None, host: str | None = None) -> ImportResult:
        sets = load_policy_path(path, principal=principal, host=host)
        return self.import_sets(sets, source_label=path.name)

    # ------------------------------------------------------------------ analysis
    def analyze(self, policies: list[Policy] | None = None, *, persist: bool = True) -> PolicyAnalysis:
        targets = policies if policies is not None else self.require_stored()
        analysis = analyze_set(self.world(), targets)
        if persist:
            self.ctx.store.findings.upsert(analysis.findings)
            resolved = self.ctx.store.findings.resolve_absent(PRODUCT, list(RULES), [f.id for f in analysis.findings])
            if resolved:
                analysis.warnings.append(f"{resolved} earlier policy finding(s) no longer apply and were resolved")
            self.ctx.audit.record(
                "policy.analyze", affected=[p.object_id for p in targets], details={"findings": len(analysis.findings)}
            )
        return analysis

    def check(
        self, path: Path, *, principal: str | None = None, host: str | None = None
    ) -> tuple[list[PolicySet], PolicyAnalysis]:
        sets = load_policy_path(path, principal=principal, host=host)
        analysis = analyze_set(self.world(), policies_of(sets))
        analysis.warnings += [w for s in sets for w in s.warnings]
        return sets, analysis

    # ------------------------------------------------------------------ evaluation
    def _requested(self, verb: str, target: str, ports: list[str]) -> PortSet:
        if ports:
            return PortSet.parse(ports)
        if verb in _PORT_VERBS:
            return PortSet.parse([_PORT_VERBS[verb]])
        obj = self.world().objects.get(target)
        if obj is not None and obj.type == "service" and obj.metadata.get("port"):
            proto = "udp" if str(obj.metadata.get("protocol", "")).lower() in _UDP_PROTOCOLS else "tcp"
            return PortSet.parse([f"{proto}/{obj.metadata['port']}"])
        return PortSet.everything()

    def evaluate(
        self,
        subject: str,
        verb: str,
        target: str,
        *,
        ports: list[str] | None = None,
        source_hosts: list[str] | None = None,
        policies: list[Policy] | None = None,
    ) -> Evaluation:
        verb = verb.strip().lower()
        if not verb or len(verb) > 64:
            raise InvalidInputError("Give an action such as access, reach, ssh, admin or deploy.")
        world = self.world()
        policies = policies if policies is not None else self.require_stored()
        requested = self._requested(verb, target, ports or [])
        action = None if verb in GENERIC_VERBS else verb
        stype, ttype = subject.split(":", 1)[0], target.split(":", 1)[0]
        is_principal = stype in ("user", "identity", "group", "role")
        addressable_subject = stype in ("host", "ip", "network", "service")
        addressable_target = ttype in ("host", "ip", "network", "service")
        has_network = any(p.domain == "network" for p in policies)
        notes: list[str] = []
        parts: list[PartVerdict] = []
        sources: list[str] = list(source_hosts or [])
        if not sources:
            if addressable_subject:
                sources = [subject]
            elif is_principal:
                sources = list(world.owned_hosts.get(subject, [])) or world.source_hosts(subject)[:5]
        network_verdicts: dict[str, list[PartVerdict]] = {}
        if has_network and addressable_target:
            if not sources:
                notes.append(
                    f"No source host is known for {world.name(subject)} (no owned device, session or "
                    "credential placement); the network check was skipped. Use --from HOST."
                )
            for source in sources:
                network_verdicts[source] = evaluate_network(world, policies, source, target, requested)
        elif has_network and not addressable_target:
            notes.append(f"{world.name(target)} has no network address; only access policies apply.")
        network_ok: bool | None = None
        chosen_source: str | None = None
        if network_verdicts:
            allowed_sources = [s for s, vs in network_verdicts.items() if vs and all(v.decision == "allow" for v in vs)]
            network_ok = bool(allowed_sources)
            chosen_source = allowed_sources[0] if allowed_sources else next(iter(network_verdicts))
            parts.extend(network_verdicts[chosen_source])
            if not network_verdicts[chosen_source]:
                notes.append("No network policy governs this flow (all policies are scoped elsewhere).")
                network_ok = None
        identity_ok: bool | None = None
        if is_principal and verb not in NETWORK_ONLY_VERBS:
            verdict = evaluate_identity(world, policies, subject, target, action)
            if verdict is not None and verdict.decision != "allow":
                for identity in sorted(world.identities_of.get(subject, ())):
                    alternative = evaluate_identity(world, policies, identity, target, action)
                    if alternative is not None and alternative.decision == "allow":
                        alternative.explanation.insert(
                            0, f"{world.name(subject)} can use the identity {world.name(identity)} (HAS_IDENTITY)"
                        )
                        verdict = alternative
                        break
            if verdict is not None:
                parts.append(verdict)
                identity_ok = verdict.decision == "allow"
        evaluated = [ok for ok in (network_ok, identity_ok) if ok is not None]
        if not evaluated:
            decision = "not-evaluated"
            reason = "No applicable policy: import network and/or access policies (raf policy import)."
        else:
            decision = "allow" if all(evaluated) else "deny"
            reason = self._reason(parts, decision)
        indirect: list[IndirectPath] = []
        if network_ok is False and is_principal and has_network:
            indirect = self._indirect(world, policies, subject, sources, target, requested)
            if indirect:
                notes.append(
                    "An indirect network path exists through hosts the subject can log into; the direct "
                    "decision does not reflect it."
                )
        subject_obj, target_obj = world.objects.get(subject), world.objects.get(target)
        return Evaluation(
            subject={"id": subject, "name": world.name(subject), "type": stype, "known": subject_obj is not None},
            target={"id": target, "name": world.name(target), "type": ttype, "known": target_obj is not None},
            verb=verb,
            action=action,
            requested_ports=requested.labels(),
            decision=decision,
            reason=reason,
            parts=parts,
            network_sources=sources if network_verdicts else [],
            indirect=indirect,
            notes=notes,
        )

    @staticmethod
    def _reason(parts: list[PartVerdict], decision: str) -> str:
        pieces = []
        for part in parts:
            decisive = [d for d in part.decisions if d.effect == part.decision] or part.decisions
            refs = ", ".join(f"{d.policy} {d.rule or 'default'}" for d in decisive[:3])
            pieces.append(f"{part.part}: {part.decision} ({refs})")
        return ("ALLOW - " if decision == "allow" else "DENY - ") + "; ".join(pieces)

    def _indirect(
        self,
        world: PolicyWorld,
        policies: list[Policy],
        subject: str,
        sources: list[str],
        target: str,
        requested: PortSet,
    ) -> list[IndirectPath]:
        candidates = list(world.source_hosts(subject))
        for host, _r in self._identity_hosts(world, policies, subject):
            if host not in candidates:
                candidates.append(host)
        results: list[IndirectPath] = []
        pivot_ports = PortSet.parse(list(PIVOT_PORTS))
        for pivot in candidates:
            if pivot == target or pivot in sources:
                continue
            first = None
            for source in sources:
                verdicts = evaluate_network(world, policies, source, pivot, pivot_ports)
                if verdicts and all(v.decision == "allow" for v in verdicts):
                    first = (source, verdicts)
                    break
            if first is None:
                continue
            second = evaluate_network(world, policies, pivot, target, requested)
            if not second or not all(v.decision == "allow" for v in second):
                continue
            source, leg1 = first
            legs = [
                PathLeg(
                    source=source,
                    target=pivot,
                    ports=_intersection(leg1),
                    rules=[f"{d.policy}:{d.rule}" for v in leg1 for d in v.decisions if d.effect == "allow" and d.rule],
                ),
                PathLeg(
                    source=pivot,
                    target=target,
                    ports=_intersection(second),
                    rules=[
                        f"{d.policy}:{d.rule}" for v in second for d in v.decisions if d.effect == "allow" and d.rule
                    ],
                ),
            ]
            summary = (
                f"{world.name(source)} → {world.name(pivot)} ({', '.join(legs[0].ports)} via "
                f"{', '.join(legs[0].rules) or 'default'}) → {world.name(target)} ({', '.join(legs[1].ports)} "
                f"via {', '.join(legs[1].rules) or 'default'})"
            )
            results.append(IndirectPath(pivot=pivot, pivot_name=world.name(pivot), legs=legs, summary=summary))
            if len(results) >= 5:
                break
        return results

    @staticmethod
    def _identity_hosts(world: PolicyWorld, policies: list[Policy], subject: str) -> list[tuple[str, str]]:
        """Hosts the subject may log into according to access policies (host resources with login actions)."""
        closure = world.principal_closure(subject)
        out = []
        for policy in policies:
            if policy.domain == "network":
                continue
            for rule in policy.active_rules():
                if rule.effect != "allow" or not any(s == "*" or s in closure for s in rule.sources):
                    continue
                if not any(a in ("*", "ssh", "rdp", "admin", "login") or a.startswith("ssh") for a in rule.actions):
                    continue
                for resource in rule.destinations:
                    if resource.startswith("host:") and "*" not in resource:
                        out.append((resource, rule.id))
        return out

    # ------------------------------------------------------------------ revisions
    def load_ref(self, ref: str, *, files: bool = True) -> tuple[str, list[Policy]]:
        """A policy file/directory (only with ``files``), ``current``, a snapshot name, or a state provider ref."""
        path = Path(ref)
        if files and path.exists():
            return path.name, policies_of(load_policy_path(path))
        state = resolve_state(self.ctx, ref)
        ids = {k: h for k, h in state.hashes.get("object", {}).items() if k.startswith("policy:")}
        bodies = state.body(list(ids.values()))
        policies = []
        for digest in ids.values():
            body = bodies.get(digest)
            if body and body.get("active", True):
                policy = policy_from_object(body.get("metadata") or {})
                if policy is not None:
                    policies.append(policy)
        return state.label, sorted(policies, key=lambda p: p.id)

    def diff(self, before_ref: str, after_ref: str, *, files: bool = True) -> PolicyDiff:
        """Compare two revisions; ``files=False`` (the API) resolves workspace states only, never local paths."""
        before_label, before = self.load_ref(before_ref, files=files)
        after_label, after = self.load_ref(after_ref, files=files)
        if not before and not after:
            raise NotFoundError(
                "Neither side contains policies.",
                suggestions=["raf policy diff fixtures/policies/raven-policies-2026-09.json current"],
            )
        return diff_sets(self.world(), before, after, before_label=before_label, after_label=after_label)


def _intersection(verdicts: list[PartVerdict]) -> list[str]:
    allowed: PortSet | None = None
    for verdict in verdicts:
        ports = PortSet.parse(verdict.allowed_ports) if verdict.allowed_ports else PortSet.empty()
        allowed = ports if allowed is None else allowed.intersect(ports)
    return allowed.labels() if allowed is not None else []


def resolve_endpoint(ctx: RafContext, ref: str) -> str:
    """Resolve a CLI/API reference; bare CIDRs/IPs become ip:/cidr selectors evaluated by address."""
    text = ref.strip()
    if text.lower() in (ANY, "internet"):
        return object_id("network", "internet")
    return ctx.resolve(text).id


__all__ = ["Evaluation", "ImportResult", "PolicyService", "resolve_endpoint"]
