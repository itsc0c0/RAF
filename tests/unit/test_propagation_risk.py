"""Traversal semantics, Pareto-front propagation and the explainable risk model."""

from __future__ import annotations

from datetime import UTC, datetime

from raf.core.graph.propagation import Propagator
from raf.core.graph.source import MemoryGraphSource
from raf.core.ids import relationship_id
from raf.core.objects.models import Relationship, SecurityObject
from raf.core.objects.semantics import CONTROL, REACH, traversals
from raf.core.risk.exposure import ExposureModel
from raf.core.risk.model import assess, factor, level_for

NOW = datetime(2026, 10, 7, tzinfo=UTC)


def _obj(oid: str, **metadata: object) -> SecurityObject:
    return SecurityObject(
        id=oid,
        type=oid.split(":", 1)[0],
        name=oid.split(":", 1)[1],
        created_at=NOW,
        updated_at=NOW,
        metadata=dict(metadata),
    )


def _rel(source: str, rtype: str, target: str, confidence: float = 1.0, **metadata: object) -> Relationship:
    return Relationship(
        id=relationship_id(source, rtype, target),
        relationship_type=rtype,
        source_object=source,
        target_object=target,
        confidence=confidence,
        created_at=NOW,
        updated_at=NOW,
        metadata=dict(metadata),
    )


def test_semantics_reach_never_grants_control() -> None:
    fwd, rev = traversals("CAN_REACH", "network", "network")
    assert fwd is not None and fwd.mode == REACH and rev is None
    fwd, rev = traversals("LOGGED_INTO", "user", "host")
    assert fwd is not None and fwd.mode == CONTROL and rev is not None and rev.factor < fwd.factor
    assert traversals("RESOLVES_TO", "domain", "ip") == (None, None)


def test_pareto_front_keeps_short_weak_path() -> None:
    """A long high-confidence path must not hide a short low-confidence path that can still extend."""
    nodes = [_obj(f"identity:{n}") for n in ("start", "a1", "a2", "a3", "mid", "goal")]
    rels = [
        # long, strong: start -> a1 -> a2 -> a3 -> mid
        _rel("identity:start", "CAN_ASSUME", "identity:a1"),
        _rel("identity:a1", "CAN_ASSUME", "identity:a2"),
        _rel("identity:a2", "CAN_ASSUME", "identity:a3"),
        _rel("identity:a3", "CAN_ASSUME", "identity:mid"),
        # short, weaker: start -> mid
        _rel("identity:start", "CAN_ACCESS", "identity:mid", confidence=0.4),
        _rel("identity:mid", "CAN_ASSUME", "identity:goal"),
    ]
    graph = MemoryGraphSource(nodes, rels)
    reached = Propagator(graph, max_depth=3, min_confidence=0.1).run(["identity:start"])
    assert "identity:goal" in reached  # only reachable within depth 3 through the short path
    assert reached["identity:goal"].depth == 2


def test_vulnerability_upgrades_reach_to_control_and_disabled_identities_stop() -> None:
    nodes = [
        _obj("network:internet"),
        _obj("network:dmz"),
        _obj("host:vpn"),
        _obj("vulnerability:sim-1", cvss=9.8, exploit_available=True),
        _obj("identity:svc", disabled=True),
        _obj("host:db"),
    ]
    rels = [
        _rel("network:internet", "CAN_REACH", "network:dmz"),
        _rel("host:vpn", "MEMBER_OF", "network:dmz"),
        _rel("vulnerability:sim-1", "AFFECTS", "host:vpn"),
        _rel("host:vpn", "USES", "identity:svc"),
        _rel("identity:svc", "ADMIN_OF", "host:db"),
    ]
    graph = MemoryGraphSource(nodes, rels)
    reached = Propagator(graph, max_depth=6, min_confidence=0.05).run(["network:internet"], start_mode=REACH)
    assert reached["host:vpn"].mode == CONTROL and reached["host:vpn"].via_vulnerability == "vulnerability:sim-1"
    assert "identity:svc" not in reached and "host:db" not in reached  # disabled identity blocks control
    no_upgrade = Propagator(graph, max_depth=6, upgrade_vulnerabilities=False).run(
        ["network:internet"], start_mode=REACH
    )
    assert no_upgrade["host:vpn"].mode == REACH


def test_risk_model_is_clamped_and_ordered() -> None:
    result = assess("host:x", [factor("a", "raises", 70), factor("b", "lowers", -10), factor("c", "more", 60)])
    assert result.score == 100 and result.level == "CRITICAL"
    assert [f.sign for f in result.factors] == ["+", "+", "-"]
    assert level_for(24) == "LOW" and level_for(25) == "MEDIUM" and level_for(50) == "HIGH"
    assert assess("host:y", [factor("d", "lowers", -40)]).score == 0


def test_exposure_context_beats_cvss() -> None:
    """Internet-facing + critical + reachable outranks an isolated host with a higher CVSS."""
    nodes = [
        _obj("network:internet", cidr="0.0.0.0/0", zone="external"),
        _obj("network:dmz", cidr="10.40.0.0/16"),
        _obj("network:lab", cidr="10.50.0.0/16", zone="isolated-lab"),
        _obj("host:vpn-01", criticality="high", internet_facing=True),
        _obj("host:lab-01", criticality="low"),
        _obj("vulnerability:v1", cvss=8.1),
        _obj("vulnerability:v2", cvss=9.9, exploit_available=True),
    ]
    rels = [
        _rel("network:internet", "CAN_REACH", "network:dmz"),
        _rel("host:vpn-01", "MEMBER_OF", "network:dmz"),
        _rel("host:lab-01", "MEMBER_OF", "network:lab"),
        _rel("vulnerability:v1", "AFFECTS", "host:vpn-01"),
        _rel("vulnerability:v2", "AFFECTS", "host:lab-01"),
    ]
    model = ExposureModel(MemoryGraphSource(nodes, rels))
    ranked = {r.object["id"]: r for r in model.assess_all()}
    vpn, lab = ranked["host:vpn-01"], ranked["host:lab-01"]
    assert vpn.score > lab.score and vpn.internet == "direct" and lab.internet == "none"
    assert any(f.rule == "exposure.isolated" and f.sign == "-" for f in lab.factors)
    assert all(f.label for f in vpn.factors)
