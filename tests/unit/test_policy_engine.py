"""Policy normalization, zone semantics, first-match port evaluation and rule anomalies."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from raf.core.errors import InvalidInputError
from raf.core.objects.models import Relationship, SecurityObject
from raf.data import raven
from raf.products.policy.engine import (
    PolicyWorld,
    address_set,
    analyze_set,
    diff_sets,
    element_for,
    evaluate_identity,
    evaluate_network,
    set_covers,
)
from raf.products.policy.formats import parse_native, parse_policy_text, sniff_policy
from raf.products.policy.model import PortSet, normalize_address, normalize_ports

NOW = datetime(2026, 10, 7, tzinfo=UTC)


def _obj(oid: str, **metadata: object) -> SecurityObject:
    otype, key = oid.split(":", 1)
    return SecurityObject(id=oid, type=otype, name=key.upper() if otype in ("host", "network") else key,
                          created_at=NOW, updated_at=NOW, metadata=dict(metadata))


def _rel(source: str, rtype: str, target: str) -> Relationship:
    from raf.core.ids import relationship_id

    return Relationship(id=relationship_id(source, rtype, target), relationship_type=rtype, source_object=source,
                        target_object=target, created_at=NOW, updated_at=NOW)


@pytest.fixture
def world() -> PolicyWorld:
    objects = [
        _obj("network:internet", cidr="0.0.0.0/0", zone="external"),
        _obj("network:corp", cidr="10.10.0.0/16"),
        _obj("network:dev", cidr="10.20.0.0/16"),
        _obj("network:prod", cidr="10.30.0.0/16", criticality="high"),
        _obj("host:ws-01", ip="10.10.1.21"),
        _obj("host:dev-01", ip="10.20.0.11"),
        _obj("host:db-01", ip="10.30.0.10", criticality="critical"),
        _obj("user:alice"), _obj("group:engineering"), _obj("role:developer"),
        _obj("cloud_resource:production", criticality="critical"),
    ]
    rels = [
        _rel("host:ws-01", "MEMBER_OF", "network:corp"), _rel("host:dev-01", "MEMBER_OF", "network:dev"),
        _rel("host:db-01", "MEMBER_OF", "network:prod"), _rel("user:alice", "OWNS", "host:ws-01"),
        _rel("user:alice", "MEMBER_OF", "group:engineering"), _rel("group:engineering", "HAS_ROLE", "role:developer"),
        _rel("cloud_resource:production", "CONTAINS", "host:db-01"),
    ]
    return PolicyWorld(objects, rels)


def test_port_set_arithmetic() -> None:
    web = PortSet.parse(["tcp/443", "tcp/80"])
    assert web.labels() == ["tcp/80", "tcp/443"]
    assert PortSet.parse(["any"]).is_everything() and PortSet.parse(["any"]).covers(web)
    assert not web.covers(PortSet.parse(["tcp/22"]))
    rest = PortSet.parse(["tcp/1-1024"]).subtract(web)
    assert rest.labels() == ["tcp/1-79", "tcp/81-442", "tcp/444-1024"]
    assert PortSet.parse(["ssh", "dns"]).labels() == ["tcp/22", "udp/53"]
    assert normalize_ports(["TCP/443", "443"]) == ["tcp/443"]
    with pytest.raises(InvalidInputError):
        PortSet.parse(["tcp/70000"])


def test_selector_normalization() -> None:
    assert normalize_address("0.0.0.0/0") == "any"
    assert normalize_address("10.20.0.0/16") == "cidr:10.20.0.0/16"
    assert normalize_address("CORP") == "network:corp"
    assert normalize_address("host:DB-01") == "host:db-01"


def test_zone_semantics_internet_does_not_cover_internal(world: PolicyWorld) -> None:
    internet = address_set(world, ["network:internet"])
    corp = address_set(world, ["network:corp"])
    assert not set_covers(internet, corp)
    assert set_covers(address_set(world, ["network:prod"]), address_set(world, ["host:db-01"]))
    assert set_covers(address_set(world, ["cidr:10.0.0.0/8"]), corp)
    ext = element_for(world, "ip:203.0.113.45")
    assert "network:internet" in world.zones_of.get("ip:203.0.113.45", set()) or ext.nets


def test_first_match_evaluation_explains_every_port(world: PolicyWorld) -> None:
    policy = parse_native({"policies": [{"id": "fw", "rules": [
        {"id": "allow-dev-prod", "action": "allow", "source": "network:dev", "destination": "network:prod",
         "ports": ["any"]},
        {"id": "deny-db", "action": "deny", "source": "network:dev", "destination": "host:db-01",
         "ports": ["tcp/5432"]},
    ]}]}, None).policies[0]
    verdict = evaluate_network(world, [policy], "host:dev-01", "host:db-01", PortSet.parse(["tcp/5432"]))[0]
    assert verdict.decision == "allow"
    assert [d.rule for d in verdict.decisions] == ["allow-dev-prod"]
    assert [p.rule for p in verdict.preempted] == ["deny-db"]
    denied = evaluate_network(world, [policy], "host:ws-01", "host:db-01", PortSet.everything())[0]
    assert denied.decision == "deny" and denied.decisions[-1].rule is None


def test_anomaly_detection(world: PolicyWorld) -> None:
    doc = {"policies": [
        {"id": "fw", "rules": [
            {"id": "broad", "action": "allow", "source": "network:dev", "destination": "network:prod", "ports": "any"},
            {"id": "shadowed", "action": "deny", "source": "network:dev", "destination": "host:db-01",
             "ports": "tcp/5432"},
            {"id": "ssh", "action": "allow", "source": "network:corp", "destination": "network:dev",
             "ports": ["tcp/22", "tcp/443"]},
            {"id": "dup", "action": "allow", "source": "network:corp", "destination": "network:dev", "ports": "tcp/22"},
            {"id": "gone", "action": "allow", "source": "network:corp", "destination": "host:ftp-old", "ports": 21},
        ]},
        {"id": "iam", "domain": "identity", "statements": [
            {"id": "dev", "effect": "allow", "principals": ["role:developer"], "actions": ["git:*"],
             "resources": ["service:git"]},
            {"id": "eng-read", "effect": "allow", "principals": ["group:engineering"], "actions": ["git:read"],
             "resources": ["service:git"]},
            {"id": "god", "effect": "allow", "principals": ["role:developer"], "actions": ["*"], "resources": ["*"]},
        ]},
    ]}
    analysis = analyze_set(world, parse_native(doc, None).policies)
    found = {(f.metadata["policy"], f.rule_id, f.metadata["rules"][0]) for f in analysis.findings}
    assert ("fw", "overly-broad-rule", "broad") in found
    assert ("fw", "shadowed-rule", "shadowed") in found
    assert ("fw", "redundant-rule", "dup") in found
    assert ("fw", "stale-reference", "gone") in found
    assert ("iam", "overly-broad-rule", "god") in found
    assert ("iam", "redundant-rule", "eng-read") in found
    assert all(f.explanation and f.evidence for f in analysis.findings)


def test_identity_evaluation_deny_overrides(world: PolicyWorld) -> None:
    policy = parse_native({"policies": [{"id": "iam", "domain": "identity", "statements": [
        {"id": "admin-prod", "effect": "allow", "principals": ["group:engineering"], "actions": ["*"],
         "resources": ["cloud_resource:production"]},
        {"id": "no-export", "effect": "deny", "principals": ["*"], "actions": ["db:export"], "resources": ["*"]},
    ]}]}, None).policies[0]
    allowed = evaluate_identity(world, [policy], "user:alice", "host:db-01", "db:read")
    assert allowed is not None and allowed.decision == "allow"
    assert "production" in " ".join(allowed.explanation)  # resource inherited through containment
    denied = evaluate_identity(world, [policy], "user:alice", "host:db-01", "db:export")
    assert denied is not None and denied.decision == "deny" and denied.decisions[0].rule == "no-export"


def test_raven_revision_diff_flags_expansion() -> None:
    world = PolicyWorld.empty()
    old = parse_native(raven.policy_document(raven.PREVIOUS_POLICY_REVISION), "old").policies
    new = parse_native(raven.policy_document(), "new").policies
    diff = diff_sets(world, old, new, before_label="old", after_label="new")
    changes = {(c.rule, c.change, c.impact) for c in diff.changes}
    assert ("r40-dev-to-prod", "modified", "access-expanded") in changes
    assert ("r90-corp-to-dev-ssh", "added", "access-expanded") in changes
    introduced = {f.rule_id for f in diff.findings_introduced}
    assert {"overly-broad-rule", "redundant-rule"} <= introduced


def test_formats_and_untrusted_input() -> None:
    csv_set = parse_policy_text(raven.firewall_csv(), source="fw.csv", suffix=".csv")
    assert csv_set.format == "csv-firewall" and csv_set.policies[0].id == "fw"
    assert csv_set.policies[0].rules[0].sources == ["network:internet"]
    aws = parse_policy_text(json.dumps({"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}))
    assert aws.format == "aws-iam" and aws.policies[0].rules[0].metadata["principal_unspecified"] is True
    with pytest.raises(InvalidInputError, match="aliases"):
        parse_policy_text("a: &x [1]\nb: *x\n", suffix=".yaml")
    with pytest.raises(InvalidInputError, match="strings"):
        parse_policy_text(json.dumps({"policies": [{"id": "p", "rules": [{"action": "allow", "source": {"x": 1}}]}]}))
    with pytest.raises(InvalidInputError, match="unknown action"):
        parse_policy_text(json.dumps({"policies": [{"id": "p", "rules": [{"action": "maybe"}]}]}))
    assert sniff_policy(b'{"format": "raf-policy/1"}', ".json") > 0.9
    assert sniff_policy(b'{"events": []}', ".json") == 0.0
