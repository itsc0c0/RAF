"""Blast, IAM, Policy and Exposure against the Raven demo workspace (and through CLI/API)."""

from __future__ import annotations

import warnings
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from raf.core.context.app import RafContext
from tests.conftest import FIXTURES

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from fastapi.testclient import TestClient

from raf.apps.api.app import create_app

# --------------------------------------------------------------------------- blast


def test_blast_primary_path_reaches_production_through_exposed_token(raven: RafContext) -> None:
    from raf.products.blast.service import BlastService

    result = BlastService(raven).blast("user:alice")
    assert result.risk.level == "CRITICAL"
    path = [hop.target for hop in result.primary_path]
    assert "identity:svc-deploy" in path and path[-1] == "cloud_resource:production"
    assert all(hop.why for hop in result.primary_path)
    assert result.controllable_assets > 0 and result.critical_assets >= result.privileged_paths


def test_blast_respects_disabled_and_time(raven: RafContext) -> None:
    from raf.core.timeutil import parse_timestamp
    from raf.products.blast.service import BlastService

    before = BlastService(raven).blast("user:bob", at=parse_timestamp("2026-10-06T23:26:00Z"))
    after = BlastService(raven).blast("user:bob", at=parse_timestamp("2026-10-06T23:28:00Z"))
    # the direct membership ended at 23:27 (containment); later reach, if any, needs other hops
    assert "group:vpn-users" in {b.id for b in before.direct}
    assert "group:vpn-users" not in {b.id for b in after.direct}


# --------------------------------------------------------------------------- iam


def test_iam_analyzers_on_raven(raven: RafContext) -> None:
    from raf.products.iam.service import IamService

    report = IamService(raven).analyze()
    by_rule: dict[str, set[str]] = {}
    for f in report.findings:
        by_rule.setdefault(f.rule_id, set()).update(f.affected_objects)
    assert "identity:old-admin" in by_rule["dormant-privileged"]
    assert "identity:old-admin" in by_rule["privileged-without-mfa"]
    assert "role:break-glass" in by_rule["broad-role"]
    assert {"user:dave", "role:break-glass"} <= by_rule["inherited-privilege"]
    assert {"identity:svc-deploy", "host:dev-01", "user:alice"} <= by_rule["credential-exposure-path"]
    assert "user:sarah" in by_rule["excessive-privilege"]
    # re-running is idempotent and does not resolve still-valid findings
    again = IamService(raven).analyze()
    assert again.resolved == 0 and {f.id for f in again.findings} == {f.id for f in report.findings}


def test_iam_paths_and_effective_access(raven: RafContext) -> None:
    from raf.products.iam.service import IamService

    service = IamService(raven)
    paths = service.paths("user:alice", "cloud_resource:production")
    assert paths and paths[0].hops[0].source == "user:alice" and paths[0].hops[-1].target == "cloud_resource:production"
    assert any(h.target == "identity:svc-deploy" for h in paths[0].hops)
    access = service.effective_access("user:dave")
    assert access.privileged
    break_glass = next(r for r in access.roles if r["id"] == "role:break-glass")
    assert break_glass["via_nested_group"] and break_glass["chain"][1] == "oncall-support"
    assert any(r["id"] == "cloud_resource:production" and r["admin"] for r in access.resources)


# --------------------------------------------------------------------------- policy


def test_policy_demo_import_and_decisions(raven: RafContext) -> None:
    from raf.products.policy.service import PolicyService

    service = PolicyService(raven)
    assert [p.id for p in service.stored()] == ["raven-access", "raven-fw"]
    alice = service.evaluate("user:alice", "access", "host:db-01")
    assert alice.decision == "deny" and alice.network_sources == ["host:ws-01"]
    assert alice.indirect and alice.indirect[0].pivot == "host:dev-01"
    dev = service.evaluate("host:dev-01", "reach", "host:db-01", ports=["tcp/5432"])
    assert dev.decision == "allow"
    network = dev.parts[0]
    assert network.decisions[0].rule == "r40-dev-to-prod"
    assert [p.rule for p in network.preempted] == ["r85-deny-dev-to-prod-db"]
    frank = service.evaluate("user:frank", "admin", "cloud_resource:production")
    assert frank.decision == "allow" and frank.parts[-1].decisions[0].rule == "break-glass"
    lab = service.evaluate("host:lab-01", "reach", "host:db-01")
    assert lab.decision == "deny"


def test_policy_findings_and_generic_import(raven: RafContext, tmp_path: Path) -> None:
    from raf.analysis.ingest import import_path
    from raf.core.ingestion.pipeline import IngestOptions
    from raf.products.policy.service import PolicyService

    rules = {f.metadata["rules"][0]: f.rule_id for f in raven.store.findings.list(product="policy", limit=100)}
    assert rules["r85-deny-dev-to-prod-db"] == "shadowed-rule"
    assert rules["r40-dev-to-prod"] == "overly-broad-rule"
    assert rules["r90-corp-to-dev-ssh"] == "redundant-rule"
    assert rules["r55-dmz-to-legacy-ftp"] == "stale-reference"
    # the previous revision through the generic importer replaces the stored policy content
    _job, report = import_path(raven, FIXTURES / "policies" / "raven-policies-2026-09.json", IngestOptions())
    assert report is not None and report.parser.startswith("raf-policy")
    fw = PolicyService(raven).get("raven-fw")
    assert fw.revision == "2026-09-01" and fw.rule("r40-dev-to-prod").ports == ["tcp/22", "tcp/8443"]  # type: ignore[union-attr]
    diff = PolicyService(raven).diff(str(FIXTURES / "policies" / "raven-policies.json"), "current")
    assert any(c.rule == "r40-dev-to-prod" and c.impact == "access-reduced" for c in diff.changes)


# --------------------------------------------------------------------------- exposure


def test_exposure_ranks_context_not_cvss(raven: RafContext) -> None:
    from raf.products.exposure.service import ExposureService

    report = ExposureService(raven).report()
    ranked = {i.object["id"]: i for i in report.items}
    assert report.items[0].object["id"] == "host:vpn-01"
    lab, vpn = ranked["host:lab-01"], ranked["host:vpn-01"]
    assert lab.level == "LOW" and vpn.level == "CRITICAL" and lab.vulnerabilities[0]["cvss"] >= 9
    assert any(f.rule == "exposure.isolated" for f in lab.factors)
    dev = ranked["host:dev-01"]
    assert any(f.rule == "exposure.privileged-credentials" for f in dev.factors)
    assert report.findings == len([i for i in report.items if i.level in ("HIGH", "CRITICAL")])
    assert report.metrics.entry_points >= 2 and report.metrics.exposed_critical_assets > 0


# --------------------------------------------------------------------------- CLI and API


def test_cli_exposure_products(raven_home: Path, cli: Any) -> None:
    blast = cli("blast", "alice", "--json")
    assert blast.exit_code == 0, blast.stderr
    assert blast.json()["schema"] == "raf.blast/v1" and blast.json()["risk"]["level"] == "CRITICAL"
    iam = cli("iam", "analyze", "--json")
    assert iam.exit_code == 0 and iam.json()["by_rule"]["broad-role"] == 1
    path = cli("iam", "path", "alice", "production")
    assert path.exit_code == 0 and "svc-deploy" in path.stdout and "Best path" in path.stdout
    can = cli("policy", "can", "alice", "access", "DB-01")
    assert can.exit_code == 0 and "DENY" in can.stdout and "Indirect paths" in can.stdout
    check = cli("policy", "check", str(FIXTURES / "policies" / "raven-fw-export.csv"), "--json")
    assert check.exit_code == 0 and check.json()["sets"][0]["format"] == "csv-firewall"
    diff = cli("policy", "diff", str(FIXTURES / "policies" / "raven-policies-2026-09.json"), "current")
    assert diff.exit_code == 0 and "access-expanded" in diff.stdout
    exposure = cli("exposure", "--json", "--min-level", "high")
    assert exposure.exit_code == 0
    assert all(i["level"] in ("HIGH", "CRITICAL") for i in exposure.json()["items"])
    show = cli("exposure", "show", "LAB-01")
    assert show.exit_code == 0 and "not reachable from any entry point" in show.stdout
    bad = cli("policy", "can", "alice", "access", "nobody-here")
    assert bad.exit_code != 0 and "Traceback" not in bad.stderr


@pytest.fixture
def api(raven_home: Path) -> Iterator[Any]:
    with TestClient(create_app(env={"RAF_HOME": str(raven_home)})) as client:
        yield client


def test_api_exposure_products(api: Any) -> None:
    exposure = api.get("/api/v1/exposure", params={"min_level": "high"}).json()
    first = exposure["items"][0]
    assert set(first) >= {"object", "score", "level", "factors", "entry_points", "vulnerabilities"}
    assert set(first["factors"][0]) >= {"label", "sign", "points", "evidence"}
    one = api.get("/api/v1/exposure/DB-01").json()
    assert one["object"]["id"] == "host:db-01" and one["factors"]
    assert api.get("/api/v1/exposure", params={"min_level": "bogus"}).status_code in (400, 422)
    blast = api.get("/api/v1/blast/alice").json()
    assert blast["risk"]["level"] == "CRITICAL" and blast["primary_path"]
    paths = api.get("/api/v1/iam/path", params={"source": "alice", "target": "production"}).json()
    assert paths["paths"][0]["hops"][0]["why"]
    analyze = api.get("/api/v1/iam/analyze").json()
    assert analyze["summary"]["principals"] == 11 and analyze["findings"]
    policies = api.get("/api/v1/policy/policies").json()["items"]
    assert {p["id"] for p in policies} == {"raven-fw", "raven-access"} and policies[0]["rules"]
    flow = api.post("/api/v1/policy/evaluate", json={"source": "DEV-01", "target": "DB-01", "port": 5432}).json()
    assert flow["decision"] == "allow" and flow["parts"][0]["decisions"][0]["rule"] == "r40-dev-to-prod"
    access = api.post("/api/v1/policy/evaluate", json={"principal": "alice", "target": "DB-01"}).json()
    assert access["decision"] == "deny" and access["indirect"]
    checked = api.post(
        "/api/v1/policy/check",
        json={"document": "id,action,source,destination,port\nr1,allow,any,any,any\n", "format": "csv"},
    ).json()
    assert checked["analysis"]["findings"][0]["rule_id"] == "overly-broad-rule"
    assert api.get("/api/v1/policy/diff", params={"before": "../etc/passwd"}).status_code == 422
