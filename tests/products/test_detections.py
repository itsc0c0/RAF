"""Timeline detections: rules over events from any source, explained activity, correlated incidents."""

from __future__ import annotations

import json
import warnings
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from raf.analysis.analyze import AnalyzeOptions, analyze_path
from raf.core.context.app import RafContext, open_context
from raf.core.plugins.registry import ProductRegistry
from raf.core.storage.repos.events import EventQuery
from raf.data.multisource import ACCESS_KEY
from raf.products.catalog import builtin_manifests
from raf.products.timeline.detections import DetectionService
from tests.conftest import FIXTURES

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from fastapi.testclient import TestClient

from raf.apps.api.app import create_app

MIXED = FIXTURES / "logs" / "raven-multisource.log"


@pytest.fixture
def dctx(tmp_path: Path) -> Iterator[RafContext]:
    from raf.core.workspace.manager import RafHome

    env = {"RAF_HOME": str(tmp_path / "detect-home")}
    context = open_context(env=env, registry=ProductRegistry(RafHome.from_env(env), builtin_manifests()))
    yield context
    context.close()


def _rules(findings: list[Any]) -> Counter[str]:
    return Counter(f.rule_id for f in findings)


def test_mixed_log_attack_chain_decoys_and_incident(dctx: RafContext) -> None:
    result = analyze_path(dctx, MIXED)
    assert result.status == "completed" and result.detected_label == "Multi-source log"
    steps = {s.name: s for s in result.steps}
    assert "sources" in steps["Ingest (Multi-source log)"].stats and steps["Detections"].status == "ok"
    findings = dctx.store.findings.list(product="timeline", limit=100)
    assert _rules(findings) == Counter(
        {
            "attack-chain": 1,
            "bulk-storage-read": 1,
            "cloud-credential-public": 1,
            "exposed-artifact": 1,
            "large-transfer": 1,
            "cloud-persistence": 1,
            "web-recon": 1,
            "new-external-signin": 1,
            "security-alert": 1,
        }
    )
    by_rule = {f.rule_id: f for f in findings}
    assert by_rule["attack-chain"].severity.value == "CRITICAL"
    assert by_rule["bulk-storage-read"].severity.value == "CRITICAL"
    assert "deploy.env" in by_rule["exposed-artifact"].title
    assert by_rule["cloud-persistence"].severity.value == "MEDIUM"  # denied: an attempt, nothing was created
    assert by_rule["web-recon"].severity.value == "LOW"  # every probe was refused
    assert by_rule["new-external-signin"].severity.value == "LOW"  # MFA completed in the same session
    credential = by_rule["cloud-credential-public"]
    assert "same access key" in credential.description  # the key is also used from the CI runner
    for finding in findings:  # the key itself never appears in clear
        assert ACCESS_KEY not in json.dumps(finding.to_json_dict())
        assert "payments-old" not in finding.description and "FIN-301" not in finding.title
    # decoys are explained, not findings
    explained = steps["Detections"].stats["explained"]
    assert explained == 2
    assert {e["title"].split(" ")[1] for e in result.stats["explained"]} >= {"destructive"}
    # the chain is a suspected incident linking its evidence
    case = [i for i in result.incidents if i.startswith("incident:case-")]
    assert len(case) == 1
    incident = dctx.store.incidents.get(case[0])
    assert incident is not None and incident.status == "suspected" and incident.severity.value == "CRITICAL"
    assert "Ruled out" in incident.description and incident.event_count >= 20
    linked = dctx.store.events.count(EventQuery(incident_id=case[0]))
    assert linked == incident.event_count


def test_detections_are_idempotent_and_dry_runs_store_nothing(dctx: RafContext) -> None:
    analyze_path(dctx, MIXED)
    before = {f.id for f in dctx.store.findings.list(product="timeline", limit=100)}
    report = DetectionService(dctx).run(EventQuery(), scope_label="workspace")
    assert report.created == 0 and report.updated == len(before) and report.resolved == 0
    assert {f.id for f in report.findings} == before
    dry = DetectionService(dctx).run(EventQuery(), scope_label="workspace", persist=False)
    assert {f.id for f in dry.findings} == before and dry.created == 0


def test_a_late_change_record_explains_and_resolves(dctx: RafContext, tmp_path: Path) -> None:
    lines = MIXED.read_text().splitlines()
    without = [line for line in lines if " change {" not in line]
    path = tmp_path / "ops.log"
    path.write_text("\n".join(without) + "\n")
    analyze_path(dctx, path)
    destructive = dctx.store.findings.list(product="timeline", rule_id="destructive-change", limit=10)
    assert len(destructive) == 1 and destructive[0].status.value == "OPEN"
    change = tmp_path / "changes.log"
    change.write_text(next(line for line in lines if " change {" in line) + "\n")
    analyze_path(dctx, change, AnalyzeOptions(format="multilog"))
    report = DetectionService(dctx).run(EventQuery(), scope_label="workspace")
    assert not [f for f in report.findings if f.rule_id == "destructive-change"]
    assert any(e.rule == "destructive-change" and "CHG-1017" in e.reason for e in report.explained)
    resolved = dctx.store.findings.get(destructive[0].id)
    assert resolved is not None and resolved.status.value == "RESOLVED"


def test_text_import_is_reread_by_the_mixed_log_parser(dctx: RafContext) -> None:
    first = analyze_path(dctx, MIXED, AnalyzeOptions(format="text"))
    assert first.stats["detections"] == 0 and first.stats["objects"] == 0
    second = analyze_path(dctx, MIXED)
    timeline = next(s for s in second.steps if s.name == "Timeline")
    assert timeline.stats["reparsed"] == timeline.stats["in_scope"] > 2000
    assert second.stats["events"] == timeline.stats["in_scope"] and second.stats["detections"] >= 8
    assert dctx.store.events.count(EventQuery(event_types=["log.message"])) < 50  # only free text is left as text


def test_the_demo_incident_is_reconstructed_from_its_evidence(raven: RafContext) -> None:
    report = DetectionService(raven).run(EventQuery(), scope_label="workspace", persist=False)
    rules = _rules(report.findings)
    for rule in (
        "brute-force",
        "credential-access",
        "service-account-new-source",
        "large-transfer",
        "security-alert",
        "suspicious-command",
        "attack-chain",
    ):
        assert rules[rule] >= 1, rule
    # the nightly backup (cron pg_dump, then a transfer of the same size) is explained, not flagged
    assert any("scheduled backup" in e.reason for e in report.explained)
    assert all(i.existing and i.name == "INC-001" for i in report.incidents)  # no new incident is made up
    brute = next(f for f in report.findings if f.rule_id == "brute-force")
    assert "bob" in brute.title and "then a success" in brute.title


def test_cli_and_api(cli: Any, raf_home: Path) -> None:
    analyzed = cli("analyze", str(MIXED))
    assert analyzed.exit_code == 0, analyzed.stderr
    assert "Detections:" in analyzed.stdout and "Explained (no finding):" in analyzed.stdout
    dry = cli("detect", "--dry-run")
    assert dry.exit_code == 0 and "dry run: nothing stored" in dry.stdout and "CASE-" in dry.stdout
    data = cli("--json", "detect", "analysis-1", "--dry-run").json()
    assert data["events_examined"] > 2000 and data["incidents"][0]["name"].startswith("CASE-")
    with TestClient(create_app(env={"RAF_HOME": str(raf_home)})) as api:
        response = api.post("/api/v1/timeline/detect", json={"ref": "analysis-1", "dry_run": True})
        assert response.status_code == 200, response.text
        assert {f["rule_id"] for f in response.json()["findings"]} >= {"bulk-storage-read", "attack-chain"}
