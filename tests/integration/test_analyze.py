"""raf analyze: input detection, per-type pipelines, analysis records, scoping and the API."""

from __future__ import annotations

import json
import random
import string
import warnings
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from raf.analysis.analyze import AnalyzeOptions, analyze_path, detect_input
from raf.core.context.app import RafContext, open_context
from raf.core.errors import IngestionError
from raf.core.plugins.registry import ProductRegistry
from raf.core.query.scope import resolve_scope
from raf.core.storage.repos.events import EventQuery
from raf.products.catalog import builtin_manifests
from tests.conftest import FIXTURES

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from fastapi.testclient import TestClient

from raf.apps.api.app import create_app

SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "metadata": {"component": {"type": "application", "name": "demo-app", "bom-ref": "app"}},
    "components": [
        {
            "type": "library",
            "name": "requests",
            "version": "2.31.0",
            "purl": "pkg:pypi/requests@2.31.0",
            "bom-ref": "pkg:pypi/requests@2.31.0",
        }
    ],
    "dependencies": [{"ref": "app", "dependsOn": ["pkg:pypi/requests@2.31.0"]}],
}


def _names(result: Any) -> list[str]:
    return [step.name for step in result.steps]


@pytest.fixture
def actx(tmp_path: Path) -> Iterator[RafContext]:
    """An empty workspace with the built-in products registered (as in the CLI and API)."""
    from raf.core.workspace.manager import RafHome

    env = {"RAF_HOME": str(tmp_path / "analyze-home")}
    context = open_context(env=env, registry=ProductRegistry(RafHome.from_env(env), builtin_manifests()))
    yield context
    context.close()


def test_detection(actx: RafContext, tmp_path: Path) -> None:
    ctx = actx
    from raf.products.dependency.samples import write_sample_project

    assert detect_input(ctx, FIXTURES / "pcap" / "raven-inc001.pcap").kind == "pcap"
    events = detect_input(ctx, FIXTURES / "raven-events.jsonl")
    assert (events.kind, events.parser, events.label) == ("events", "jsonl", "JSON Lines")
    assert detect_input(ctx, FIXTURES / "evidence").kind == "directory"
    assert detect_input(ctx, FIXTURES / "policies" / "raven-policies.json").kind == "policy"
    write_sample_project(tmp_path / "shop")
    assert detect_input(ctx, tmp_path / "shop").kind == "repository"
    assert detect_input(ctx, tmp_path / "shop" / "requirements.txt").kind == "manifest"
    sbom = tmp_path / "bom.json"
    sbom.write_text(json.dumps(SBOM), encoding="utf-8")
    assert detect_input(ctx, sbom).kind == "sbom"
    junk = tmp_path / "blob.bin"
    junk.write_bytes(bytes(range(256)) * 8)
    with pytest.raises(IngestionError):
        detect_input(ctx, junk)


def test_events_pipeline_and_scope(actx: RafContext) -> None:
    ctx = actx
    seen: list[str] = []
    result = analyze_path(
        ctx, FIXTURES / "raven-events.jsonl", AnalyzeOptions(on_step=lambda step: seen.append(step.name))
    )
    assert result.id == "analysis-1" and result.status == "completed" and seen == _names(result)
    assert _names(result) == [
        "Detect",
        "Ingest (JSON Lines)",
        "Timeline",
        "Graph",
        "Incidents",
        "IAM analysis",
        "Exposure correlation",
        "Findings",
    ]
    assert all(step.status == "ok" for step in result.steps)
    assert result.stats["objects"] > 300 and result.stats["events"] > 500 and result.stats["findings"] > 0
    assert result.incidents == ["incident:inc-001"] and "raf lens analysis-1" in result.suggestions
    record = ctx.store.analyses.get("analysis-1")
    assert record is not None and record.status == "completed" and record.job_ids == result.job_ids
    scope = resolve_scope(ctx, ["@last"])
    assert scope.kind == "analysis" and scope.id == "analysis-1"
    assert ctx.store.events.count(scope.event_query()) == result.stats["events"]
    assert ctx.audit.verify()["valid"]


def test_pcap_reanalysis_covers_earlier_import(raven: RafContext) -> None:
    # The demo already holds this capture (as INC-001 evidence): nothing is duplicated, yet the
    # analysis scope still reaches the capture's events through the job that first imported them.
    result = analyze_path(raven, FIXTURES / "pcap" / "raven-inc001.pcap", AnalyzeOptions(correlate=False))
    protocol = next(step for step in result.steps if step.name == "Protocol")
    assert protocol.product == "protocol" and protocol.stats["flows"] == 4 and result.stats["flows"] == 4
    assert "9 already present" in next(s.detail for s in result.steps if s.name == "Timeline")
    assert [s.status for s in result.steps if s.product in ("iam", "exposure")] == ["skipped", "skipped"]
    # The evidence job that first imported the capture also holds other files: the scope is narrowed
    # to this capture's source, so analysis-N shows exactly its 9 events.
    scope = resolve_scope(raven, [result.id])
    assert scope.source == "raven-inc001.pcap" and len(scope.job_ids) == 2
    assert raven.store.events.count(scope.event_query()) == 9


def test_repository_sbom_and_disabled_products(actx: RafContext, tmp_path: Path) -> None:
    ctx = actx
    from raf.products.dependency.samples import write_sample_project

    write_sample_project(tmp_path / "shop")
    token = "ghp_" + "".join(random.Random(7).choice(string.ascii_letters + string.digits) for _ in range(36))
    (tmp_path / "shop" / ".env").write_text(f"GITHUB_TOKEN={token}\n", encoding="utf-8")
    repo = analyze_path(ctx, tmp_path / "shop")
    assert _names(repo) == ["Detect", "Dependency scan", "Vault secret scan", "Graph", "Findings"]
    assert repo.status == "completed" and repo.stats["packages"] > 0 and repo.stats["secrets"] >= 1
    assert token not in json.dumps(repo.to_json_dict())  # Vault never reveals the value
    sbom = tmp_path / "bom.json"
    sbom.write_text(json.dumps(SBOM), encoding="utf-8")
    imported = analyze_path(ctx, sbom)
    assert _names(imported) == ["Detect", "Dependency (SBOM import)", "Graph", "Findings"]
    assert imported.status == "completed"
    assert ctx.registry is not None
    ctx.registry.disable("vault")
    skipped = analyze_path(ctx, tmp_path / "shop")
    vault = next(step for step in skipped.steps if step.name == "Vault secret scan")
    assert vault.status == "skipped" and "disabled" in vault.detail and skipped.status == "completed"


def test_bundle_pipeline_and_failed_analysis(raven: RafContext, actx: RafContext, tmp_path: Path) -> None:
    ctx = actx
    from raf.analysis.backup import export_workspace

    bundle = tmp_path / "raven.raf"
    export_workspace(raven, bundle)
    result = analyze_path(ctx, bundle, AnalyzeOptions(correlate=False))
    assert _names(result)[:4] == ["Detect", "Bundle verification", "Bundle import", "Timeline"]
    assert result.status == "completed" and result.stats["events"] > 500
    assert ctx.store.events.count(EventQuery(job_ids=result.job_ids)) == result.stats["events"]
    tampered = tmp_path / "tampered.raf"
    with zipfile.ZipFile(bundle) as src, zipfile.ZipFile(tampered, "w") as dst:
        for item in src.infolist():
            data = src.read(item.filename)
            dst.writestr(item, data + b"\n" if item.filename == "objects.jsonl" else data)
    failed = analyze_path(ctx, tampered)
    assert failed.status == "failed" and failed.steps[-1].status == "failed"
    assert ctx.store.analyses.get(failed.id).status == "failed"  # type: ignore[union-attr]


def test_cli_analyze(raf_home: Path, cli: Any) -> None:
    result = cli("analyze", str(FIXTURES / "raven-events.jsonl"))
    assert result.exit_code == 0, result.stderr
    for text in ("Detected:", "Running:", "✓ Ingest (JSON Lines)", "✓ Exposure correlation", "Explore:"):
        assert text in result.stdout
    assert "raf lens analysis-1" in result.stdout
    shown = cli("analyze", "analysis-1", "--json").json()
    assert shown["schema"] == "raf.analysis/v1" and shown["id"] == "analysis-1" and shown["status"] == "completed"
    listing = cli("analyses", "--json").json()
    assert listing["total"] == 1 and listing["items"][0]["detected_type"] == "events"
    graph = cli("graph", "@last", "--json").json()
    assert graph["scope"]["id"] == "analysis-1"
    timeline = cli("timeline", "analysis-1", "--json")
    assert timeline.exit_code == 0
    assert cli("analyze", "analysis-99").exit_code != 0


@pytest.fixture
def api(raf_home: Path) -> Iterator[Any]:
    with TestClient(create_app(env={"RAF_HOME": str(raf_home)})) as client:
        yield client


def test_api_analyze(api: Any) -> None:
    capture = (FIXTURES / "pcap" / "raven-inc001.pcap").read_bytes()
    response = api.post(
        "/api/v1/analyze", files={"file": ("../../etc/capture.pcap", capture, "application/octet-stream")}
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["detected_type"] == "pcap" and data["status"] == "completed" and data["input"] == "capture.pcap"
    assert data["stats"]["flows"] == 4 and data["id"] == "analysis-1"
    listing = api.get("/api/v1/analyses").json()
    assert listing["total"] == 1 and listing["items"][0]["input"] == "capture.pcap"
    shown = api.get("/api/v1/analyses/analysis-1").json()
    assert shown["job_ids"] and "/" not in shown["input"]
    assert api.get("/api/v1/analyses/analysis-9").status_code == 404
    assert api.post("/api/v1/analyze", data={"path": "/etc/passwd"}).status_code == 422
    empty = api.post("/api/v1/analyze", files={"file": ("empty.json", b"", "application/json")})
    assert empty.status_code == 422 and "empty" in empty.json()["error"]["message"]


def test_surface_inventory_pipeline(raven: RafContext, actx: RafContext) -> None:
    inventory = FIXTURES / "surface" / "raven-surface.json"
    # In the demo workspace the scope is configured: the inventory is evaluated within it.
    result = analyze_path(raven, inventory, AnalyzeOptions(correlate=False))
    assert result.detected_type == "surface" and result.status == "completed"
    surface = next(step for step in result.steps if step.name == "Surface analysis")
    assert surface.product == "surface" and surface.stats["findings"] == 13
    # Without a scope nothing is judged, and analyzing never authorizes anything by itself.
    fresh = analyze_path(actx, inventory, AnalyzeOptions(correlate=False))
    step = next(step for step in fresh.steps if step.name == "Surface analysis")
    assert step.stats == {"scope_entries": 0} and "no authorized scope" in step.detail
    from raf.products.surface.service import SurfaceService

    assert SurfaceService(actx).scope_entries() == []
