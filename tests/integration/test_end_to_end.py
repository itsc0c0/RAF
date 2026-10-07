"""The signature workflow (specification section 51), run through the CLI exactly as documented."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from tests.conftest import FIXTURES


@pytest.mark.slow
def test_signature_workflow(raf_home: Path, cli: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(FIXTURES.parent)  # the documented commands use ./fixtures/...

    def ok(*args: str) -> Any:
        result = cli(*args)
        assert result.exit_code == 0, f"raf {' '.join(args)} failed:\n{result.stdout}\n{result.stderr}"
        return result

    def data(*args: str) -> Any:
        return ok(*args, "--json").json()

    ok("workspace", "create", "demo")
    ok("workspace", "use", "demo")
    assert any(w["name"] == "demo" and w["current"] for w in data("workspace", "list")["items"])

    created = data("range", "create", "raven", "--seed", "42")
    assert created["state"]["name"] == "raven" and created["report"]["objects_created"] > 0
    started = data("range", "start", "raven")
    assert started["report"]["events_created"] > 0

    products = data("products")["items"]
    assert len(products) >= 19 and {p["name"] for p in products} >= {"graph", "range", "forge", "oracle", "lab"}

    graph = data("graph", "user", "alice")
    assert graph["scope"]["id"] == "user:alice" and len(graph["nodes"]) > 1

    scenario = data("forge", "scenario", "suspicious-access", "--seed", "99")
    assert scenario["records"] > 0 and scenario["incident"]

    analysis = data("analyze", "./fixtures/raven-events.jsonl")
    assert analysis["status"] == "completed" and analysis["detected_type"] == "events"
    assert [s["name"] for s in analysis["steps"]][:4] == ["Detect", "Ingest (JSON Lines)", "Timeline", "Graph"]
    assert f"raf lens {analysis['id']}" in analysis["suggestions"]

    timeline = data("timeline", "user", "alice")
    assert timeline["total"] > 0
    ok("trace", "alice")
    blast = data("blast", "alice")
    assert blast["controllable_assets"] > 0 and blast["critical_paths"]

    ok("snapshot", "create", "before")
    ok("ghost", "clone", "current", "hardened")
    modified = data("ghost", "modify", "hardened", "--remove-access", "alice:production")
    applied = modified["applied"][-1]
    assert applied["op"] == "remove-access" and applied["effects"]["removed_relationships"]
    ok("snapshot", "create", "after", "--source", "ghost:hardened")
    diff = data("diff", "before", "after")
    assert diff["totals"]["changes"] >= 1 and diff["totals"]["relationships_b"] < diff["totals"]["relationships_a"]
    assert any(c["item_kind"] == "relationship" and c["change"] == "removed" for c in diff["changes"])

    ok("evidence", "case", "create", "INC-001")
    evidence = data("evidence", "import", "./fixtures/evidence", "--case", "INC-001")
    assert len(evidence["items"]) == 4

    replay = ok("replay", "INC-001")
    assert "bob" in replay.stdout and "svc-deploy" in replay.stdout

    answer = data("oracle", "ask", "Explain the most important security path in INC-001")
    assert answer["intent"] == "incident-path" and not answer["invalid_references"]
    path = answer["answer"].split("Most important security path", 1)[1]
    assert "bob" in path and "svc-deploy" in path and "production" in path
    assert {c["id"] for c in answer["citations"]} >= {"incident:inc-001", "host:dev-01", "identity:svc-deploy"}

    # Everything above was recorded and is attributable.
    assert data("audit", "verify")["valid"]
