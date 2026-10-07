"""R$F OS screens (raf tui): page documents built from real services, the API routes, the launcher."""

from __future__ import annotations

import json
import sys
import warnings
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from raf.analysis import screens
from raf.core.context.app import RafContext
from raf.core.errors import NotFoundError

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from fastapi.testclient import TestClient

from raf.apps.api.app import create_app

# The screen protocol (docs/tui.md) that the raf-os renderer deserializes: every block carries
# exactly these fields; optional values are null, never missing.
OPT = (str, type(None))
STYLE = {"normal", "dim", "accent", "ok", "info", "warn", "danger", "note"}
STYLE_OPT = STYLE | {None}
SEVERITY = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
NUMBER = (int, float)


def _tree_node(value: Any, where: str) -> None:
    _check(
        value,
        {"label": str, "type": OPT, "ref": OPT, "note": OPT, "style": STYLE_OPT, "children": [_tree_node]},
        where,
    )


SCHEMA: dict[str, dict[str, Any]] = {
    "section": {"text": str},
    "text": {"lines": [str], "style": STYLE},
    "kv": {"rows": [{"k": str, "v": str, "style": STYLE_OPT, "ref": OPT}]},
    "event": {"time": str, "date": str, "category": str, "lines": [str], "severity": SEVERITY, "ref": OPT},
    "gap": {"text": str},
    "chain": {
        "nodes": [{"label": str, "type": str, "ref": OPT, "note": OPT}],
        "edges": [{"label": str, "kind": {"observed", "modeled", "correlated"}, "note": OPT, "ref": OPT}],
    },
    "tree": {"root": _tree_node, "arrows": bool},
    "table": {"columns": [str], "align": [{"l", "r", "c"}], "rows": [{"cells": [str], "style": STYLE_OPT, "ref": OPT}]},
    "finding": {"severity": SEVERITY, "title": str, "id": str, "lines": [str], "ref": OPT},
    "compare": {
        "left": str,
        "right": str,
        "rows": [{"label": str, "before": str, "after": str, "verdict": {"better", "worse", "same", "info"}}],
    },
    "graph": {
        "root": str,
        "nodes": [
            {
                "id": str,
                "label": str,
                "type": str,
                "criticality": OPT,
                "highlight": bool,
                "parent": OPT,
                "edge": OPT,
                "dir": {"in", "out", None},
            }
        ],
        "links": [{"source": str, "target": str, "label": str}],
    },
    "diagram": {"lines": [str], "style": STYLE},
    "citations": {"items": [{"id": str, "label": str, "type": str}]},
    "bars": {"rows": [{"label": str, "value": NUMBER, "max": NUMBER, "style": STYLE_OPT}]},
    "grid": {"columns": int, "items": [{"label": str, "status": str, "style": STYLE_OPT}]},
    "spacer": {},
}


def _check(value: Any, spec: Any, where: str) -> None:
    if callable(spec) and not isinstance(spec, type):
        spec(value, where)
    elif isinstance(spec, dict):
        assert isinstance(value, dict) and set(value) == set(spec), f"{where}: fields {sorted(value)}"
        for key, sub in spec.items():
            _check(value[key], sub, f"{where}.{key}")
    elif isinstance(spec, list):
        assert isinstance(value, list), f"{where}: not a list"
        for i, item in enumerate(value):
            _check(item, spec[0], f"{where}[{i}]")
    elif isinstance(spec, set):
        assert value in spec, f"{where}: {value!r} not in {sorted(map(str, spec))}"
    else:
        assert isinstance(value, spec) and not (spec is int and isinstance(value, bool)), f"{where}: {value!r}"


def assert_protocol(doc: dict[str, Any]) -> None:
    _check(
        doc,
        {"page": str, "title": str, "subtitle": OPT, "param": OPT, "blocks": list, "notes": [str]},
        doc.get("page", "?"),
    )
    for i, block in enumerate(doc["blocks"]):
        where = f"{doc['page']}.blocks[{i}]"
        assert block.get("t") in SCHEMA, f"{where}: unknown block {block.get('t')!r}"
        _check(block, {"t": str, **SCHEMA[block["t"]]}, f"{where}<{block['t']}>")
        if block["t"] == "table":
            assert len(block["align"]) == len(block["columns"]), where
            assert all(len(row["cells"]) == len(block["columns"]) for row in block["rows"]), where
        if block["t"] == "chain":
            assert len(block["edges"]) == len(block["nodes"]) - 1 and block["nodes"], where
        if block["t"] == "graph":
            ids = [n["id"] for n in block["nodes"]]
            assert len(ids) == len(set(ids)) and block["root"] == ids[0], where
            assert all((n["parent"] is None) == (n["id"] == block["root"]) for n in block["nodes"]), where
            assert all(n["parent"] in ids[: ids.index(n["id"])] for n in block["nodes"] if n["parent"]), where
            assert all(link["source"] in ids and link["target"] in ids for link in block["links"]), where


def _blocks(doc: dict[str, Any], kind: str) -> list[dict[str, Any]]:
    return [b for b in doc["blocks"] if b["t"] == kind]


def _all_text(doc: dict[str, Any]) -> str:
    return json.dumps(doc, ensure_ascii=False)


def test_index_and_every_page_render(raven: RafContext) -> None:
    index = screens.pages_index(raven)
    assert [p["id"] for p in index["pages"]] == list(screens.PAGES)
    assert index["focus"] == {
        "incident": "INC-001",
        "incident_id": "incident:inc-001",
        "subject": "bob",
        "subject_id": "user:bob",
        "target": "production",
        "target_id": "cloud_resource:production",
    }
    assert index["stats"]["objects"] > 300 and index["system"]["workspace"] == raven.workspace.name
    seen: set[str] = set()
    for page in screens.PAGES:
        doc = screens.screen(raven, page)
        assert doc["page"] == page and doc["title"].startswith("R$F") and doc["blocks"]
        assert_protocol(json.loads(json.dumps(doc)))  # exactly what the API sends
        seen |= {b["t"] for b in doc["blocks"]}
    assert seen == set(SCHEMA), set(SCHEMA) - seen  # every block type is exercised
    event_id = _blocks(screens.screen(raven, "timeline"), "event")[0]["ref"]
    finding_id = _blocks(screens.screen(raven, "findings"), "table")[0]["rows"][0]["ref"]
    rel_id = next(e["ref"] for e in _blocks(screens.screen(raven, "trace"), "chain")[0]["edges"] if e["ref"])
    for ref in ("host:dev-01", "bob", event_id, finding_id, rel_id):
        assert_protocol(json.loads(json.dumps(screens.inspect(raven, ref).to_dict())))
    relationship = screens.inspect(raven, rel_id).to_dict()
    assert relationship["subtitle"] == rel_id and "WHAT IT MEANS FOR PROPAGATION" in _all_text(relationship)


def test_story_pages_tell_the_incident(raven: RafContext) -> None:
    trace = screens.screen(raven, "trace")
    chain = _blocks(trace, "chain")[0]
    labels = [n["label"] for n in chain["nodes"]]
    assert labels[:4] == ["203.0.113.45", "VPN-01", "bob", "DEV-01"] and labels[-1] == "production"
    assert len(chain["edges"]) == len(chain["nodes"]) - 1
    assert {e["kind"] for e in chain["edges"]} == {"observed", "modeled"}
    timeline = screens.screen(raven, "timeline")
    events = _blocks(timeline, "event")
    assert events and _blocks(timeline, "gap") and events[0]["category"] == "AUTH"
    assert any("result=SUCCESS" in line for e in events for line in e["lines"])
    blast = screens.screen(raven, "blast", "bob")
    assert blast["title"] == "R$F BLAST — bob" and any(t["arrows"] for t in _blocks(blast, "tree"))
    assert "modeled reachability" in _all_text(blast)
    iam = screens.screen(raven, "iam")
    assert "INHERITED ACCESS" in _all_text(iam)
    at = next(i for i, b in enumerate(iam["blocks"]) if b.get("text") == "CREDENTIAL-DERIVED PATH")
    node, derived = iam["blocks"][at + 1]["root"], []
    while node:
        derived.append(node["label"])
        node = node["children"][0] if node["children"] else None
    assert derived[:2] == ["bob", "DEV-01"] and derived[-1] == "svc-deploy" and "DEPLOY_TOKEN" in derived[-2]
    graph = screens.screen(raven, "graph")
    drawing = _blocks(graph, "graph")[0]
    ids = {n["id"] for n in drawing["nodes"]}
    assert drawing["root"] == "user:bob" and all(n["parent"] in ids for n in drawing["nodes"] if n["parent"])
    assert any(n["highlight"] for n in drawing["nodes"] if n["id"] == "host:dev-01")
    # the whole story path is drawn (beyond two hops too); process activity records are not
    highlighted = {n["id"] for n in drawing["nodes"] if n["highlight"]}
    assert {"identity:svc-deploy", "cloud_resource:production"} <= highlighted
    assert not any(n["type"] == "process" for n in drawing["nodes"])
    assert any("process records are not drawn" in note for note in graph["notes"])


def test_ghost_page_simulates_without_saving(raven: RafContext) -> None:
    before = raven.store.relationships.count()
    doc = screens.screen(raven, "ghost", "bob → production")
    compare = _blocks(doc, "compare")[0]
    first = compare["rows"][0]
    assert first["label"] == "bob → production" and (first["before"], first["after"]) == ("REACHABLE", "BLOCKED")
    rows = {row["label"]: row for row in compare["rows"]}
    assert int(rows["Attack paths broken"]["after"]) > 0 and rows["New attack paths"]["after"] == "0"
    assert "No production changes have been made" in _all_text(doc)
    assert raven.store.relationships.count() == before
    assert not raven.store.kv.items("ghost")  # nothing saved as a Ghost model


def test_page_parameters_and_errors(raven: RafContext) -> None:
    assert screens.screen(raven, "exposure", "DEV-01")["title"] == "R$F EXPOSURE — DEV-01"
    assert screens.screen(raven, "oracle", "Who can control DB-01?")["param"] == "Who can control DB-01?"
    assert screens.screen(raven, "findings", "HIGH")["title"] == "R$F FINDINGS — HIGH"
    assert screens.screen(raven, "timeline", "DEV-01")["title"] == "R$F TIMELINE — DEV-01"
    inspected = screens.inspect(raven, "host:dev-01").to_dict()
    assert inspected["title"] == "HOST DEV-01" and "RELATIONSHIPS" in _all_text(inspected)
    event_id = _blocks(screens.screen(raven, "timeline"), "event")[0]["ref"]
    assert screens.inspect(raven, event_id).to_dict()["subtitle"] == event_id
    with pytest.raises(NotFoundError):
        screens.screen(raven, "nonsense")
    with pytest.raises(NotFoundError):
        screens.screen(raven, "blast", "no-such-thing")


def test_empty_workspace_home(ctx: RafContext) -> None:
    doc = screens.screen(ctx, "home")
    assert "EMPTY WORKSPACE" in _all_text(doc) and "raf demo load" in _all_text(doc)
    assert_protocol(doc)
    assert_protocol(screens.screen(ctx, "findings"))
    assert_protocol(screens.screen(ctx, "evidence"))
    with pytest.raises(NotFoundError):
        screens.screen(ctx, "blast")
    assert screens.pages_index(ctx)["focus"]["incident"] is None


@pytest.fixture
def api(raven_home: Path) -> Iterator[Any]:
    with TestClient(create_app(env={"RAF_HOME": str(raven_home)})) as client:
        yield client


def test_api_routes(api: Any) -> None:
    index = api.get("/api/v1/tui/pages").json()
    assert index["focus"]["subject"] == "bob" and len(index["pages"]) == len(screens.PAGES)
    blast = api.get("/api/v1/tui/screen/blast", params={"ref": "alice"}).json()
    assert blast["title"] == "R$F BLAST — alice"
    oracle = api.get("/api/v1/tui/screen/oracle", params={"question": "Can alice reach production?"}).json()
    assert oracle["param"] == "Can alice reach production?"
    assert api.get("/api/v1/tui/inspect", params={"ref": "DEV-01"}).json()["title"] == "HOST DEV-01"
    assert api.get("/api/v1/tui/screen/nope").status_code == 404
    assert api.get("/api/v1/tui/screen/blast", params={"ref": "x" * 600}).status_code == 422


def test_launcher_api_requires_its_token(raven_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from raf.apps.cli.commands.tui import local_api

    monkeypatch.setenv("RAF_HOME", str(raven_home))
    with local_api("default") as (base, token):
        assert base.startswith("http://127.0.0.1:")
        with httpx.Client(trust_env=False, timeout=30) as client:
            assert client.get(f"{base}/tui/pages").status_code == 401
            ok = client.get(f"{base}/tui/pages", headers={"Authorization": f"Bearer {token}"})
            assert ok.status_code == 200 and ok.json()["focus"]["incident"] == "INC-001"


def test_cli_tui_without_binary(raf_home: Path, cli: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from raf.apps.cli.commands import tui

    monkeypatch.setattr(tui, "find_binary", lambda: None)
    missing = cli("tui", "--dump", "home")
    assert missing.exit_code == 6 and "cargo build --release" in missing.stderr
    assert cli("tui", "--page", "nowhere").exit_code == 4
    assert cli("tui").exit_code == 4  # not a terminal: suggests --dump


FAKE_PANEL = """#!{python}
import json, os, sys, urllib.request
api, token = os.environ["RAF_OS_API"], os.environ["RAF_OS_TOKEN"]
request = urllib.request.Request(api + "/tui/screen/blast?ref=alice", headers={"Authorization": "Bearer " + token})
with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=60) as response:
    title = json.load(response)["title"]
report = {
    "argv": sys.argv[1:],
    "title": title,
    "workspace": os.environ.get("RAF_OS_WORKSPACE"),
    "api_token_passed": "RAF_API_TOKEN" in os.environ,
    "loopback": api.startswith("http://127.0.0.1:"),
}
with open(os.environ["FAKE_PANEL_REPORT"], "w") as out:
    json.dump(report, out)
sys.exit(int(os.environ.get("FAKE_PANEL_EXIT", "0")))
"""


def test_launcher_runs_the_panel_against_its_api(
    raven_home: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """`raf tui` hands the panel a loopback API, its one-time token and the workspace, nothing else."""
    from raf.apps.cli.commands import tui
    from tests.conftest import run_cli

    panel = tmp_path / "raf-os"
    panel.write_text(FAKE_PANEL.replace("{python}", sys.executable))
    panel.chmod(0o755)
    report = tmp_path / "report.json"
    monkeypatch.setenv("RAF_HOME", str(raven_home))
    monkeypatch.setenv("FAKE_PANEL_REPORT", str(report))
    monkeypatch.setenv("RAF_API_TOKEN", "not-for-the-panel")
    monkeypatch.setattr(tui, "find_binary", lambda: panel)
    result = run_cli("tui", "--dump", "blast", "--param", "alice", "--width", "120")
    assert result.exit_code == 0, result.stderr
    data = json.loads(report.read_text())
    assert data["argv"] == ["--dump", "blast", "--width", "120", "--param", "alice"]
    assert data["title"] == "R$F BLAST — alice" and data["workspace"] == "default"
    assert data["loopback"] and not data["api_token_passed"]
    monkeypatch.setenv("FAKE_PANEL_EXIT", "3")
    assert run_cli("tui", "--dump", "home").exit_code == 3  # the panel's failure is raf's failure
