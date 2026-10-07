from __future__ import annotations

from pathlib import Path
from typing import Any


def test_graph_commands(cli: Any, raven_home: Path) -> None:
    view = cli("graph", "user", "alice", "--json").json()
    assert view["schema"] == "raf.graph/v1" and view["scope"]["id"] == "user:alice"
    human = cli("graph", "alice")
    assert human.exit_code == 0 and "MEMBER_OF" in human.stdout
    path = cli("graph", "path", "alice", "production", "--json").json()
    assert path["found"] and path["length"] >= 1
    assert cli("graph", "neighbors", "WS-01").exit_code == 0
    assert cli("graph", "stats", "--json").json()["total_objects"] > 300
    out = raven_home / "g.graphml"
    assert cli("graph", "export", "INC-001", "--format", "graphml", "--output", str(out)).exit_code == 0
    assert out.read_text().startswith("<?xml")
    assert cli("graph", "path", "alice").exit_code == 4


def test_last_reference(cli: Any, raven_home: Path) -> None:
    assert cli("graph", "user", "alice", "-q").exit_code == 0
    assert cli("graph", "@last", "--json").json()["scope"]["id"] == "user:alice"


def test_timeline_and_trace(cli: Any, raven_home: Path) -> None:
    timeline = cli("timeline", "INC-001", "--json", "--limit", "5").json()
    assert timeline["total"] > 20 and len(timeline["items"]) == 5
    filtered = cli("timeline", "user", "alice", "--filter", "type:auth.login", "--json").json()
    assert all(i["event_type"] == "auth.login" for i in filtered["items"])
    trace = cli("trace", "svc-deploy", "--direction", "back", "--json").json()
    assert any(link["relation"] == "CREDENTIAL_EXPOSURE" for link in trace["backward"])
    assert "correlated" in cli("trace", "svc-deploy", "--direction", "back").stdout


def test_snapshot_diff_replay(cli: Any, raven_home: Path) -> None:
    assert cli("snapshot", "create", "before").exit_code == 0
    assert cli("snapshot", "create", "after").exit_code == 0
    diff = cli("diff", "before", "after", "--json").json()
    assert diff["schema"] == "raf.diff/v1" and diff["totals"]["changes"] == 0
    assert "No differences" in cli("diff", "before", "after").stdout
    listing = cli("snapshot", "list", "--json").json()
    assert [s["name"] for s in listing["items"]] == ["before", "after"]
    assert cli("snapshot", "delete", "after", "--yes").exit_code == 0
    replay = cli("replay", "INC-001", "--json").json()
    assert replay["schema"] == "raf.replay/v1" and len(replay["steps"]) > 20
    state = cli("replay", "INC-001", "--at", "23:05", "--json").json()
    assert any(s["user"] == "user:bob" for s in state["sessions"])
    assert "Active sessions" in cli("replay", "INC-001", "--at", "23:05").stdout
    window = cli("replay", "INC-001", "--from", "23:00", "--to", "23:10", "--json").json()
    assert window["events"] > 5
    assert cli("replay", "INC-001", "--speed", "3").exit_code == 4


def test_bundle_cli(cli: Any, raven_home: Path) -> None:
    target = raven_home / "inc.raf"
    assert cli("timeline", "INC-001", "--export", str(target), "--format", "raf").exit_code == 0
    assert cli("bundle", "verify", str(target)).exit_code == 0
    assert cli("workspace", "create", "copy").exit_code == 0
    imported = cli("bundle", "import", str(target), "--workspace", "copy", "--json").json()
    assert imported["imported"]["events"] > 20
