from __future__ import annotations

import warnings
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from fastapi.testclient import TestClient

from raf.apps.api.app import create_app


@pytest.fixture
def api(raven_home: Path) -> Iterator[Any]:
    with TestClient(create_app(env={"RAF_HOME": str(raven_home)})) as client:
        yield client


def test_graph_routes(api: Any) -> None:
    view = api.get("/api/v1/graph/view", params={"ref": "alice", "depth": 1}).json()
    assert view["scope"]["id"] == "user:alice" and view["nodes"]
    neighbors = api.get("/api/v1/graph/neighbors", params={"ref": "WS-01"}).json()
    assert neighbors["nodes"]
    path = api.get("/api/v1/graph/path", params={"source": "bob", "target": "DB-01"}).json()
    assert path["found"]
    assert api.get("/api/v1/graph/export", params={"ref": "INC-001", "format": "dot"}).text.startswith("digraph")
    assert api.get("/api/v1/graph/view", params={"ref": "nobody"}).status_code == 404
    assert api.get("/api/v1/graph/view", params={"depth": 99}).status_code == 422


def test_timeline_routes(api: Any) -> None:
    data = api.get("/api/v1/timeline", params={"ref": "INC-001", "limit": 10}).json()
    assert data["total"] > 20 and len(data["items"]) == 10 and data["next_cursor"]
    nxt = api.get("/api/v1/timeline", params={"ref": "INC-001", "limit": 10, "cursor": data["next_cursor"]}).json()
    assert nxt["items"][0]["id"] != data["items"][0]["id"]
    export = api.get("/api/v1/timeline/export", params={"ref": "INC-001", "format": "csv"})
    assert export.status_code == 200 and export.text.startswith("timestamp,")


def test_replay_trace_diff_snapshot_routes(api: Any) -> None:
    replay = api.get("/api/v1/replay/INC-001").json()
    assert replay["steps"] and replay["final_state_hash"]
    state = api.get("/api/v1/replay/INC-001/state", params={"at": "2026-10-06T23:05:00Z"}).json()
    assert state["sessions"]
    trace = api.get("/api/v1/trace/svc-deploy", params={"direction": "back"}).json()
    assert trace["backward"]
    assert api.post("/api/v1/snapshots", json={"name": "s1"}).status_code == 201
    assert api.post("/api/v1/snapshots", json={"name": "s1"}).status_code == 409
    diff = api.get("/api/v1/diff", params={"a": "s1", "b": "current"}).json()
    assert diff["totals"]["changes"] == 0
    assert api.delete("/api/v1/snapshots/s1").status_code == 200
