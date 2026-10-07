"""Object routes answer references to events, findings and snapshots with a clear error, never a 500."""

from __future__ import annotations

import warnings
from pathlib import Path

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from fastapi.testclient import TestClient

from raf.apps.api.app import create_app


def test_object_routes_refuse_events_findings_and_snapshots(raven_home: Path) -> None:
    with TestClient(create_app(env={"RAF_HOME": str(raven_home)}, serve_ui=False), base_url="http://127.0.0.1") as api:
        event = api.get("/api/v1/events", params={"limit": 1}).json()["items"][0]["id"]
        finding = api.get("/api/v1/findings", params={"limit": 1}).json()["items"][0]["id"]
        cases = [
            (event, "an event", "events"),
            (finding, "a finding", "findings"),
            ("snapshot:s1", "a snapshot", "snapshots"),
        ]
        for ref, kind, route in cases:
            for suffix in ("", "/pivots"):
                response = api.get(f"/api/v1/objects/{ref}{suffix}")
                assert response.status_code == 422, (ref, suffix, response.text)
                error = response.json()["error"]
                assert error["code"] == "raf.invalid_input"
                assert error["message"] == f"'{ref}' is {kind}, not an object."
                assert error["hint"] == f"Use GET /api/v1/{route}/{ref}."
        assert api.get(f"/api/v1/events/{event}").status_code == 200
        assert api.get(f"/api/v1/findings/{finding}").status_code == 200
        assert api.get("/api/v1/objects/WS-02").json()["object"]["id"] == "host:ws-02"
        assert api.get("/api/v1/objects/WS-02/pivots").json()["object_id"] == "host:ws-02"
