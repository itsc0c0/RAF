from __future__ import annotations

import warnings
from pathlib import Path
from typing import Any

import pytest

from raf.core.errors import RafError
from raf.core.objects.models import ObjectDraft

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from fastapi.testclient import TestClient

from raf.apps.api.app import create_app


@pytest.fixture
def client(raf_home: Path) -> Any:
    app = create_app(env={"RAF_HOME": str(raf_home)})
    with TestClient(app) as c:
        yield c


def test_health_status_openapi(client: Any) -> None:
    assert client.get("/api/v1/health").json()["status"] == "ok"
    status = client.get("/api/v1/status").json()
    assert status["workspace"] == "default"
    spec = client.get("/api/v1/openapi.json").json()
    assert "/api/v1/objects" in spec["paths"]


def test_objects_and_errors(client: Any) -> None:
    pool = client.app.state.pool
    pool.get(None).store.objects.upsert_drafts([ObjectDraft.make("host", "WS-01"), ObjectDraft.make("user", "x")])
    listing = client.get("/api/v1/objects", params={"type": "host"}).json()
    assert listing["total"] == 1 and listing["items"][0]["id"] == "host:ws-01"
    assert client.get("/api/v1/objects/WS-01").json()["object"]["id"] == "host:ws-01"
    assert client.get("/api/v1/objects/host:ws-01/pivots").status_code == 200
    missing = client.get("/api/v1/objects/nope")
    assert missing.status_code == 404 and missing.json()["error"]["code"] == "raf.not_found"
    bad = client.get("/api/v1/objects", params={"limit": 5000})
    assert bad.status_code == 422 and bad.json()["error"]["code"] == "raf.invalid_request"
    search = client.get("/api/v1/search", params={"q": "ws"}).json()
    assert search["objects"][0]["id"] == "host:ws-01"


def test_dns_rebinding_protection(client: Any) -> None:
    assert client.get("/api/v1/health", headers={"host": "attacker.example"}).status_code == 403
    assert client.get("/api/v1/health", headers={"host": "127.0.0.1:8765"}).status_code == 200


def test_remote_bind_requires_token(raf_home: Path) -> None:
    with pytest.raises(RafError):
        create_app(env={"RAF_HOME": str(raf_home)}, host="0.0.0.0")
    app = create_app(
        env={"RAF_HOME": str(raf_home)}, host="0.0.0.0", token="s3cret-token", allowed_hosts={"raf.internal"}
    )
    with TestClient(app) as c:
        assert c.get("/api/v1/status", headers={"host": "raf.internal"}).status_code == 401
        ok = c.get("/api/v1/status", headers={"host": "raf.internal", "authorization": "Bearer s3cret-token"})
        assert ok.status_code == 200


def test_workspace_scoping(client: Any) -> None:
    assert client.post("/api/v1/workspaces", json={"name": "lab"}).status_code == 201
    pool = client.app.state.pool
    pool.get("lab").store.objects.upsert_drafts([ObjectDraft.make("host", "LAB-1")])
    assert client.get("/api/v1/objects", params={"workspace": "lab"}).json()["total"] == 1
    assert client.get("/api/v1/objects", headers={"X-RAF-Workspace": "lab"}).json()["total"] == 1
    assert client.get("/api/v1/objects").json()["total"] == 0
    assert client.get("/api/v1/objects", params={"workspace": "../x"}).status_code == 422
