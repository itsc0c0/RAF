"""Lens: scoped exploration with groups, histograms, involved objects, findings and pivots."""

from __future__ import annotations

import warnings
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from raf.core.context.app import RafContext

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from fastapi.testclient import TestClient

from raf.apps.api.app import create_app


def test_lens_object_scope(raven: RafContext) -> None:
    from raf.products.lens.service import LensService

    service = LensService(raven)
    result = service.query(service.scope_for(["10.30.0.5"]), limit=10)
    assert result.total > 50 and len(result.items) == 10 and result.histogram
    assert {"ip", "host"} <= {i["type"] for i in result.involved}
    top = {t["id"] for t in result.top_objects}
    assert "host:app-01" in top and "ip:10.30.0.5" not in top  # the scope itself is not a "related" object
    assert result.relationships and result.pivots["host:app-01"][0]["product"] == "graph"
    assert any(p["product"] == "exposure" for p in result.pivots["host:app-01"])


def test_lens_filters_sources_and_evidence(raven: RafContext) -> None:
    from raf.products.lens.service import LensService

    service = LensService(raven)
    failures = service.query(service.scope_for(["INC-001"]), filter_text="outcome=failure", group_by="actor")
    assert failures.total > 0 and all(e.outcome == "failure" for e in failures.items)
    assert failures.groups and failures.group_by == "actor"
    capture = service.query(service.scope_for([]), source="raven-inc001.pcap")
    assert capture.total == 9 and {e.parser for e in capture.items} == {"pcap/1.0"}
    evidence = next(o for o in raven.store.objects.iter_all(types=["evidence"]) if o.name == "proxy.csv")
    by_item = service.query(service.scope_for([evidence.id]))
    assert by_item.total == 4 and all(
        e.raw_reference and e.raw_reference.startswith("evidence:") for e in by_item.items
    )
    empty = service.query(service.scope_for([]), filter_text="type=nothing.here")
    assert empty.total == 0 and empty.top_objects == [] and empty.histogram == []


def test_cli_lens(raven_home: Path, cli: Any) -> None:
    result = cli("lens", "APP-01", "--limit", "5")
    assert result.exit_code == 0, result.stderr
    assert "MOST INVOLVED" in result.stdout and "raf graph" in result.stdout
    data = cli("lens", "--source", "proxy.csv", "--json").json()
    assert data["schema"] == "raf.lens/v1" and data["total"] == 4
    assert cli("lens", "no-such-thing").exit_code != 0


@pytest.fixture
def api(raven_home: Path) -> Iterator[Any]:
    with TestClient(create_app(env={"RAF_HOME": str(raven_home)})) as client:
        yield client


def test_api_lens(api: Any) -> None:
    data = api.get("/api/v1/lens/query", params={"ref": "INC-001", "group_by": "event_type", "limit": 5}).json()
    assert set(data) >= {"scope", "total", "items", "groups", "histogram", "involved", "top_objects", "names"}
    assert data["scope"]["kind"] == "incident" and len(data["items"]) == 5
    assert api.get("/api/v1/lens/query", params={"limit": 0}).status_code == 422
