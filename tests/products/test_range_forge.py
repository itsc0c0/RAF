"""Range (synthetic organizations, lifecycle, purge) and Forge (telemetry, scenarios)."""

from __future__ import annotations

import json
import warnings
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from raf.core.context.app import RafContext
from raf.core.errors import ConflictError, InvalidInputError, NotFoundError
from raf.core.storage.repos.events import EventQuery
from raf.data.synth import OrgConfig, TelemetryWindow, build_org, generate, inventory_records, scenario

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from fastapi.testclient import TestClient

from raf.apps.api.app import create_app

DAY = datetime(2026, 10, 5, tzinfo=UTC)


def test_synthetic_org_is_deterministic_and_marked() -> None:
    config = OrgConfig(name="acme", employees=12, workstations=10, servers=3, services=["dns", "web", "database"])
    a, b = build_org(config, 7), build_org(config, 7)
    assert inventory_records(a) == inventory_records(b)
    assert inventory_records(a) != inventory_records(build_org(config, 8))
    assert len(a.users) == 12 and len(a.workstation_users()) == 10 and len(a.servers()) >= 3
    assert all(r.get("synthetic") for r in inventory_records(a))
    assert a.domain == "acme.example"
    with pytest.raises(InvalidInputError):
        OrgConfig(name="x", services=["teleporter"]).validate()


def test_generators_and_scenarios_are_synthetic_and_safe() -> None:
    org = build_org(OrgConfig(name="acme"), 1)
    window = TelemetryWindow.of(DAY, 24)
    for kind in ("auth", "dns", "web", "process", "file", "identity", "cloud"):
        records = generate(kind, org, count=50, window=window, seed=3, noise=0.5)
        assert len(records) == 50 and all(r["synthetic"] for r in records)
        assert records == generate(kind, org, count=50, window=window, seed=3, noise=0.5)
    built = scenario("suspicious-access", org, seed=99, start=DAY)
    text = json.dumps(built.records)
    assert built.incident["name"] == "SIM-SUSPICIOUS-ACCESS-99"
    assert ".example" in text and "203.0.113." in text  # reserved domains / documentation ranges only
    assert all(r["synthetic"] and "forge" in r["tags"] for r in built.records)


def test_range_raven_lifecycle(ctx: RafContext) -> None:
    from raf.products.range.service import RangeService

    service = RangeService(ctx)
    created = service.create("raven", seed=42)
    assert created.state.preset == "raven" and ctx.store.objects.get("user:alice") is not None
    with pytest.raises(ConflictError):
        service.create("raven")
    with pytest.raises(ConflictError):
        service.tick("raven")  # not running yet
    run = service.start("raven", hours=24)
    assert run.state.status == "running" and run.state.clock == datetime(2026, 10, 6, tzinfo=UTC)
    events = ctx.store.events.count(EventQuery(job_ids=run.state.jobs))
    assert events > 100 and ctx.store.events.count(EventQuery(synthetic=True)) == events
    assert service.stop("raven").status == "stopped"
    status = service.status("raven")
    assert status["live"]["events"] == events and status["organization"]["employees"] == 6
    destroyed = service.destroy("raven")
    assert destroyed.purged is not None and destroyed.purged.events == events
    assert ctx.store.objects.get("user:alice") is None and ctx.store.events.count() == 0
    with pytest.raises(NotFoundError):
        service.get("raven")


def test_range_purge_keeps_shared_data(ctx: RafContext) -> None:
    from raf.analysis.ingest import import_records
    from raf.products.range.service import RangeService

    import_records(ctx, [{"kind": "object", "type": "user", "name": "alice", "metadata": {"note": "real HR record"}}],
                   source_name="hr-export", title="HR export")
    service = RangeService(ctx)
    service.create("raven", seed=1)
    service.reset("raven")
    service.destroy("raven")
    alice = ctx.store.objects.get("user:alice")
    assert alice is not None and alice.metadata.get("note") == "real HR record"
    assert ctx.store.objects.get("host:ws-01") is None


def test_range_generic_config_and_validation(ctx: RafContext, tmp_path: Path) -> None:
    from raf.products.range.service import RangeService, load_config_file

    config_file = tmp_path / "acme.yaml"
    config_file.write_text("name: acme\nemployees: 8\nworkstations: 6\nservers: 2\ndepartments: [engineering, hr]\n"
                           "services: [dns, git]\nsecurity controls:\n  mfa: 0.5\n  segmentation: false\n",
                           encoding="utf-8")
    service = RangeService(ctx)
    run = service.create("acme", seed=5, config=load_config_file(config_file))
    status = service.status("acme")
    assert status["organization"]["employees"] == 8 and status["organization"]["controls"]["segmentation"] is False
    assert run.report is not None and run.report.objects_created > 20
    service.start("acme", hours=10)
    reset = service.reset("acme")
    assert reset.state.periods == 0 and reset.purged is not None and reset.purged.events > 0
    with pytest.raises(InvalidInputError):
        service.create("bad name!")
    with pytest.raises(InvalidInputError):
        service.create("other", config={"teleporters": 3})
    with pytest.raises(InvalidInputError):
        service.create("raven", config={"employees": 3})


def test_forge_uses_workspace_population(raven: RafContext, tmp_path: Path) -> None:
    from raf.products.forge.service import ForgeService

    service = ForgeService(raven)
    result = service.scenario("credential-risk", seed=5)
    assert result.population == "workspace" and result.incident == "SIM-CREDENTIAL-RISK-5" and result.job
    users = {u.id for u in raven.store.objects.iter_all(types=["user"])}
    assert f"user:{result.subject}" in users
    # the modeled credential placement became part of the graph (IAM can now see it)
    uses = [r for r in raven.store.relationships.iter_all(types=["USES"])
            if r.metadata.get("credential_location", "").endswith("/project/.env")]
    assert uses
    out = tmp_path / "dns.jsonl"
    written = service.telemetry("dns", count=25, seed=1, output=out, ingest=False)
    assert written.job is None and len(out.read_text().splitlines()) == 25
    with pytest.raises(InvalidInputError):
        service.telemetry("dns", count=0, seed=1)
    with pytest.raises(InvalidInputError):
        service.scenario("ransomware", seed=1)


def test_cli_range_and_forge(raf_home: Path, cli: Any, tmp_path: Path) -> None:
    created = cli("range", "create", "raven", "--seed", "42", "--json")
    assert created.exit_code == 0, created.stderr
    assert created.json()["state"]["seed"] == 42
    assert cli("range", "start", "raven", "--hours", "12").exit_code == 0
    status = cli("range", "status", "raven", "--json").json()
    assert status["state"]["status"] == "running" and status["live"]["events"] > 0
    forge = cli("forge", "scenario", "suspicious-access", "--seed", "99", "--json")
    assert forge.exit_code == 0 and forge.json()["incident"] == "SIM-SUSPICIOUS-ACCESS-99"
    auth = cli("forge", "auth", "--count", "200", "--seed", "3")
    assert auth.exit_code == 0 and "200 synthetic record(s)" in auth.stdout
    assert cli("forge", "list").exit_code == 0
    assert cli("range", "destroy", "raven").exit_code != 0  # needs confirmation
    assert cli("range", "destroy", "raven", "--yes").exit_code == 0
    bad = cli("forge", "teleport")
    assert bad.exit_code != 0


@pytest.fixture
def api(raf_home: Path) -> Iterator[Any]:
    with TestClient(create_app(env={"RAF_HOME": str(raf_home)})) as client:
        yield client


def test_api_range_and_forge(api: Any) -> None:
    created = api.post("/api/v1/range/ranges", json={"name": "lab-org", "preset": "small-office", "seed": 3})
    assert created.status_code == 200, created.text
    assert api.post("/api/v1/range/ranges/lab-org/start", json={"hours": 4}).status_code == 200
    assert api.get("/api/v1/range/ranges").json()["items"][0]["status"] == "running"
    generated = api.post("/api/v1/forge/generate", json={"kind": "web", "count": 50, "seed": 2}).json()
    assert generated["records"] == 50 and generated["population"] == "workspace"
    assert api.post("/api/v1/forge/generate", json={"kind": "web", "count": 10**7}).status_code == 422
    assert api.delete("/api/v1/range/ranges/lab-org").status_code == 200
    assert api.get("/api/v1/range/ranges/lab-org").status_code == 404
