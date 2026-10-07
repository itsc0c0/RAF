"""Ghost: models, what-if operations (min cut), comparisons, state provider and API."""

from __future__ import annotations

import warnings
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from raf.core.context.app import RafContext
from raf.core.errors import ConflictError, InvalidInputError, NotFoundError

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from fastapi.testclient import TestClient

from raf.apps.api.app import create_app


def test_min_cut_prefers_credential_exposure() -> None:
    from raf.products.ghost.ops import _Arc, min_cut

    arcs = [
        _Arc("a", "b", 3, "rel:grant", True, ""),
        _Arc("b", "c", 1, "rel:cred", True, ""),
        _Arc("c", "t", 50, "rel:struct", True, ""),
        _Arc("a", "c", 1, "rel:session", True, ""),
    ]
    cut = min_cut(arcs, "a", "t")
    assert {arc.rel for arc in cut} == {"rel:cred", "rel:session"}


def test_remove_access_cuts_all_paths_and_explains(raven: RafContext) -> None:
    from raf.products.ghost.ops import _controls
    from raf.products.ghost.service import GhostService

    service = GhostService(raven)
    service.create("hardened")
    model, applied = service.modify("hardened", [("remove-access", "alice:production")])
    op = applied[0]
    assert op.effects.removed_relationships and op.explanation
    assert all("credential exposure" in line for line in op.explanation)
    state = service.materialize(model)
    assert not _controls(state, "user:alice", "cloud_resource:production")
    # the workspace itself is untouched
    current = service.current_state()
    assert _controls(current, "user:alice", "cloud_resource:production")
    assert all(rid in current.relationships for rid in op.effects.removed_relationships)


def test_model_lifecycle_clone_undo_delete(raven: RafContext) -> None:
    from raf.products.ghost.service import GhostService

    service = GhostService(raven)
    base = service.create("prod-model", description="baseline")
    assert base.base_snapshot == "ghost-prod-model-base"
    with pytest.raises(ConflictError):
        service.create("prod-model")
    with pytest.raises(InvalidInputError):
        service.create("current")
    service.modify("prod-model", [("disable-identity", "old-admin")])
    clone = service.clone("prod-model", "experiment-01")
    assert clone.parent == "prod-model" and len(clone.ops) == 1
    _model, removed = service.undo("experiment-01")
    assert removed.op == "disable-identity" and not service.get("experiment-01").ops
    with pytest.raises(InvalidInputError):
        service.undo("experiment-01")
    service.delete("experiment-01")
    assert service.snapshots.get("ghost-prod-model-base") is not None  # still used by prod-model
    service.delete("prod-model")
    assert service.snapshots.get("ghost-prod-model-base") is None
    with pytest.raises(NotFoundError):
        service.get("prod-model")


def test_operations_validate_against_the_model(raven: RafContext) -> None:
    from raf.products.ghost.service import GhostService

    service = GhostService(raven)
    service.create("m")
    with pytest.raises(InvalidInputError):
        service.modify("m", [("remove-access", "carol:production")])  # no path to cut
    with pytest.raises(InvalidInputError):
        service.modify("m", [("remove-role", "alice:break-glass")])  # inherited, not direct
    with pytest.raises(NotFoundError):
        service.modify("m", [("isolate", "no-such-host")])
    with pytest.raises(InvalidInputError):
        service.modify("m", [("explode", "x")])
    model, applied = service.modify(
        "m",
        [
            ("change-role", "group:operations:break-glass:helpdesk"),
            ("remove-exposure", "VPN-01"),
            ("disable-rule", "raven-fw:r40-dev-to-prod"),
            ("deny-flow", "CORP:DEV:tcp/443"),
        ],
    )
    assert [a.op for a in applied] == ["change-role", "remove-exposure", "disable-rule", "deny-flow"]
    state = service.materialize(model)
    assert not state.rels(source="group:operations", target="role:break-glass", types=["HAS_ROLE"])
    assert state.rels(source="host:vpn-01", target="network:dmz-internal", types=["MEMBER_OF"])
    assert not state.rels(source="network:dev", target="network:prod", types=["CAN_REACH"])
    trimmed = state.rels(source="network:corp", target="network:dev", types=["CAN_REACH"])
    assert trimmed and trimmed[0].metadata["ports"] == ["tcp/22"]
    policy = state.objects["policy:raven-fw"].metadata["policy"]
    assert policy["rules"][0]["id"] == "ghost-deny-1"
    assert next(r for r in policy["rules"] if r["id"] == "r40-dev-to-prod")["enabled"] is False


def test_compare_and_snapshot_from_model(raven: RafContext) -> None:
    from raf.analysis.providers import install_state_providers
    from raf.core.snapshots.service import SnapshotService, resolve_state
    from raf.products.diff.service import DiffService
    from raf.products.ghost.service import GhostService

    service = GhostService(raven)
    SnapshotService(raven.store).create("before")
    service.clone("current", "hardened")
    service.modify("hardened", [("remove-access", "alice:production")])
    comparison = service.compare("current", "hardened")
    assert comparison.delta["attack_paths"] < 0 and comparison.delta["critical_paths"] < 0
    alice = next(u for u in comparison.users if u["id"] == "user:alice")
    assert alice["after"] == 0 and "cloud_resource:production" in alice["lost"]
    install_state_providers(raven)
    state = resolve_state(raven, "ghost:hardened")
    SnapshotService(raven.store).create_from_state("after", state, source="ghost:hardened")
    diff = DiffService(raven).diff("before", "after")
    removed = [c for c in diff.changes if c.change == "removed"]
    assert len(removed) == len(diff.changes) == 3  # only the what-if effects, findings carried over


def test_cli_ghost_flow(raven_home: Path, cli: Any) -> None:
    assert cli("ghost", "clone", "current", "hardened").exit_code == 0
    result = cli("ghost", "modify", "hardened", "--remove-access", "alice:production", "--json")
    assert result.exit_code == 0, result.stderr
    assert result.json()["applied"][0]["op"] == "remove-access"
    compare = cli("ghost", "compare", "current", "hardened")
    assert compare.exit_code == 0 and "BASELINE" in compare.stdout and "CHANGE" in compare.stdout
    snap = cli("snapshot", "create", "after", "--source", "ghost:hardened")
    assert snap.exit_code == 0, snap.stderr
    listing = cli("ghost", "list", "--json").json()
    assert listing["items"][0]["name"] == "hardened"
    assert cli("ghost", "delete", "hardened").exit_code != 0  # needs confirmation
    assert cli("ghost", "delete", "hardened", "--yes").exit_code == 0
    bad = cli("ghost", "modify", "nope", "--isolate", "WS-01")
    assert bad.exit_code != 0 and "does not exist" in bad.stderr


@pytest.fixture
def api(raven_home: Path) -> Iterator[Any]:
    with TestClient(create_app(env={"RAF_HOME": str(raven_home)})) as client:
        yield client


def test_api_ghost(api: Any) -> None:
    assert api.post("/api/v1/ghost/models", json={"name": "baseline"}).status_code == 200
    assert api.post("/api/v1/ghost/models/baseline/clone", json={"name": "exp"}).status_code == 200
    applied = api.post("/api/v1/ghost/models/exp/ops", json={"op": "isolate", "arg": "DEV-01"}).json()
    assert applied["applied"][0]["effects"]["removed_relationships"]
    models = api.get("/api/v1/ghost/models").json()["items"]
    assert {m["name"] for m in models} == {"baseline", "exp"}
    compare = api.get("/api/v1/ghost/compare", params={"a": "baseline", "b": "exp"}).json()
    assert set(compare["a_metrics"]) >= {
        "attack_paths",
        "critical_paths",
        "reachable_assets",
        "entry_points",
        "exposed_critical_assets",
    }
    assert api.post("/api/v1/ghost/models/exp/ops", json={"op": "nope", "arg": "x"}).status_code == 422
    assert api.delete("/api/v1/ghost/models/exp").status_code == 200
