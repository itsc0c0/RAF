"""Evidence: hashing, read-only storage, chain of custody, tamper detection, incident linking."""

from __future__ import annotations

import stat
import warnings
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from raf.core.context.app import RafContext
from raf.core.errors import ConflictError, InvalidInputError, NotFoundError
from raf.core.storage.repos.events import EventQuery
from tests.conftest import FIXTURES

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from fastapi.testclient import TestClient

from raf.apps.api.app import create_app


def test_custody_chain_detects_tampering() -> None:
    from raf.products.evidence.store import append_custody, verify_custody

    chain: list[Any] = []
    append_custody(chain, "acquired", "cli:analyst", {"sha256": "a" * 64})
    append_custody(chain, "stored", "cli:analyst", {"store": "aa/aaa"})
    assert verify_custody(chain) == (True, None)
    chain[0] = chain[0].model_copy(update={"details": {"sha256": "b" * 64}})
    ok, reason = verify_custody(chain)
    assert not ok and "altered" in (reason or "")


def test_import_preserves_originals_and_links_window(raven: RafContext, tmp_path: Path) -> None:
    from raf.products.evidence.service import EvidenceService

    service = EvidenceService(raven)
    case = service.get_case("INC-001")  # created by the demo step
    assert case.incident == "incident:inc-001"
    items = service.items("INC-001")
    assert {i.name for i in items} >= {"auth.log", "proxy.csv", "edr-process-events.jsonl", "analyst-notes.txt"}
    auth = next(i for i in items if i.name == "auth.log")
    stored = service.store.path_for(auth.stored)
    assert not stored.stat().st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)  # read-only copy
    assert [c.action for c in auth.custody][:3] == ["acquired", "stored", "parsed"]
    job_events = raven.store.events.query(EventQuery(job_ids=[auth.job or ""]), limit=500).items
    assert all(e.raw_reference and e.raw_reference.startswith("evidence:ev-") for e in job_events)
    events = [e for e in job_events if (e.raw_reference or "").startswith(f"evidence:{auth.id}#")]
    assert len(events) == auth.events
    incident = raven.store.incidents.get("incident:inc-001")
    assert incident is not None and incident.start and incident.end
    linked = {e.id for e in raven.store.events.query(EventQuery(incident_id="incident:inc-001"), limit=5000).items}
    inside = [e for e in job_events if incident.start <= e.timestamp <= incident.end]
    outside = [e for e in job_events if not incident.start <= e.timestamp <= incident.end]
    assert outside and not any(e.id in linked for e in outside)  # only events inside the window are linked
    assert inside and all(e.id in linked for e in inside)
    notes = next(i for i in items if i.name == "analyst-notes.txt")
    assert notes.status == "unparsed" and notes.type == "text"
    # the original stays untouched and importing the same content again deduplicates the stored copy
    original = tmp_path / "auth.log"
    original.write_bytes((FIXTURES / "evidence" / "auth.log").read_bytes())
    before = original.stat().st_mtime
    again = service.import_path(original, "INC-001", parse=False)
    assert again.items[0].sha256 == auth.sha256 and again.items[0].stored == auth.stored
    assert original.stat().st_mtime == before and original.read_bytes() == stored.read_bytes()


def test_verify_detects_modified_copy(ctx: RafContext, tmp_path: Path) -> None:
    from raf.products.evidence.service import EvidenceService

    service = EvidenceService(ctx)
    service.create_case("CASE-1")
    artifact = tmp_path / "notes.txt"
    artifact.write_text("first line\n", encoding="utf-8")
    item = service.import_path(artifact, "CASE-1").items[0]
    assert service.verify(case="CASE-1").verified
    stored = service.store.path_for(item.stored)
    stored.chmod(0o600)
    stored.write_text("tampered\n", encoding="utf-8")
    result = service.verify(case="CASE-1")
    assert not result.verified and "mismatch" in result.items[0]["reason"]
    refreshed = service.get_item(item.id)
    assert refreshed.custody[-1].action == "verified" and refreshed.custody[-1].details["ok"] is False
    with pytest.raises(InvalidInputError):
        service.export(item.id, tmp_path / "out.txt")  # never export unverifiable evidence


def test_cases_notes_derived_and_errors(ctx: RafContext, tmp_path: Path) -> None:
    from raf.products.evidence.service import EvidenceService

    service = EvidenceService(ctx)
    service.create_case("INC-042", title="Test")
    with pytest.raises(ConflictError):
        service.create_case("inc-042")
    with pytest.raises(InvalidInputError):
        service.create_case("../escape")
    with pytest.raises(NotFoundError):
        service.import_path(tmp_path, "NOPE")
    source = tmp_path / "memory.bin"
    source.write_bytes(b"\x00\x01binary")
    parent = service.import_path(source, "INC-042").items[0]
    derived_file = tmp_path / "strings.txt"
    derived_file.write_text("strings extracted from memory.bin\n", encoding="utf-8")
    child = service.import_path(derived_file, "INC-042", derived_from=parent.id).items[0]
    assert child.derived_from == parent.id and any(c.action == "derived" for c in child.custody)
    assert ctx.store.relationships.between(f"evidence:{child.id}", f"evidence:{parent.id}")
    noted = service.note(parent.id, "Acquired from the analyst workstation")
    assert noted.custody[-1].action == "note"
    link = tmp_path / "link.txt"
    link.symlink_to(derived_file)
    skipped = service.import_path(tmp_path, "INC-042", parse=False).skipped
    assert any("symbolic" in s["reason"] for s in skipped)
    exported_item, target = service.export(child.id, tmp_path / "exported.txt")
    assert target.read_bytes() == derived_file.read_bytes() and exported_item.custody[-1].action == "exported"


def test_cli_evidence(raf_home: Path, cli: Any) -> None:
    assert cli("evidence", "case", "create", "INC-007").exit_code == 0
    imported = cli("evidence", "import", str(FIXTURES / "evidence"), "--case", "INC-007", "--json")
    assert imported.exit_code == 0, imported.stderr
    assert len(imported.json()["items"]) == 4
    listing = cli("evidence", "list", "--case", "INC-007")
    assert listing.exit_code == 0 and "auth.log" in listing.stdout
    verify = cli("evidence", "verify", "--case", "INC-007")
    assert verify.exit_code == 0 and "All evidence verified" in verify.stdout
    show = cli("evidence", "show", imported.json()["items"][0]["id"])
    assert show.exit_code == 0 and "Chain of custody" in show.stdout
    assert cli("evidence", "import", "/nonexistent", "--case", "INC-007").exit_code != 0
    # A failed verification reaches the shell as exit status 5.
    item = imported.json()["items"][0]
    stored = next(p for p in raf_home.rglob(f"{item['sha256']}*") if p.is_file())
    stored.chmod(0o600)
    stored.write_bytes(b"tampered\n")
    tampered = cli("evidence", "verify", "--case", "INC-007")
    assert tampered.exit_code == 5 and "FAILED" in tampered.stdout + tampered.stderr


@pytest.fixture
def api(raf_home: Path) -> Iterator[Any]:
    with TestClient(create_app(env={"RAF_HOME": str(raf_home)})) as client:
        yield client


def test_api_evidence(api: Any) -> None:
    assert api.post("/api/v1/evidence/cases", json={"name": "INC-100", "title": "API case"}).status_code == 200
    upload = api.post(
        "/api/v1/evidence/cases/INC-100/items",
        files={"file": ("proxy.csv", (FIXTURES / "evidence" / "proxy.csv").read_bytes(), "text/csv")},
    )
    assert upload.status_code == 200, upload.text
    item_id = upload.json()["items"][0]["id"]
    case = api.get("/api/v1/evidence/cases/INC-100").json()
    assert case["item_count"] == 1 and case["items"][0]["sha256"]
    item = api.get(f"/api/v1/evidence/items/{item_id}").json()
    assert item["custody"][0]["action"] == "acquired" and item["acquired_at"]
    verified = api.post("/api/v1/evidence/cases/INC-100/verify").json()
    assert verified["verified"] and verified["items"][0]["ok"]
    assert api.get("/api/v1/evidence/cases/NOPE").status_code == 404
