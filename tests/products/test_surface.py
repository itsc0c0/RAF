"""R$F Surface: authorized scope, inventory formats, untrusted input, rules on the Raven fixture,
re-analysis, views, CLI, API and the ``raf import`` parser."""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import socket
import warnings
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml

from raf.core.context.app import RafContext
from raf.core.errors import ConflictError, InvalidInputError, NotFoundError, ResourceLimitExceeded
from raf.core.objects.types import FindingStatus
from raf.data import raven as raven_data
from raf.products.surface import formats, sample
from raf.products.surface.convert import build
from raf.products.surface.formats import parse_document
from raf.products.surface.model import (
    MAX_DOCUMENT_BYTES,
    clean_text,
    is_internal_address,
    name_covers,
    parse_endpoint,
)
from raf.products.surface.parser import SurfaceInventoryParser, sniff_surface
from raf.products.surface.rules import RULES
from raf.products.surface.scope import Scope, ScopeEntry, normalize_target
from raf.products.surface.service import SurfaceService
from tests.conftest import FIXTURES

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from fastapi.testclient import TestClient

from raf.apps.api.app import create_app

FIXTURE = FIXTURES / "surface" / "raven-surface.json"
NEWEST_RAVEN_EVENT = datetime(2026, 10, 7, 1, 6, tzinfo=UTC)
OBSERVED = datetime(2026, 10, 7, tzinfo=UTC)
FP = "ab" * 32
RLO = chr(0x202E)  # right-to-left override

#: A small inventory with every record kind; string values only, so every format carries the same data.
MINI: list[dict[str, str]] = [
    {"kind": "domain", "name": "example-co.example", "owner": "Web team", "registrar": "example-registrar"},
    {"kind": "dns", "name": "www.example-co.example", "type": "A", "value": "192.0.2.10", "ttl": "300"},
    {"kind": "dns", "name": "cdn.example-co.example", "type": "CNAME", "value": "example-co.cdn.example"},
    {"kind": "dns", "name": "example-co.example", "type": "MX", "value": "10 mx.mail.example"},
    {"kind": "dns", "name": "example-co.example", "type": "TXT", "value": "v=spf1 -all"},
    {"kind": "ip", "address": "192.0.2.10", "owner": "Web team", "host": "WEB-A", "asn": "64500"},
    {
        "kind": "service",
        "ip": "192.0.2.10",
        "port": "443",
        "protocol": "tcp",
        "product": "nginx",
        "internet_facing": "true",
        "server": "WEB-A",
    },
    {
        "kind": "certificate",
        "subject_cn": "www.example-co.example",
        "sans": "www.example-co.example;example-co.example",
        "issuer": "Example CA",
        "not_after": "2027-01-01T00:00:00Z",
        "fingerprint_sha256": FP,
        "presented_by": "192.0.2.10:443",
    },
    {
        "kind": "cloud_asset",
        "provider": "examplecloud",
        "account": "co-prod",
        "type": "bucket",
        "name": "co-files",
        "public": "false",
        "owner": "Web team",
    },
    {"kind": "owner", "owner": "Web team", "asset": "domain:www.example-co.example"},
]


def mini_documents() -> dict[str, bytes]:
    columns = list(dict.fromkeys(key for record in MINI for key in record))
    handle = io.StringIO()
    writer = csv.DictWriter(handle, fieldnames=columns)
    writer.writeheader()
    writer.writerows(MINI)
    header = {"format": "raf-surface/1"}
    return {
        "json": json.dumps({**header, "records": MINI}).encode(),
        "jsonl": "\n".join(json.dumps(r) for r in [header, *MINI]).encode(),
        "yaml": yaml.safe_dump({**header, "records": MINI}, sort_keys=False).encode(),
        "csv": handle.getvalue().encode(),
    }


def by_rule(findings: list[Any]) -> dict[tuple[str, str], str]:
    return {(f.rule_id, f.affected_objects[0]): f.severity.value for f in findings}


@pytest.fixture
def raven_surface(raven: RafContext) -> SurfaceService:
    service = SurfaceService(raven)
    # raf demo load already imported this inventory and applied its scope: importing it again is
    # idempotent (same objects, scope entries unchanged).
    result = service.import_file(FIXTURE, apply_scope=True)
    assert result.rejected == 0 and result.accepted == result.records == 52
    assert [c.result for c in result.scope_changes] == ["unchanged"] * 4
    return service


# --------------------------------------------------------------------------- fixture and generator


def test_fixture_matches_generator_and_generation_is_deterministic() -> None:
    assert FIXTURE.read_text(encoding="utf-8") == sample.raven_surface_json(), (
        "fixtures/surface/raven-surface.json is stale: raf surface sample fixtures/surface/raven-surface.json --yes"
    )
    assert json.loads(FIXTURE.read_text(encoding="utf-8")) == sample.raven_surface_document()
    assert sample.raven_surface_json() == sample.raven_surface_json()


def test_fixture_uses_reserved_names_and_matches_the_raven_organization() -> None:
    document = sample.raven_surface_document()
    strings: list[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
        elif isinstance(value, str):
            strings.append(value)

    walk(document)
    documentation = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
    for text in strings:
        candidate = text.split(":")[0]
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        # public addresses are RFC 5737 documentation addresses; internal ones come from raven.DOMAINS
        assert any(address in net for net in documentation) or is_internal_address(candidate), text
    names = [r["name"] for r in document["records"] if r["kind"] in ("domain", "dns")]
    assert names and all(name.endswith(".example") for name in names)
    dns = {(r["name"], r["value"]) for r in document["records"] if r["kind"] == "dns" and r["type"] == "A"}
    for name, address in raven_data.DOMAINS.items():
        assert (name, address) in dns
    public = {h["name"]: h["public_ip"] for h in raven_data.HOSTS if h.get("public_ip")}
    assert ("www.raven.example", public["WEB-01"]) in dns and ("vpn.raven.example", public["VPN-01"]) in dns
    # the authorized range must not claim the INC-001 exfiltration server (198.51.100.23) as Raven's
    assert ipaddress.ip_address(raven_data.EXFIL_IP) not in ipaddress.ip_network("198.51.100.0/28")


# --------------------------------------------------------------------------- scope


def test_scope_targets_are_normalized_and_validated() -> None:
    assert normalize_target("Raven.Example.") == ("raven.example", "domain")
    assert normalize_target("198.51.100.7/28") == ("198.51.100.0/28", "cidr")
    assert normalize_target("198.51.100.20") == ("198.51.100.20", "ip")
    assert normalize_target("2001:DB8::1") == ("2001:db8::1", "ip")
    assert normalize_target("2001:db8::/48") == ("2001:db8::/48", "cidr")
    assert normalize_target("examplecloud:Raven-Prod") == ("examplecloud:raven-prod", "cloud_account")
    assert normalize_target("198.51.100.20", "cidr") == ("198.51.100.20/32", "cidr")
    for bad, kind in [
        ("*.raven.example", None),
        ("0.0.0.0/0", None),
        ("10.0.0.0/7", None),
        ("2001:db8::/16", None),
        ("example", None),
        ("not a domain!", None),
        ("198.51.100.0/33", None),
        ("raven.example", "bogus"),
        ("198.51.100.20", "domain"),
        ("examplecloud:", None),
        ("", None),
    ]:
        with pytest.raises(InvalidInputError):
            normalize_target(bad, kind)


def test_scope_coverage_semantics() -> None:
    now = datetime(2026, 10, 7, tzinfo=UTC)

    def entry(target: str, kind: str) -> ScopeEntry:
        return ScopeEntry(target=target, kind=kind, added_at=now)

    scope = Scope(
        [
            entry("raven.example", "domain"),
            entry("dev.raven.example", "domain"),
            entry("198.51.100.0/24", "cidr"),
            entry("198.51.100.0/28", "cidr"),
            entry("203.0.113.7", "ip"),
            entry("2001:db8::/48", "cidr"),
            entry("examplecloud:raven-prod", "cloud_account"),
        ]
    )
    assert scope.configured and scope.summary(2) == "dev.raven.example, raven.example (+5 more)"
    assert scope.match_domain("raven.example").target == "raven.example"  # type: ignore[union-attr]
    assert scope.match_domain("a.b.raven.example").target == "raven.example"  # type: ignore[union-attr]
    assert scope.match_domain("x.dev.raven.example").target == "dev.raven.example"  # type: ignore[union-attr]
    assert scope.match_domain("*.raven.example") is not None
    assert scope.match_domain("notraven.example") is None
    assert scope.match_domain("raven.example.attacker.example") is None
    assert scope.match_ip("198.51.100.5").target == "198.51.100.0/28"  # type: ignore[union-attr]
    assert scope.match_ip("198.51.100.200").target == "198.51.100.0/24"  # type: ignore[union-attr]
    assert scope.match_ip("198.51.101.1") is None
    assert scope.match_ip("203.0.113.7") is not None and scope.match_ip("203.0.113.8") is None
    assert scope.match_ip("2001:db8::abcd") is not None and scope.match_ip("2001:db9::1") is None
    assert scope.match_ip("not-an-ip") is None
    assert scope.match_cloud("examplecloud", "raven-prod") is not None
    assert scope.match_cloud("examplecloud", "other") is None and scope.match_cloud(None, "raven-prod") is None
    assert not Scope([]).configured


def test_scope_store_add_replace_remove(ctx: RafContext) -> None:
    service = SurfaceService(ctx)
    entry, result = service.add_scope("raven.example", owner="IT operations", authorization="SEC-1")
    assert result == "added" and entry.kind == "domain"
    assert service.add_scope("raven.example", owner="IT operations", authorization="SEC-1")[1] == "unchanged"
    with pytest.raises(ConflictError):
        service.add_scope("raven.example", owner="Someone else")
    assert service.add_scope("raven.example", owner="Platform", replace=True)[1] == "replaced"
    service.add_scope("198.51.100.0/28", owner="Network")
    service.add_scope("examplecloud:raven-prod")
    assert [e.target for e in service.scope_entries()] == [
        "raven.example",
        "198.51.100.0/28",
        "examplecloud:raven-prod",
    ]
    stored = ctx.store.kv.items("surface.scope")
    assert set(stored) == {"raven.example", "198.51.100.0/28", "examplecloud:raven-prod"}
    assert stored["raven.example"]["owner"] == "Platform" and stored["raven.example"]["authorization"] is None
    assert service.remove_scope("198.51.100.7/28").target == "198.51.100.0/28"  # normalized like on add
    with pytest.raises(NotFoundError):
        service.remove_scope("198.51.100.0/28")
    operations = [entry.operation for entry in ctx.audit.list(limit=20)]
    assert "surface.scope.remove" in operations and "surface.scope.add" in operations


# --------------------------------------------------------------------------- formats


def test_every_format_yields_the_same_records_and_objects(ctx: RafContext, tmp_path: Path) -> None:
    documents = mini_documents()
    natives = {
        fmt: [n.data for n in build(parse_document(data, fmt), observed=OBSERVED).natives]
        for fmt, data in documents.items()
    }
    assert natives["json"] and all(records == natives["json"] for records in natives.values())
    conversion = build(parse_document(documents["csv"], "csv"), observed=OBSERVED)
    assert conversion.accepted == len(MINI) and not conversion.rejected
    assert conversion.by_kind == {
        "certificate": 1,
        "cloud_asset": 1,
        "dns": 4,
        "domain": 1,
        "ip": 1,
        "owner": 1,
        "service": 1,
    }
    service = SurfaceService(ctx)
    created: dict[str, tuple[int, int]] = {}
    for fmt, data in documents.items():
        path = tmp_path / f"inventory.{'yml' if fmt == 'yaml' else fmt}"
        path.write_bytes(data)
        result = service.import_file(path)
        assert result.format == fmt and result.accepted == len(MINI) and result.rejected == 0, result.rejections
        created[fmt] = (result.objects_created, result.relationships_created)
    assert created["json"][0] > 0 and created["json"][1] > 0
    assert created["jsonl"] == created["yaml"] == created["csv"] == (0, 0)  # same model: nothing new
    store = ctx.store
    cert = store.objects.get(f"certificate:{FP}")
    assert cert is not None and cert.metadata["sans"] == ["www.example-co.example", "example-co.example"]
    apex = store.objects.require("domain:example-co.example")
    assert apex.metadata["txt"] == ["v=spf1 -all"] and apex.metadata["owner"] == "Web team"
    assert sorted(apex.metadata["surface"]["sources"]) == ["certificate", "dns", "inventory"]
    relationships = {
        (r.source_object, r.relationship_type, r.target_object) for r in store.relationships.list(limit=500)
    }
    assert ("domain:www.example-co.example", "RESOLVES_TO", "ip:192.0.2.10") in relationships
    assert ("domain:www.example-co.example", "PART_OF", "domain:example-co.example") in relationships
    assert ("service:192.0.2.10:443/tcp", "LISTENS_ON", "port:192.0.2.10:443") in relationships
    assert ("port:192.0.2.10:443", "PRESENTS", f"certificate:{FP}") in relationships
    assert (f"certificate:{FP}", "ISSUED_FOR", "domain:example-co.example") in relationships
    assert ("host:web-a", "RUNS", "service:192.0.2.10:443/tcp") in relationships
    assert ("organization:web team", "OWNS", "domain:www.example-co.example") in relationships
    assert ("domain:example-co.example", "RELATED_TO", "domain:mx.mail.example") in relationships
    provenance = store.provenance.for_subject("domain:www.example-co.example")
    assert provenance and provenance[0].parser == "raf-surface/1.0" and provenance[0].job_id


def test_document_sections_and_header_fields() -> None:
    document = parse_document(
        json.dumps(
            {
                "format": "raf-surface/1",
                "organization": "Example Co",
                "as_of": "2026-10-01",
                "domains": [{"name": "a.example"}],
                "dns": [{"name": "www.a.example", "type": "A", "value": "192.0.2.1"}],
                "services": [{"kind": "ip", "address": "192.0.2.1"}],
                "surprise": 1,
            }
        ).encode(),
        "json",
    )
    assert document.organization == "Example Co" and document.as_of == datetime(2026, 10, 1, tzinfo=UTC)
    assert any("surprise" in w for w in document.warnings)
    conversion = build(document, observed=OBSERVED)
    assert conversion.accepted == 2
    assert [r.locator for r in conversion.rejected] == ["services[0]"]
    assert "does not match its section" in conversion.rejected[0].reason


# --------------------------------------------------------------------------- untrusted input


def test_untrusted_documents_are_refused_with_readable_errors(ctx: RafContext, tmp_path: Path) -> None:
    service = SurfaceService(ctx)
    big = tmp_path / "big.json"
    with big.open("wb") as handle:
        handle.truncate(MAX_DOCUMENT_BYTES + 1)  # sparse file: the size check comes before reading
    with pytest.raises(ResourceLimitExceeded):
        service.import_file(big)
    with pytest.raises(ResourceLimitExceeded):
        parse_document(b" " * (MAX_DOCUMENT_BYTES + 1), "json")
    with pytest.raises(NotFoundError):
        service.import_file(tmp_path / "missing.json")
    with pytest.raises(InvalidInputError):
        service.import_file(tmp_path)  # a directory
    cases: list[tuple[bytes, str, str]] = [
        (b"records: [unclosed", "yaml", "not valid YAML"),
        (b"a: &x [1, 2]\nrecords: *x\n", "yaml", "aliases are not allowed"),
        (b"!!python/object/apply:os.system ['true']", "yaml", "not valid YAML"),
        (b"[" * 100_000, "json", "nested too deeply"),
        (b"[" * 100_000, "yaml", "nested too deeply"),
        (b"{not json", "json", "not valid JSON"),
        (b'{"format": "raf-surface/9", "records": []}', "json", "Unsupported inventory format"),
        (b'{"records": {"kind": "domain"}}', "json", "'records' must be a list"),
        (b"42", "json", "must be a raf-surface/1 document"),
        (b"name,type\nwww.a.example,A\n", "csv", "needs a 'kind' column"),
        (b"", "csv", "empty"),
    ]
    for data, fmt, message in cases:
        with pytest.raises(InvalidInputError) as caught:
            service.import_bytes(data, fmt=fmt)
        assert message in caught.value.message, (data[:40], caught.value.message)
    assert ctx.store.objects.count() == 0  # nothing was imported by refused documents


def test_bad_records_are_rejected_into_the_report(ctx: RafContext) -> None:
    records: list[Any] = [
        {"kind": "domain", "name": "good.example", "notes": "line\x1b[2Jclear" + RLO + "evil\x07 text"},
        {"kind": "domain", "name": {"$ne": 1}},
        {"kind": "domain", "name": "evil\x1b[31m.example"},
        {"kind": "vulnerability", "name": "CVE-0000-0000"},
        {"kind": ["dns"]},
        {"name": "no-kind.example"},
        ["a", "list"],
        "a string",
        7,
        {"kind": "service", "ip": "198.51.100.1", "port": [443]},
        {"kind": "service", "ip": "198.51.100.1", "port": "70000"},
        {"kind": "service", "host": "JUMP-01", "port": 22},
        {"kind": "dns", "name": "a.example", "type": "SRV", "value": "x"},
        {"kind": "dns", "name": "a.example", "type": "A", "value": "2001:db8::1"},
        {"kind": "dns", "name": "a.example", "type": "CNAME", "value": "a.example"},
        {"kind": "certificate", "subject_cn": "x.example"},
        {"kind": "certificate", "subject_cn": "x.example", "fingerprint_sha256": "zz"},
        {"kind": "cloud_asset", "provider": "examplecloud", "type": "bucket", "name": "a/b"},
        {"kind": "owner", "owner": "Team", "asset": "something odd"},
        {"kind": "owner", "owner": "Team", "asset": "cloud_asset:not-in-this-file"},
        {"kind": "domain", "name": "x" * 70 + ".example"},
        {"kind": "domain", "name": "nested.example", "tags": [{"deep": [1, [2, [3]]]}]},
        {"kind": "domain", **{f"field{i}": i for i in range(80)}},
    ]
    service = SurfaceService(ctx)
    result = service.import_bytes(json.dumps(records).encode())
    assert result.accepted == 1 and result.rejected == len(records) - 1
    reasons = {r.record: r.reason for r in result.rejections}
    assert "'name' must be text, not an object" in reasons["[1]"]
    assert "not a valid host name" in reasons["[2]"]
    assert "Unknown record kind 'vulnerability'" in reasons["[3]"]
    assert "'kind' must be text, not a list" in reasons["[4]"]
    assert "has no 'kind'" in reasons["[5]"]
    assert "got a list" in reasons["[6]"] and "got str" in reasons["[7]"] and "got int" in reasons["[8]"]
    assert "port number" in reasons["[9]"] and "port number" in reasons["[10]"]
    assert "needs an endpoint" in reasons["[11]"]
    assert "Unsupported DNS record type" in reasons["[12]"] and "IPv4" in reasons["[13]"]
    assert "cannot point to itself" in reasons["[14]"]
    assert "fingerprint_sha256, or issuer and serial" in reasons["[15]"] and "64 hexadecimal" in reasons["[16]"]
    assert "must not contain '/'" in reasons["[17]"]
    assert "Cannot tell what kind of asset" in reasons["[18]"] and "No cloud asset named" in reasons["[19]"]
    assert "not a valid host name" in reasons["[20]"] and "entries must be text" in reasons["[21]"]
    assert "fields (limit 64)" in reasons["[22]"]
    good = ctx.store.objects.require("domain:good.example")
    notes = good.metadata["notes"]
    assert "\x1b" not in notes and RLO not in notes and "\x07" not in notes and "clear" in notes
    job = ctx.jobs.require(result.job_id or "")
    assert job.result is not None and job.result["rejected"] == len(records) - 1
    quarantine = Path(job.result["rejects_file"]).read_text(encoding="utf-8").splitlines()
    assert len(quarantine) == len(records) - 1 and "\x1b" not in "".join(quarantine)


def test_foreign_data_is_sanitized_in_views(ctx: RafContext, cli: Any) -> None:
    from raf.core.ingestion.pipeline import IngestionPipeline

    escape = "\x1b[2J\x1b[31m"
    foreign = [
        {"kind": "object", "type": "host", "name": f"EVIL{escape}HOST", "metadata": {"owner": f"mallory{escape}"}},
        {"kind": "relationship", "source": f"host:EVIL{escape}HOST", "type": "HAS_ADDRESS", "target": "ip:192.0.2.10"},
    ]
    IngestionPipeline(ctx).ingest_records(foreign, source_name="other-tool.json")
    service = SurfaceService(ctx)
    service.add_scope("192.0.2.0/28", authorization="T-1")
    service.import_bytes(json.dumps([{"kind": "ip", "address": "192.0.2.10"}]).encode())
    (asset,) = service.assets(kind="ip")[0]
    (owner,) = asset.owners  # inherited from the foreign host; the escape character is neutralized
    assert owner.startswith("mallory") and "\x1b" not in owner
    assert asset.owner_via is not None and "\x1b" not in asset.owner_via
    assert "\x1b" not in asset.summary and all("\x1b" not in h for h in asset.details["hosts"])
    shown = cli("surface", "assets")
    assert shown.exit_code == 0 and "EVIL" in shown.stdout and "\x1b" not in shown.stdout


def test_record_limit_and_framing_errors(ctx: RafContext, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(formats, "MAX_RECORDS", 3)
    lines = [
        '{"format": "raf-surface/1"}',
        "{broken",
        *[json.dumps({"kind": "domain", "name": f"d{i}.example"}) for i in range(5)],
    ]
    result = SurfaceService(ctx).import_bytes("\n".join(lines).encode(), fmt="jsonl")
    assert result.accepted == 3
    reasons = {r.record: r.reason for r in result.rejections}
    assert "Malformed JSON" in reasons["line 2"]
    assert "2 records beyond the limit of 3" in reasons["document"]


def test_value_helpers() -> None:
    assert clean_text(" a\x00b" + chr(0x200B) + "c" + chr(0x2028) + "d ", "x") == "a b c d"
    assert clean_text("x" * 300, "x", limit=10, truncate=True) == "xxxxxxx..."
    with pytest.raises(InvalidInputError):
        clean_text("x" * 300, "x", limit=10)
    assert name_covers("*.raven.example", "www.raven.example")
    assert not name_covers("*.raven.example", "raven.example")
    assert not name_covers("*.raven.example", "a.b.raven.example")
    endpoint = parse_endpoint("[2001:DB8::1]:8443/udp")
    assert (endpoint.address, endpoint.port, endpoint.transport, endpoint.port_key) == (
        "2001:db8::1",
        8443,
        "udp",
        "[2001:db8::1]:8443/udp",
    )
    assert parse_endpoint("shop.raven.example").port == 443
    assert is_internal_address("10.1.2.3") and is_internal_address("::ffff:192.168.1.1")
    assert not is_internal_address("198.51.100.10")  # documentation ranges stand in for public addresses


# --------------------------------------------------------------------------- rules on the Raven fixture


def test_rules_on_the_raven_fixture(raven_surface: SurfaceService) -> None:
    analysis = raven_surface.analyze()
    assert analysis.reference_time == NEWEST_RAVEN_EVENT and analysis.reference_source.startswith("newest event")
    fingerprint = sample.fingerprint
    expected = {
        ("out-of-scope-asset", "domain:raven-launch.example"): "MEDIUM",
        ("unowned-asset", "domain:ci.raven.example"): "LOW",
        ("unowned-asset", "service:198.51.100.12:3389/tcp"): "HIGH",
        ("expired-certificate", f"certificate:{fingerprint('shop')}"): "HIGH",
        ("expiring-certificate", f"certificate:{fingerprint('api')}"): "MEDIUM",
        ("certificate-name-mismatch", "port:198.51.100.10:443"): "HIGH",
        ("dangling-dns", "domain:legacy-ftp.raven.example"): "MEDIUM",
        ("exposed-sensitive-service", "service:198.51.100.12:3389/tcp"): "CRITICAL",
        ("exposed-sensitive-service", "service:198.51.100.11:22/tcp"): "LOW",
        ("public-cloud-storage", "cloud_resource:examplecloud/raven-prod/bucket/raven-public-assets"): "LOW",
        ("shadow-asset", "domain:staging.raven.example"): "MEDIUM",
        ("shadow-asset", "domain:jump.raven.example"): "LOW",
        ("internal-address-in-dns", "domain:dc01.raven.example"): "MEDIUM",
    }
    assert by_rule(analysis.findings) == expected
    assert set(analysis.by_rule) == set(RULES)
    # the demo created the 13 findings; this analysis finds the same ones again
    assert analysis.created == 0 and analysis.updated == 13 and analysis.resolved == 0 and analysis.out_of_scope == 2
    findings = {f.rule_id + "|" + f.affected_objects[0]: f for f in analysis.findings}
    for finding in analysis.findings:
        assert finding.id.startswith(f"finding:surface:{finding.rule_id}:") and finding.product == "surface"
        assert finding.description and finding.recommendation and finding.evidence
        assert finding.explanation and all({"factor", "label", "sign"} <= set(e) for e in finding.explanation)
        assert finding.explanation[0]["label"].endswith(")")  # the baseline is stated
    launch = findings["out-of-scope-asset|domain:raven-launch.example"]
    assert "domain:www.raven-launch.example" in launch.affected_objects
    assert any("Marketing" in e["label"] for e in launch.explanation)
    rdp = findings["exposed-sensitive-service|service:198.51.100.12:3389/tcp"]
    ssh = findings["exposed-sensitive-service|service:198.51.100.11:22/tcp"]
    assert rdp.severity.rank > ssh.severity.rank  # RDP on a critical, unowned host > SSH on a bastion
    assert any(e["factor"] == "bastion" and e["sign"] == "-" for e in ssh.explanation)
    assert any(e["factor"] == "criticality" for e in rdp.explanation) and "host:jump-01" in rdp.affected_objects
    mismatch = findings["certificate-name-mismatch|port:198.51.100.10:443"]
    assert mismatch.metadata["names"] == ["vpn.raven.example"]
    assert any(e["factor"] == "self-signed" for e in mismatch.explanation)
    expiring = findings[f"expiring-certificate|certificate:{fingerprint('api')}"]
    assert expiring.metadata["days"] == 21 and "2026-10-28" in expiring.description
    dangling = findings["dangling-dns|domain:legacy-ftp.raven.example"]
    assert "decommissioned" in dangling.description and dangling.confidence < 0.8
    internal = findings["internal-address-in-dns|domain:dc01.raven.example"]
    assert any("DC-01" in e["label"] for e in internal.explanation)
    staging = findings["shadow-asset|domain:staging.raven.example"]
    assert any(e["factor"] == "unknown-system" for e in staging.explanation)


def test_reanalysis_is_idempotent_and_resolves_fixed_issues(raven_surface: SurfaceService) -> None:
    service = raven_surface
    store = service.ctx.store
    first = service.analyze()
    again = service.analyze()
    assert [f.id for f in again.findings] == [f.id for f in first.findings]
    assert again.created == 0 and again.resolved == 0 and again.updated == len(first.findings)
    ids = {(f.rule_id, f.affected_objects[0]): f.id for f in first.findings}
    acknowledged = ids[("shadow-asset", "domain:jump.raven.example")]
    store.findings.set_status(acknowledged, FindingStatus.ACKNOWLEDGED, "known leftover")

    # an owner for the jump host's RDP service and the removal of the dangling record
    fixes = [
        {"kind": "owner", "owner": "IT operations", "asset": "service:198.51.100.12:3389/tcp"},
        {
            "kind": "dns",
            "name": "legacy-ftp.raven.example",
            "type": "CNAME",
            "value": "ftp-old.raven.example",
            "status": "removed",
        },
    ]
    service.import_bytes(json.dumps(fixes).encode())
    fixed = service.analyze()
    assert fixed.resolved == 2
    assert (
        store.findings.require(ids[("unowned-asset", "service:198.51.100.12:3389/tcp")]).status
        == FindingStatus.RESOLVED
    )
    assert (
        store.findings.require(ids[("dangling-dns", "domain:legacy-ftp.raven.example")]).status
        == FindingStatus.RESOLVED
    )
    assert store.findings.require(acknowledged).status == FindingStatus.ACKNOWLEDGED  # analyst decisions stick
    rdp = next(
        f for f in fixed.findings if f.id == ids[("exposed-sensitive-service", "service:198.51.100.12:3389/tcp")]
    )
    assert rdp.severity.value == "CRITICAL" and not any(e["factor"] == "no-owner" for e in rdp.explanation)
    legacy = store.relationships.list(source="domain:legacy-ftp.raven.example", types=["RESOLVES_TO"])
    assert legacy and legacy[0].valid_to is not None  # ended, not deleted

    # later reference time: the API certificate has expired
    later = service.analyze(at=datetime(2026, 10, 29, tzinfo=UTC))
    rules = by_rule(later.findings)
    api_cert = f"certificate:{sample.fingerprint('api')}"
    assert ("expired-certificate", api_cert) in rules and ("expiring-certificate", api_cert) not in rules

    # scope removal: the cloud account is no longer authorized
    service.remove_scope("examplecloud:raven-prod")
    narrowed = service.analyze()
    rules = by_rule(narrowed.findings)
    assert not any(rule == "public-cloud-storage" for rule, _ in rules)
    outside = {subject for rule, subject in rules if rule == "out-of-scope-asset"}
    assert "cloud_resource:examplecloud/raven-prod/bucket/raven-backups" in outside
    bucket = "cloud_resource:examplecloud/raven-prod/bucket/raven-public-assets"
    assert bucket in outside
    bucket_finding = next(f for f in narrowed.findings if f.affected_objects[0] == bucket)
    assert "domain:raven-public-assets.storage.examplecloud.example" in bucket_finding.affected_objects  # folded


def test_rule_context_and_edge_cases(ctx: RafContext) -> None:
    service = SurfaceService(ctx)
    for target in ("corp.example", "192.0.2.0/28", "examplecloud:corp"):
        service.add_scope(target, owner="IT", authorization="T-1")
    records: list[dict[str, Any]] = [
        {"kind": "domain", "name": "corp.example", "owner": "IT"},
        # CNAME to a third-party name nobody inventoried and that does not resolve: claimable
        {"kind": "dns", "name": "promo.corp.example", "type": "CNAME", "value": "corp-promo.pages-host.example"},
        # A record to an address outside the scope that no inventory knows
        {"kind": "dns", "name": "old.corp.example", "type": "A", "value": "203.0.113.99"},
        # CNAME to a name that only resolves in the internal view
        {"kind": "dns", "name": "wiki.corp.example", "type": "CNAME", "value": "wiki-int.corp.example"},
        {"kind": "dns", "name": "wiki-int.corp.example", "type": "A", "value": "10.1.1.1", "view": "internal"},
        {"kind": "dns", "name": "www.corp.example", "type": "A", "value": "192.0.2.5"},
        {"kind": "domain", "name": "www.corp.example", "owner": "user:frank"},
        {"kind": "ip", "address": "192.0.2.5", "owner": "IT"},
        {
            "kind": "certificate",
            "subject_cn": "*.corp.example",
            "fingerprint_sha256": "cd" * 32,
            "not_after": "2030-01-01",
            "presented_by": "192.0.2.5:443",
        },
        {
            "kind": "service",
            "ip": "192.0.2.5",
            "port": 5432,
            "product": "PostgreSQL 16",
            "internet_facing": True,
            "owner": "Data",
            "criticality": "critical",
        },
        {
            "kind": "service",
            "ip": "192.0.2.5",
            "port": 8443,
            "product": "Redis 7 behind a TLS proxy",
            "internet_facing": True,
            "owner": "Data",
        },
        {
            "kind": "cloud_asset",
            "provider": "examplecloud",
            "account": "corp",
            "type": "bucket",
            "name": "corp-db-backup",
            "public": True,
            "owner": "Data",
            "classification": "confidential",
        },
    ]
    imported = service.import_bytes(json.dumps(records).encode())
    assert imported.rejected == 0
    analysis = service.analyze(at=OBSERVED)
    rules = by_rule(analysis.findings)
    assert rules == {
        ("dangling-dns", "domain:promo.corp.example"): "HIGH",
        ("dangling-dns", "domain:old.corp.example"): "HIGH",
        ("dangling-dns", "domain:wiki.corp.example"): "MEDIUM",
        ("exposed-sensitive-service", "service:192.0.2.5:5432/tcp"): "CRITICAL",
        ("exposed-sensitive-service", "service:192.0.2.5:8443/tcp"): "HIGH",
        ("public-cloud-storage", "cloud_resource:examplecloud/corp/bucket/corp-db-backup"): "CRITICAL",
    }  # no name mismatch: *.corp.example covers www.corp.example
    findings = {f.affected_objects[0]: f for f in analysis.findings}
    assert any(e["factor"] == "takeover" for e in findings["domain:promo.corp.example"].explanation)
    assert any(e["factor"] == "released-address" for e in findings["domain:old.corp.example"].explanation)
    assert "internal-view records" in findings["domain:wiki.corp.example"].description
    assert "product 'Redis 7 behind a TLS proxy'" in findings["service:192.0.2.5:8443/tcp"].explanation[0]["label"]
    bucket = findings["cloud_resource:examplecloud/corp/bucket/corp-db-backup"]
    assert {e["factor"] for e in bucket.explanation} >= {"public-storage", "classification", "name"}
    owners = ctx.store.relationships.list(source="user:frank", types=["OWNS"])
    assert [r.target_object for r in owners] == ["domain:www.corp.example"]


def test_without_scope_nothing_is_owned(ctx: RafContext) -> None:
    service = SurfaceService(ctx)
    result = service.import_file(FIXTURE)
    assert result.scope_declared == 4 and not result.scope_applied and not service.scope_entries()
    analysis = service.analyze(at=OBSERVED)
    assert analysis.findings == [] and analysis.reference_source == "given"
    assert any("No authorized scope" in note for note in analysis.notes)
    summary = service.summary(at=OBSERVED)
    assert not summary.scope_configured and summary.in_scope == 0 and summary.unscoped == summary.assets > 0
    empty = SurfaceService(ctx).analyze(at=OBSERVED, persist=False)
    assert not empty.persisted


def test_views_tree_assets_and_ownership(raven_surface: SurfaceService) -> None:
    raven_surface.analyze()
    summary = raven_surface.summary()
    assert summary.scope_configured and summary.by_kind == {
        "certificate": 4,
        "cloud_asset": 3,
        "domain": 20,
        "ip": 4,
        "service": 4,
    }
    assert summary.out_of_scope == 2 and summary.findings_open == 13 and summary.owners
    roots = {node["name"]: node for node in summary.tree}
    assert set(roots) == {"raven.example", "raven-launch.example"}
    assert roots["raven-launch.example"]["scope"] == "out" and roots["raven-launch.example"]["claimed_owners"]
    children = {child["name"]: child for child in roots["raven.example"]["children"]}
    www = children["www.raven.example"]["records"][0]
    assert www["type"] == "A" and www["hosts"] == ["WEB-01"] and www["services"][0]["name"] == "web"
    states = {cert["name"]: cert["state"] for cert in www["certificates"]}
    assert states == {"www.raven.example": "valid", "shop.raven.example": "expired"}
    api = children["api.raven.example"]["records"][0]
    assert api["type"] == "CNAME" and api["cloud"][0]["name"] == "raven-api-lb"
    assert api["certificates"][0]["state"] == "expiring"
    assert roots["raven.example"]["txt"] == ["v=spf1 include:mail.provider.example -all"]
    certificates, total = raven_surface.assets(kind="certificate")
    assert total == 4
    owners = {a.name: (a.owners, a.owner_via) for a in certificates}
    assert owners["shop.raven.example"] == (["Platform"], "service web")
    assert owners["api.raven.example"] == (["Platform"], None)  # owner record
    outside, _ = raven_surface.assets(scope="out")
    assert {a.name for a in outside} == {"raven-launch.example", "www.raven-launch.example"}
    assert next(a for a in outside if a.name == "raven-launch.example").claimed_owners == ["Marketing"]
    addresses = {a.name: a for a in raven_surface.assets(kind="ip")[0]}
    assert addresses["198.51.100.10"].owners == ["IT operations"] and addresses["198.51.100.10"].internet_facing
    references, _ = raven_surface.assets(kind="ip", include_references=True)
    assert "198.51.100.13" in {a.name for a in references}
    with pytest.raises(InvalidInputError):
        raven_surface.assets(kind="bogus")
    with pytest.raises(InvalidInputError):
        raven_surface.assets(scope="sideways")


def test_no_network_access(raven: RafContext, monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("R$F Surface must not touch the network")

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(socket, "gethostbyname", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)
    service = SurfaceService(raven)
    service.import_file(FIXTURE, apply_scope=True)
    assert len(service.analyze().findings) == 13
    assert service.summary().tree


# --------------------------------------------------------------------------- CLI


def test_cli_scope_commands(cli: Any) -> None:
    added = cli(
        "surface", "scope", "add", "raven.example", "--owner", "IT operations", "--authorization", "SEC-1", "--json"
    )
    assert added.exit_code == 0, added.stderr
    assert added.json()["schema"] == "raf.surface.scope.entry/v1" and added.json()["result"] == "added"
    human = cli("surface", "scope", "add", "198.51.100.0/28", "--owner", "Network")
    assert human.exit_code == 0 and "authorization" in human.stderr  # warns: no authorization reference
    listed = cli("surface", "scope", "list", "--json").json()
    assert listed["schema"] == "raf.surface.scope/v1" and [e["target"] for e in listed["items"]] == [
        "raven.example",
        "198.51.100.0/28",
    ]
    refused = cli("surface", "scope", "remove", "raven.example")
    assert refused.exit_code == 4 and "--yes" in refused.stderr
    removed = cli("surface", "scope", "remove", "raven.example", "--yes", "--json")
    assert removed.exit_code == 0 and removed.json()["result"] == "removed"
    assert [e["target"] for e in cli("surface", "scope", "list", "--json").json()["items"]] == ["198.51.100.0/28"]
    missing = cli("surface", "scope", "remove", "nowhere.example", "--yes")
    assert missing.exit_code == 3 and "Traceback" not in missing.stderr
    invalid = cli("surface", "scope", "add", "0.0.0.0/0")
    assert invalid.exit_code == 4 and "too broad" in invalid.stderr and "Traceback" not in invalid.stderr
    conflict = cli("surface", "scope", "add", "198.51.100.0/28", "--owner", "Other", "--json")
    assert conflict.exit_code == 4 and conflict.json()["error"]["code"] == "raf.conflict"


def test_cli_on_an_empty_workspace(cli: Any) -> None:
    shown = cli("surface")
    assert shown.exit_code == 0 and "not configured" in shown.stdout and "raf surface import" in shown.stdout
    analysis = cli("surface", "analyze", "--json").json()
    assert analysis["findings"] == [] and analysis["reference_source"] == "current time" and analysis["notes"]
    assert cli("surface", "assets").exit_code == 0 and cli("surface", "findings").exit_code == 0


def test_cli_import_analyze_show_assets(raven_home: Path, cli: Any, tmp_path: Path) -> None:
    imported = cli("surface", "import", str(FIXTURE), "--apply-scope", "--json")
    assert imported.exit_code == 0, imported.stderr
    data = imported.json()
    assert data["schema"] == "raf.surface.import/v1" and data["accepted"] == 52 and data["rejected"] == 0
    # the demo already applied this scope
    assert [c["result"] for c in data["scope_changes"]] == ["unchanged"] * 4 and data["job_id"]
    analysis = cli("surface", "analyze", "--json").json()
    assert analysis["schema"] == "raf.surface.analysis/v1" and len(analysis["findings"]) == 13
    assert analysis["reference_time"] == "2026-10-07T01:06:00Z"
    summary = cli("surface", "--json").json()
    assert summary["schema"] == "raf.surface.summary/v1" and summary["findings_open"] == 13
    shown = cli("surface", "show")
    assert shown.exit_code == 0
    for text in ("raven.example", "EXPIRED 2026-09-30", "OUTSIDE SCOPE", "3389/tcp", "Top findings"):
        assert text in shown.stdout, text
    certificates = cli("surface", "assets", "--kind", "certificate", "--json").json()
    assert certificates["schema"] == "raf.surface.assets/v1" and certificates["total"] == 4
    outside = cli("surface", "assets", "--out-of-scope", "--json").json()
    assert {a["name"] for a in outside["items"]} == {"raven-launch.example", "www.raven-launch.example"}
    table = cli("surface", "assets", "--kind", "service")
    assert table.exit_code == 0 and "Microsoft Terminal Services" in table.stdout
    dangling = cli("surface", "findings", "--rule", "dangling-dns", "--json").json()
    assert dangling["total"] == 1 and dangling["items"][0]["rule_id"] == "dangling-dns"
    later = cli("surface", "analyze", "--at", "2026-10-29T00:00:00Z", "--no-save", "--json").json()
    assert later["persisted"] is False
    assert sum(1 for f in later["findings"] if f["rule_id"] == "expired-certificate") == 2
    assert cli("surface", "findings", "--json").json()["total"] == 13  # --no-save changed nothing
    human = cli("surface", "analyze")
    assert human.exit_code == 0 and "CRITICAL" in human.stdout and "raf finding show" in human.stdout
    for args, code in [
        (("surface", "import", str(tmp_path / "missing.json")), 3),
        (("surface", "assets", "--kind", "bogus"), 4),
        (("surface", "assets", "--in-scope", "--out-of-scope"), 4),
        (("surface", "findings", "--rule", "no-such-rule"), 4),
        (("surface", "analyze", "--at", "not a time"), 4),
    ]:
        result = cli(*args)
        assert result.exit_code == code and "Traceback" not in result.stderr, (args, result.stderr)
    bad = tmp_path / "bad.yaml"
    bad.write_text("records: [unclosed\n", encoding="utf-8")
    refused = cli("surface", "import", str(bad))
    assert refused.exit_code == 4 and "not valid YAML" in refused.stderr and "Traceback" not in refused.stderr


def test_cli_sample_writes_the_fixture(raf_home: Path, cli: Any, tmp_path: Path) -> None:
    target = tmp_path / "raven-surface.json"
    written = cli("surface", "sample", str(target), "--json")
    assert written.exit_code == 0 and target.read_text(encoding="utf-8") == FIXTURE.read_text(encoding="utf-8")
    assert cli("surface", "sample", str(target)).exit_code == 4  # overwriting needs confirmation
    assert cli("surface", "sample", str(target), "--yes").exit_code == 0


# --------------------------------------------------------------------------- raf import parser


def test_parser_is_picked_by_raf_import(raven_home: Path, cli: Any, tmp_path: Path) -> None:
    for entry in cli("surface", "scope", "list", "--json").json()["items"]:  # start without a scope
        assert cli("surface", "scope", "remove", entry["target"], "--yes").exit_code == 0
    imported = cli("import", str(FIXTURE), "--json")
    assert imported.exit_code == 0, imported.stderr
    report = imported.json()
    assert report["parser"] == "raf-surface/1.0" and report["rejected"] == 0
    assert any("scope entries were not applied" in w for w in report["warning_samples"])
    assert cli("surface", "scope", "list", "--json").json()["items"] == []  # raf import never changes scope
    csv_path = tmp_path / "surface.csv"
    csv_path.write_bytes(mini_documents()["csv"])
    from_csv = cli("import", str(csv_path), "--json").json()
    assert from_csv["parser"] == "raf-surface/1.0" and from_csv["rejected"] == 0
    bad_path = tmp_path / "bad-surface.json"
    bad_path.write_text(json.dumps({"format": "raf-surface/1", "records": [{"kind": "nope"}]}), encoding="utf-8")
    bad = cli("import", str(bad_path), "--json").json()
    assert bad["parser"] == "raf-surface/1.0" and bad["rejected"] == 1
    assert sniff_surface(b'{"records": [{"kind": "domain", "name": "a.example"}]}', ".json") == 0.0
    assert sniff_surface(b'{"format": "raf-policy/1", "policies": []}', ".json") == 0.0
    assert sniff_surface(b"kind,name\nfoo,a.example\n", ".csv") == 0.0  # not surface kinds
    assert sniff_surface(b"kind,name,type,value\ndns,a.example,A,192.0.2.1\n", ".csv") > 0.9
    assert SurfaceInventoryParser.sniff(FIXTURE, FIXTURE.read_bytes()[:65536]) > 0.95


# --------------------------------------------------------------------------- API


@pytest.fixture
def api(raven_home: Path) -> Iterator[Any]:
    with TestClient(create_app(env={"RAF_HOME": str(raven_home)})) as client:
        yield client


def test_api_routes(api: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    base = "/api/v1/surface"
    for entry in api.get(f"{base}/scope").json()["items"]:  # the demo's scope; start from none
        assert api.delete(f"{base}/scope/{entry['target']}").status_code == 200
    assert api.get(f"{base}/scope").json() == {"items": [], "total": 0}
    created = api.post(
        f"{base}/scope", json={"target": "raven.example", "owner": "IT operations", "authorization": "SEC-1"}
    )
    assert created.status_code == 201 and created.json()["result"] == "added"
    assert api.post(f"{base}/scope", json={"target": "raven.example", "owner": "Other"}).status_code == 409
    invalid = api.post(f"{base}/scope", json={"target": "0.0.0.0/0"})
    assert invalid.status_code == 422 and invalid.json()["error"]["code"] == "raf.invalid_input"
    imported = api.post(f"{base}/import", params={"apply_scope": "true"}, content=FIXTURE.read_bytes())
    assert imported.status_code == 200, imported.text
    assert imported.json()["accepted"] == 52 and imported.json()["source"] == "api-request"
    changes = {c["target"]: c["result"] for c in imported.json()["scope_changes"]}
    assert changes["raven.example"] == "conflict" and changes["198.51.100.0/28"] == "added"
    analysis = api.post(f"{base}/analyze").json()
    assert len(analysis["findings"]) == 13 and analysis["reference_source"] == "newest event in the workspace"
    findings = api.get(f"{base}/findings").json()
    assert findings["total"] == 13 and findings["items"][0]["severity"] == "CRITICAL"
    assert api.get(f"{base}/findings", params={"rule": "shadow-asset"}).json()["total"] == 2
    assert api.get(f"{base}/findings", params={"rule": "bogus"}).status_code == 422
    summary = api.get(f"{base}/summary").json()
    assert summary["scope_configured"] and summary["tree"] and summary["findings_open"] == 13
    assets = api.get(f"{base}/assets", params={"kind": "certificate"}).json()
    assert assets["total"] == 4 and len(assets["items"]) == 4
    assert api.get(f"{base}/assets", params={"scope": "out"}).json()["total"] == 2
    assert api.get(f"{base}/assets", params={"kind": "ip", "limit": 1, "offset": 1}).json()["items"][0]["kind"] == "ip"
    assert api.get(f"{base}/assets", params={"kind": "bogus"}).status_code == 422
    assert api.get(f"{base}/assets", params={"scope": "maybe"}).status_code == 422
    removed = api.delete(f"{base}/scope/198.51.100.0/28")
    assert removed.status_code == 200 and removed.json()["entry"]["target"] == "198.51.100.0/28"
    assert api.delete(f"{base}/scope/198.51.100.0/28").status_code == 404
    # import bodies are untrusted: size, emptiness and shape are checked, no paths are accepted
    assert api.post(f"{base}/import", content=b"").status_code == 422
    assert api.post(f"{base}/import", content=b"{oops").status_code == 422
    assert api.post(f"{base}/import", content=b"42").status_code == 422
    assert api.post(f"{base}/import", params={"format": "xml"}, content=b"<a/>").status_code == 422
    partial = api.post(f"{base}/import", json=[{"kind": "domain", "name": "ok.raven.example"}, {"kind": "bad"}])
    assert partial.status_code == 200 and partial.json()["accepted"] == 1 and partial.json()["rejected"] == 1
    from raf.products.surface import api as surface_api

    monkeypatch.setattr(surface_api, "MAX_DOCUMENT_BYTES", 1000)
    too_big = api.post(f"{base}/import", content=b" " * 2000)
    assert too_big.status_code == 413 and too_big.json()["error"]["code"] == "raf.resource_limit"
