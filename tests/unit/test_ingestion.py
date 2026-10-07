from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from raf.core.context.app import RafContext
from raf.core.errors import IngestionError, ResourceLimitExceeded
from raf.core.ingestion.base import ParseContext, RawRecord, SourceInfo
from raf.core.ingestion.normalizers import CloudTrailNormalizer, EcsNormalizer, NativeNormalizer, TabularNormalizer
from raf.core.ingestion.pipeline import IngestionPipeline, IngestOptions
from raf.core.ingestion.registry import ParserRegistry
from raf.core.storage.repos.events import EventQuery
from raf.core.timeutil import UTC
from tests.conftest import FIXTURES


def _pctx() -> ParseContext:
    return ParseContext(
        source=SourceInfo(name="test"),
        default_tz=UTC,
        reference_time=None,
        max_record_bytes=4096,
        raw_max_bytes=256,
        store_raw=True,
    )


def _write(tmp_path: Path, name: str, content: str | bytes) -> Path:
    path = tmp_path / name
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")
    return path


class TestDetection:
    @pytest.mark.parametrize(
        "relative,expected",
        [
            ("raven-events.jsonl", "jsonl"),
            ("evidence/auth.log", "syslog"),
            ("evidence/proxy.csv", "csv"),
            ("evidence/edr-process-events.jsonl", "jsonl"),
        ],
    )
    def test_fixture_formats(self, relative: str, expected: str) -> None:
        path = FIXTURES / relative
        detected = ParserRegistry.default().detect(path, path.read_bytes()[:65536])
        assert detected is not None and detected[0].name == expected

    def test_access_log_and_json(self, tmp_path: Path) -> None:
        access = _write(
            tmp_path,
            "access.log",
            '203.0.113.5 - - [06/Oct/2026:10:00:00 +0000] "GET /login HTTP/1.1" 401 120 "-" "curl/8"\n' * 3,
        )
        assert ParserRegistry.default().detect(access, access.read_bytes())[0].name == "access-log"  # type: ignore[index]
        doc = _write(tmp_path, "trail.json", json.dumps({"Records": []}, indent=2))
        assert ParserRegistry.default().detect(doc, doc.read_bytes())[0].name == "json"  # type: ignore[index]

    def test_unknown_binary(self, tmp_path: Path) -> None:
        blob = _write(tmp_path, "x.bin", bytes(range(256)) * 10)
        assert ParserRegistry.default().detect(blob, blob.read_bytes()) is None


class TestNormalizers:
    def test_native_event_roles_and_defaults(self) -> None:
        normalizer = NativeNormalizer()
        out = normalizer.normalize(
            RawRecord(
                {
                    "timestamp": "2026-10-06T10:00:00Z",
                    "event_type": "auth.login",
                    "actor": "CORP\\alice",
                    "target": "10.0.0.9",
                    "attributes": {"src_ip": "10.0.0.5"},
                },
                "line 1",
            ),
            _pctx(),
        )
        ev = out.events[0]
        assert ev.actor == "user:alice" and ev.target == "ip:10.0.0.9"
        assert {(r.object_id, r.role) for r in ev.objects} >= {("ip:10.0.0.5", "src_ip")}
        alice = next(o for o in out.objects if o.id == "user:alice")
        assert alice.metadata["domain"] == "CORP"

    def test_native_rejects_bad_event_type(self) -> None:
        from raf.core.ingestion.base import RecordRejected

        with pytest.raises(RecordRejected):
            NativeNormalizer().normalize(
                RawRecord({"timestamp": "2026-10-06T10:00:00Z", "event_type": "Bad Type!"}, "x"), _pctx()
            )

    def test_ecs(self) -> None:
        native = NativeNormalizer()
        out = EcsNormalizer(native).normalize(
            RawRecord(
                {
                    "@timestamp": "2026-10-06T10:00:00Z",
                    "event": {"category": ["authentication"], "outcome": "failure"},
                    "user": {"name": "bob"},
                    "host": {"name": "WS-02"},
                    "source": {"ip": "203.0.113.4"},
                },
                "l1",
            ),
            _pctx(),
        )
        assert out.events[0].event_type == "auth.failure"
        dns = EcsNormalizer(native).normalize(
            RawRecord(
                {
                    "@timestamp": "2026-10-06T10:00:00Z",
                    "event": {"category": ["network"]},
                    "host": {"name": "WS-01"},
                    "dns": {"question": {"name": "example.org"}, "resolved_ip": ["192.0.2.1"]},
                },
                "l2",
            ),
            _pctx(),
        )
        assert dns.events[0].event_type == "dns.query" and dns.events[0].target == "domain:example.org"

    def test_cloudtrail(self) -> None:
        native = NativeNormalizer()
        record = {
            "eventTime": "2026-10-06T10:00:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "AttachUserPolicy",
            "userIdentity": {"type": "IAMUser", "userName": "ops", "arn": "arn:aws:iam::1:user/ops"},
            "requestParameters": {"userName": "alice", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
        }
        out = CloudTrailNormalizer(native).normalize(RawRecord(record, "Records[0]"), _pctx())
        ev = out.events[0]
        assert ev.event_type == "iam.permission.grant"
        assert ev.target == "identity:alice"
        assert any(r.role == "resource" and r.object_id.startswith("policy:") for r in ev.objects)

    def test_tabular_inference(self) -> None:
        out = TabularNormalizer(NativeNormalizer()).normalize(
            RawRecord(
                {"Time": "2026-10-06T10:00:00Z", "User": "alice", "Host": "WS-01", "URL": "https://x.example/a"},
                "row 2",
            ),
            _pctx(),
        )
        ev = out.events[0]
        assert ev.event_type == "http.request" and ev.target == "url:https://x.example/a"
        assert ev.actor == "host:ws-01" and ev.attributes["user"] == "alice"


class TestPipeline:
    def test_raven_import_is_idempotent_with_provenance(self, ctx: RafContext) -> None:
        pipeline = IngestionPipeline(ctx)
        first = pipeline.ingest_path(FIXTURES / "raven-events.jsonl")
        assert first.rejected == 0 and first.events_created > 500
        assert "incident:inc-001" in first.incidents
        again = IngestionPipeline(ctx).ingest_path(FIXTURES / "raven-events.jsonl")
        assert again.events_created == 0 and again.objects_created == 0 and again.relationships_created == 0
        assert again.events_duplicate == first.events_created
        # entity resolution: svc-deploy is an identity, never a duplicate user
        assert ctx.store.objects.get("user:svc-deploy") is None
        logins = ctx.store.relationships.list(source="identity:svc-deploy", types=["LOGGED_INTO"])
        assert {r.target_object for r in logins} == {"host:ci-01", "host:app-01"}
        # derived relationship provenance points at the event and record
        prov = ctx.store.provenance.for_subject(logins[0].id)
        assert prov and prov[0].event_id and prov[0].record and prov[0].parser == "jsonl/1.0"
        # temporal end: bob removed from vpn-users during containment
        member = ctx.store.relationships.list(source="user:bob", target="group:vpn-users", types=["MEMBER_OF"])[0]
        assert member.valid_to is not None

    def test_evidence_directory_and_syslog_semantics(self, ctx: RafContext) -> None:
        report = IngestionPipeline(ctx).ingest_path(FIXTURES / "evidence", IngestOptions(incident="INC-001"))
        assert len(report.files) == 3
        assert report.skipped_files and report.skipped_files[0]["reason"] == "unknown format"
        events = ctx.store.events.query(EventQuery(incident_id="incident:inc-001"), limit=100).items
        assert len(events) == report.events_created
        failure = ctx.store.events.query(EventQuery(event_types=["auth.failure"]), limit=5).items
        assert failure and failure[0].parser == "syslog-sudo/1.0"
        # the prompt-injection string stays inert data
        proxy = ctx.store.events.query(EventQuery(text="IGNORE ALL PREVIOUS"), limit=5).items
        assert proxy and proxy[0].event_type == "http.request"

    def test_malformed_records_never_abort(self, ctx: RafContext, tmp_path: Path) -> None:
        deep = "[" * 100_000 + "]" * 100_000
        lines = [
            json.dumps({"timestamp": "2026-10-06T10:00:00Z", "event_type": "auth.login", "actor": "a", "target": "h"}),
            "{not json",
            json.dumps({"event_type": "auth.login", "actor": "a"}),
            "x" * 10_000,
            deep,
            json.dumps({"timestamp": "1700000000000000000000", "event_type": "auth.login"}),
            json.dumps({"timestamp": "2026-10-06T10:01:00Z", "event_type": "auth.login", "actor": "b", "target": "h"}),
        ]
        path = _write(tmp_path, "mixed.jsonl", "\n".join(lines) + "\n")
        ctx.settings = ctx.settings.with_overrides({"ingest.max_record_kb": 8})
        report = IngestionPipeline(ctx).ingest_path(path)
        assert report.accepted == 2 and report.rejected == 5
        reasons = " | ".join(r.reason for r in report.rejections)
        assert "timestamp" in reasons and "exceeds" in reasons and "Malformed JSON" in reasons
        assert report.rejects_file and Path(report.rejects_file).exists()
        quarantined = Path(report.rejects_file).read_text().splitlines()
        assert len(quarantined) == 5

    def test_file_size_limit(self, ctx: RafContext, tmp_path: Path) -> None:
        ctx.settings = ctx.settings.with_overrides({"ingest.max_file_mb": 1})
        big = _write(tmp_path, "big.jsonl", "{}\n" * 400_000)
        with pytest.raises(ResourceLimitExceeded):
            IngestionPipeline(ctx).ingest_path(big)

    def test_unknown_format_is_actionable(self, ctx: RafContext, tmp_path: Path) -> None:
        blob = _write(tmp_path, "x.bin", bytes(range(256)) * 4)
        with pytest.raises(IngestionError) as info:
            IngestionPipeline(ctx).ingest_path(blob)
        assert "--format" in (info.value.hint or "")

    def test_json_streaming_and_native_document(self, ctx: RafContext, tmp_path: Path) -> None:
        records = [
            {
                "timestamp": f"2026-10-06T10:00:{i:02d}Z",
                "event_type": "dns.query",
                "actor": "WS-01",
                "target": f"d{i}.example",
            }
            for i in range(30)
        ]
        array = _write(tmp_path, "events.json", json.dumps(records))
        report = IngestionPipeline(ctx).ingest_path(array)
        assert report.accepted == 30 and report.format == "json"
        doc = _write(
            tmp_path,
            "native.json",
            json.dumps(
                {
                    "raf_format": "raf-native/1",
                    "objects": [{"type": "host", "name": "H1"}],
                    "relationships": [{"source": "host:H1", "type": "RUNS", "target": "service:s1"}],
                    "events": [
                        {"timestamp": "2026-10-06T11:00:00Z", "event_type": "auth.login", "actor": "u", "target": "H1"}
                    ],
                }
            ),
        )
        report = IngestionPipeline(ctx).ingest_path(doc)
        assert report.accepted == 3 and ctx.store.objects.get("service:s1") is not None

    def test_filesystem_metadata_does_not_follow_symlinks(self, ctx: RafContext, tmp_path: Path) -> None:
        root = tmp_path / "case"
        (root / "sub").mkdir(parents=True)
        (root / "sub" / "a.txt").write_text("hello")
        secret_dir = tmp_path / "outside"
        secret_dir.mkdir()
        (secret_dir / "secret.txt").write_text("do not read")
        (root / "link").symlink_to(secret_dir)
        report = IngestionPipeline(ctx).ingest_path(root, IngestOptions(format="filesystem", default_host="lab"))
        assert report.rejected == 0
        names = {o.name for o in ctx.store.objects.list(types=["file", "directory"], limit=100)}
        assert {"a.txt", "sub", "link"} <= names and "secret.txt" not in names
        link = next(o for o in ctx.store.objects.list(types=["file"], limit=100) if o.name == "link")
        assert link.metadata.get("symlink") is True


def test_cli_import_and_report(cli: Any, tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "e.jsonl",
        json.dumps({"timestamp": "2026-10-06T10:00:00Z", "event_type": "auth.login", "actor": "a", "target": "h"})
        + "\nbad\n",
    )
    result = cli("import", str(path))
    assert result.exit_code == 0
    assert "R$F could not parse record line 2" in result.stdout
    assert "raf import report job-1" in result.stdout
    report = cli("import", "report", "job-1", "--json").json()
    assert report["rejections"][0]["record"] == "line 2"
    data = cli("import", str(path), "--json").json()
    assert data["schema"] == "raf.import/v1" and data["events_duplicate"] == 1


def test_rich_markup_in_data_is_not_interpreted(cli: Any, tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "m.jsonl",
        json.dumps({"kind": "object", "type": "host", "name": "[bold red]EVIL[/] <script>x</script>"}) + "\n",
    )
    assert cli("import", str(path)).exit_code == 0
    shown = cli("show", "host:[bold red]evil[/] <script>x</script>")
    assert "[bold red]EVIL[/] <script>x</script>" in shown.stdout


def test_demo_load(cli: Any) -> None:
    result = cli("demo", "load")
    assert result.exit_code == 0 and "raf replay INC-001" in result.stdout
    status = cli("status", "--json").json()
    assert status["data"]["incidents"] == 1 and status["data"]["events"] > 500


def test_fixtures_are_up_to_date() -> None:
    import subprocess
    import sys

    from tests.conftest import REPO_ROOT

    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "generate_fixtures.py"), "--check"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout
