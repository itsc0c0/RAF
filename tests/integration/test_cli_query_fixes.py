"""CLI, filter language, scope and context reference fixes.

Covers: one JSON document for failed imports, directory import formats, closed pipes, suggested commands
that parse, configuration keys that take effect, filters that only narrow, the filter syntax, help topics,
evidence item IDs, context references and scope type words.
"""

from __future__ import annotations

import errno
import io
import json
import os
import shlex
import subprocess
import sys
from contextlib import redirect_stderr, redirect_stdout
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
import typer

from raf.apps.cli.clickcompat import Context, UsageError, is_group
from raf.core.context.app import RafContext, open_context
from raf.core.errors import InvalidInputError, NotFoundError
from raf.core.ingestion.pipeline import IngestReport
from raf.core.objects.models import ObjectDraft
from raf.core.objects.types import Severity
from raf.core.query.language import parse_filter, split_terms
from raf.core.query.scope import resolve_scope
from raf.core.storage.repos.events import EventQuery
from raf.core.timeutil import parse_timestamp
from tests.conftest import FIXTURES, CliResult

# --------------------------------------------------------------------------- helpers


def _refs(home: Path, token: str, accept: tuple[str, ...] | None = None) -> tuple[str, str]:
    ctx = open_context(env={"RAF_HOME": str(home)})
    try:
        return ctx.refs.resolve(token) if accept is None else ctx.refs.resolve(token, accept=accept)
    finally:
        ctx.close()


def _count(ctx: RafContext, words: list[str], text: str) -> int:
    base = resolve_scope(ctx, words).event_query()
    return ctx.store.events.count(parse_filter(text, resolver=ctx.resolver, base=base).query)


def _evidence(ctx: RafContext, name: str) -> str:
    return next(o.id for o in ctx.store.objects.iter_all(types=["evidence"]) if o.name == name)


class _ClosingPipe(io.StringIO):
    """A stdout whose reader goes away after ``limit`` characters, like ``raf ... | head -c N``."""

    def __init__(self, limit: int) -> None:
        super().__init__()
        self.limit = limit

    def write(self, text: str) -> int:
        if self.tell() + len(text) > self.limit:
            raise BrokenPipeError(errno.EPIPE, "Broken pipe")
        return super().write(text)


def _run_into(stdout: io.StringIO, *args: str, stderr: io.StringIO | None = None) -> CliResult:
    from raf.apps.cli import registry as cli_registry
    from raf.apps.cli.main import run

    cli_registry.build_registry.cache_clear()
    cli_registry.load_product_command.cache_clear()
    err = stderr if stderr is not None else io.StringIO()
    old_stdin, sys.stdin = sys.stdin, io.StringIO("")
    code = 0
    try:
        with redirect_stdout(stdout), redirect_stderr(err):
            try:
                run(list(args))
            except SystemExit as exc:
                code = int(exc.code or 0)
    finally:
        sys.stdin = old_stdin
    return CliResult(code, stdout.getvalue(), err.getvalue())


def _assert_parses(line: str) -> None:
    """Resolve a suggested ``raf ...`` command line and parse its options and arguments (nothing runs)."""
    from raf.apps.cli.main import app

    args = shlex.split(line)
    assert args[0] == "raf", line
    command: Any = typer.main.get_command(app)
    context = Context(command, info_name="raf")
    rest = args[1:]
    while is_group(command) and rest:
        name, sub, rest = command.resolve_command(context, rest)  # unknown command: UsageError
        assert name is not None and sub is not None, line
        command, context = sub, Context(sub, info_name=name, parent=context)
    command.make_context(context.info_name, list(rest), parent=context.parent)  # bad option or argument: UsageError


# --------------------------------------------------------------------------- 14, 15: raf import


def test_failed_import_prints_one_json_document(raf_home: Path, cli: Any, tmp_path: Path) -> None:
    bad = tmp_path / "bad.pcap"
    bad.write_text("not a capture\n")
    result = cli("--json", "import", str(bad), "--format", "pcap")
    assert result.exit_code == 1
    document = json.loads(result.stdout)  # a second document would be "Extra data"
    assert document["schema"] == "raf.error/v1"
    error = document["error"]
    job = error["details"]["job"]
    assert error["code"] == "raf.ingestion" and error["suggestions"] == [f"raf job show {job['id']}"]
    assert job["status"] == "FAILED" and job["error"]["code"] == "raf.invalid_input"
    human = cli("import", str(bad), "--format", "pcap")
    assert human.exit_code == 1 and human.stdout == "" and "not a pcap" in human.stderr


def test_directory_import_names_the_formats_of_its_files(raf_home: Path, cli: Any) -> None:
    from raf.apps.cli.commands.ingest import format_label

    result = cli("import", str(FIXTURES / "evidence"))
    assert result.exit_code == 0, result.stderr
    line = next(row for row in result.stdout.splitlines() if row.startswith("Format"))
    assert "None" not in line and "directory (syslog, jsonl, csv)" in line
    assert format_label(IngestReport(source="empty", format="directory")) == "directory"
    single = IngestReport(source="a", format="jsonl", parser="jsonl/1.0", normalizer="raf-native")
    assert format_label(single) == "jsonl (jsonl/1.0, raf-native)"


# --------------------------------------------------------------------------- 16: closed pipes


@pytest.mark.parametrize(
    "args",
    [
        ("timeline", "workspace", "--limit", "300"),  # Rich tables
        ("--json", "timeline", "workspace", "--limit", "300"),  # one JSON document
        ("--help",),  # Typer's own Rich console
        ("help", "timeline"),  # click.echo
    ],
)
def test_closed_pipe_exits_quietly(raven_home: Path, args: tuple[str, ...]) -> None:
    result = _run_into(_ClosingPipe(200), *args)
    assert result.exit_code == 0 and result.stderr == ""
    assert len(result.stdout) <= 200


def test_closed_pipe_keeps_the_failure_status(raven_home: Path) -> None:
    result = _run_into(_ClosingPipe(5), "--json", "show", "nobody-at-all")
    assert result.exit_code == 3 and result.stderr == ""


def test_closed_stderr_only_loses_the_diagnostics(raven_home: Path) -> None:
    # Lens writes "N more; narrow with --filter ..." to stderr, then the next steps to stdout.
    result = _run_into(io.StringIO(), "lens", "--limit", "1", stderr=_ClosingPipe(0))
    assert result.exit_code == 0 and result.stderr == ""
    assert "MOST INVOLVED" in result.stdout and "Next:" in result.stdout


def test_closed_pipe_in_a_real_process(raven_home: Path) -> None:
    env = {**os.environ, "RAF_HOME": str(raven_home), "NO_COLOR": "1", "COLUMNS": "200"}
    code = "from raf.apps.cli.main import run; run()"
    process = subprocess.Popen(
        [sys.executable, "-c", code, "timeline", "workspace", "--limit", "2000"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    assert process.stdout is not None and process.stderr is not None
    assert process.stdout.read(200)
    process.stdout.close()  # the reader goes away, like `head`
    stderr = process.stderr.read()
    process.stderr.close()
    assert process.wait(timeout=120) == 0
    assert stderr == b""  # no traceback, no "Exception ignored" at interpreter exit


def test_streams_closed_at_start(raven_home: Path) -> None:
    """`raf ... >&-`: Python starts without the stream; the command runs and its output goes nowhere."""
    env = {**os.environ, "RAF_HOME": str(raven_home), "NO_COLOR": "1"}
    code = "import os, sys; os.close(1); sys.stdout = None; from raf.apps.cli.main import run; run()"
    done = subprocess.run([sys.executable, "-c", code, "status"], capture_output=False, stderr=subprocess.PIPE, env=env)
    assert done.returncode == 0 and done.stderr == b""
    missing = subprocess.run([sys.executable, "-c", code, "show", "nothing-here"], stderr=subprocess.PIPE, env=env)
    assert missing.returncode == 3 and b"nothing-here" in missing.stderr  # the failure still reports


# --------------------------------------------------------------------------- 17: suggested commands parse


def test_analysis_suggestions_parse(ctx: RafContext, tmp_path: Path) -> None:
    from raf.analysis.analyze import AnalyzeOptions, Detection, _Run, _suggestions

    run = _Run(ctx, "analysis-7", AnalyzeOptions())
    run.incidents = ["incident:inc-001"]
    run.stats = {"findings": 3, "exposed_assets": ["host:app-01"]}
    lines: list[str] = []
    for kind in ("pcap", "repository", "manifest", "sbom", "jsonl"):
        lines += _suggestions(run, Detection(kind=kind, label=kind), tmp_path / "input file.pcap")
    assert "raf findings --severity high" in lines
    for line in lines:
        _assert_parses(line)
    for wrong in ("raf finding list --severity HIGH", "raf findings --bogus", "raf timeline --limit many"):
        with pytest.raises(UsageError):
            _assert_parses(wrong)


def test_oracle_suggestions_parse(raven: RafContext) -> None:
    from raf.products.oracle.service import OracleService

    service = OracleService(raven)
    lines: list[str] = []
    for question in (
        "What should I look at first?",
        "Explain the most important security path in INC-001",
        "Can alice reach production?",
        "Who can control DB-01?",
        "Why is DEV-01 critical?",
        "Tell me about svc-deploy",
    ):
        lines += service.ask(question).suggestions
    assert "raf findings --severity high" in lines
    for line in lines:
        _assert_parses(line)


# --------------------------------------------------------------------------- 18: configuration keys


def test_log_level_and_log_file_settings(raf_home: Path, cli: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    sample = str(FIXTURES / "evidence" / "auth.log")
    assert "[info]" not in cli("import", sample).stderr  # default: WARNING
    assert cli("config", "set", "core.log_level", "INFO").exit_code == 0
    assert "[info] raf.ingest" in cli("import", sample).stderr  # the configured level
    monkeypatch.setenv("RAF_CORE_LOG_LEVEL", "ERROR")
    assert "[info]" not in cli("import", sample).stderr  # the environment wins over the files
    monkeypatch.delenv("RAF_CORE_LOG_LEVEL")
    assert cli("config", "set", "core.log_level", "WARNING", "--scope", "workspace").exit_code == 0
    assert "[info]" not in cli("import", sample).stderr  # the workspace file wins over the global one

    log = raf_home / "logs" / "raf.log"
    assert log.exists()
    assert cli("config", "set", "core.log_file", "false").exit_code == 0
    log.unlink()
    assert cli("import", sample).exit_code == 0 and not log.exists()
    for scope in ("global", "workspace"):
        cli("config", "unset", "core.log_level", "--scope", scope)
    cli("config", "unset", "core.log_file")
    assert cli("version").exit_code == 0 and log.exists()


def test_internal_error_names_the_log_file_only_when_one_is_written(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from raf.apps.cli.main import render_internal
    from raf.core.logging import configure_logging
    from raf.sdk import cli as rt

    rt.reset_state()
    configure_logging("WARNING", log_dir=None)
    render_internal(RuntimeError("boom"))
    assert "also logged" not in capsys.readouterr().err
    configure_logging("WARNING", log_dir=tmp_path)
    render_internal(RuntimeError("boom"))
    assert str(tmp_path / "raf.log") in capsys.readouterr().err
    rt.reset_state()


def test_confirm_destructive_setting(raf_home: Path, cli: Any) -> None:
    assert cli("snapshot", "create", "s1").exit_code == 0
    refused = cli("--json", "snapshot", "delete", "s1")  # no terminal, no --yes
    assert refused.exit_code == 4 and refused.json()["error"]["code"] == "raf.confirmation_required"
    assert cli("config", "set", "core.confirm_destructive", "false").exit_code == 0
    assert cli("snapshot", "delete", "s1").exit_code == 0


def test_range_default_seed_and_range_reference(raf_home: Path, cli: Any) -> None:
    assert cli("config", "set", "range.default_seed", "7").exit_code == 0
    created = cli("--json", "range", "create", "acme-one", "--employees", "3")
    assert created.exit_code == 0, created.stderr
    assert created.json()["state"]["seed"] == 7
    assert cli("--json", "range", "create", "acme-two", "--employees", "3", "--seed", "3").json()["state"]["seed"] == 3
    assert _refs(raf_home, "@range") == ("range", "acme-two")
    assert cli("--json", "range", "status", "@range").json()["state"]["name"] == "acme-two"
    assert cli("range", "status", "acme-one").exit_code == 0  # showing a range remembers it
    assert cli("--json", "range", "status", "@last").json()["state"]["name"] == "acme-one"
    shown = cli("--json", "show", "@range")
    assert shown.exit_code == 4 and "does not accept" in shown.json()["error"]["message"]
    assert cli("config", "set", "range.default_seed", "--", "-1").exit_code == 4


def test_evidence_item_size_limit(raf_home: Path, cli: Any, tmp_path: Path) -> None:
    folder = tmp_path / "artifacts"
    folder.mkdir()
    big = folder / "big.bin"
    big.write_bytes(b"\0" * (1024 * 1024 + 1))
    (folder / "auth.log").write_bytes((FIXTURES / "evidence" / "auth.log").read_bytes())
    assert cli("evidence", "case", "create", "CASE-1").exit_code == 0
    assert cli("config", "set", "evidence.max_item_mb", "1").exit_code == 0
    single = cli("--json", "evidence", "import", str(big), "--case", "CASE-1")
    error = single.json()["error"]
    assert single.exit_code == 5 and error["code"] == "raf.resource_limit"
    assert "(evidence.max_item_mb)" in error["message"] and "raf config set evidence.max_item_mb" in error["hint"]
    imported = cli("--json", "evidence", "import", str(folder), "--case", "CASE-1").json()
    assert [i["name"] for i in imported["items"]] == ["auth.log"]
    assert "(evidence.max_item_mb)" in imported["skipped"][0]["reason"]


# --------------------------------------------------------------------------- 19: filters only narrow


class TestFiltersNarrowTheScope:
    def test_object_terms(self, raven: RafContext) -> None:
        alice = raven.store.events.count(resolve_scope(raven, ["user", "alice"]).event_query())
        assert _count(raven, ["user", "alice"], "object:alice") == alice
        # on an object scope, object: selects the events that involve both objects
        scope = resolve_scope(raven, ["user", "alice"]).event_query()
        both = list(raven.store.events.iter(parse_filter("object:DEV-01", resolver=raven.resolver, base=scope).query))
        assert 0 < len(both) < alice
        assert all({"user:alice", "host:dev-01"} <= {o.object_id for o in e.objects} for e in both)
        assert 0 < _count(raven, ["user", "alice"], "target:DEV-01") <= len(both)
        incident = resolve_scope(raven, ["INC-001"]).event_query()
        query = parse_filter("object:bob", resolver=raven.resolver, base=incident).query
        events = list(raven.store.events.iter(query))
        assert 0 < len(events) < raven.store.events.count(incident)
        assert all("incident:inc-001" in e.incidents and "user:bob" in {o.object_id for o in e.objects} for e in events)

    def test_incident_and_job_terms_intersect(self, raven: RafContext) -> None:
        assert _count(raven, ["job-1"], "job:job-2") == 0
        job_1 = raven.store.events.count(EventQuery(job_ids=["job-1"]))
        assert _count(raven, ["job-1"], "job:job-1 job:job-2") == job_1
        assert _count(raven, ["INC-001"], "incident:INC-001") == raven.store.events.count(
            EventQuery(incident_id="incident:inc-001")
        )
        with pytest.raises(InvalidInputError, match="one incident at a time"):
            parse_filter("incident:INC-001", resolver=raven.resolver, base=EventQuery(incident_id="incident:other"))

    def test_time_terms_keep_the_stricter_bound(self, raven: RafContext) -> None:
        start = parse_timestamp("2026-10-06T22:00:00Z")
        assert parse_filter("after:2026-10-01T00:00:00Z", base=EventQuery(start=start)).query.start == start
        later = parse_timestamp("2026-10-06T23:00:00Z")
        assert parse_filter("time>=2026-10-06T23:00:00Z", base=EventQuery(start=start)).query.start == later
        end = parse_timestamp("2026-10-06T23:30:00Z")
        assert parse_filter("before:2026-10-07T00:00:00Z", base=EventQuery(end=end)).query.end == end
        strict = parse_filter("time>2026-10-06T23:00:00Z time<2026-10-06T23:30:00Z").query
        assert strict.start == later + timedelta(microseconds=1) and strict.end == end - timedelta(microseconds=1)
        moment = next(iter(raven.store.events.iter(EventQuery(), with_objects=False))).timestamp.isoformat()
        at_or_after = raven.store.events.count(parse_filter(f"time>={moment}").query)
        assert raven.store.events.count(parse_filter(f"time>{moment}").query) < at_or_after

    def test_type_category_and_severity_terms_narrow_the_options(self, raven: RafContext) -> None:
        assert parse_filter("type:auth.login", base=EventQuery(event_types=["auth"])).query.event_types == [
            "auth.login"
        ]
        assert parse_filter("type:auth.*", base=EventQuery(event_types=["auth.login"])).query.event_types == [
            "auth.login"
        ]
        unrelated = parse_filter("type:auth", base=EventQuery(event_types=["process"])).query
        assert unrelated.event_ids == [] and raven.store.events.count(unrelated) == 0
        assert parse_filter("type:auth.login type:auth.logout").query.event_types == ["auth.login", "auth.logout"]
        both = parse_filter("category:auth category:dns", base=EventQuery(categories=["auth", "process"])).query
        assert both.categories == ["auth"]
        assert parse_filter("severity>=low", base=EventQuery(min_severity=Severity.HIGH)).query.min_severity == (
            Severity.HIGH
        )

    def test_contains_terms(self) -> None:
        assert parse_filter("source:proxy", base=EventQuery(source="proxy.csv")).query.source == "proxy.csv"
        with pytest.raises(InvalidInputError, match="source contains both"):
            parse_filter("source:auth", base=EventQuery(source="proxy.csv"))
        both = parse_filter("vpn", base=EventQuery(text="export")).query  # every text must match
        assert both.text == "export" and both.texts == ["vpn"]

    def test_contradictions_select_nothing(self, raven: RafContext) -> None:
        for text in (
            "outcome:success outcome:failure",
            "actor:alice actor:bob",
            "severity>critical",
            "synthetic:true synthetic:false",
        ):
            query = parse_filter(text, resolver=raven.resolver).query
            assert query.event_ids == [] and raven.store.events.count(query) == 0, text

    def test_lens_options_and_evidence_scope(self, raven: RafContext) -> None:
        from raf.products.lens.service import LensService

        service = LensService(raven)
        scope = service.scope_for([_evidence(raven, "proxy.csv")])
        everything = service.query(scope).total
        narrowed = service.query(scope, filter_text="object:APP-01")
        assert 0 < narrowed.total < everything
        assert narrowed.filters == ["object:APP-01", "evidence item proxy.csv"]
        assert service.query(scope, source="proxy").total == everything
        with pytest.raises(InvalidInputError):
            service.query(scope, source="auth.log")

    def test_cli(self, raven_home: Path, cli: Any) -> None:
        alice = cli("--json", "timeline", "user", "alice").json()["total"]
        narrowed = cli("--json", "timeline", "user", "alice", "--filter", "object:DEV-01")
        assert narrowed.exit_code == 0 and 0 < narrowed.json()["total"] < alice
        assert cli("--json", "timeline", "job-1", "--filter", "job:job-2").json()["total"] == 0
        window = cli("--json", "timeline", "--from", "2026-10-06T22:00:00Z", "--filter", "after:2026-10-01T00:00:00Z")
        assert window.json()["total"] == cli("--json", "timeline", "--from", "2026-10-06T22:00:00Z").json()["total"]


# --------------------------------------------------------------------------- 20: filter syntax


class TestFilterSyntax:
    def test_equals_means_colon_and_unknown_keys_fail(self) -> None:
        assert parse_filter("outcome=failure").query.outcome == parse_filter("outcome:failure").query.outcome
        for text in ("colour:blue", "colour=blue", "colour>=3"):
            with pytest.raises(InvalidInputError, match="Unknown filter key 'colour'") as info:
                parse_filter(text)
            assert "Keys: type, category" in (info.value.hint or "")

    def test_quoted_tokens_and_urls_are_free_text(self) -> None:
        assert parse_filter('"user=alice"').query.texts == ["user=alice"]
        assert parse_filter("'error: disk full'").query.texts == ["error: disk full"]
        assert parse_filter("https://portal.raven.example/x").query.texts == ["https://portal.raven.example/x"]
        assert parse_filter('actor:"John Smith"').query.actor == "John Smith"
        assert parse_filter("type:auth.login").terms == ["type:auth.login"]

    @pytest.mark.parametrize("text", ['a "b c" d\\ e', "x 'y z'", 'p "q\\"r" "s\\t"', "", "  lone  "])
    def test_tokens_follow_shell_rules(self, text: str) -> None:
        assert [token for token, _quoted in split_terms(text)] == shlex.split(text)

    def test_operators(self) -> None:
        assert parse_filter("severity>medium").query.min_severity == Severity.HIGH
        assert parse_filter("severity>=medium").query.min_severity == Severity.MEDIUM
        assert parse_filter("severity<=high").query.max_severity == Severity.HIGH
        assert parse_filter("severity<high").query.max_severity == Severity.MEDIUM
        assert parse_filter("severity<info").query.event_ids == []  # nothing is below INFO
        assert parse_filter("confidence>=0.6").query.min_confidence == 0.6
        assert parse_filter("confidence:high").query.min_confidence == 0.9  # a level name, as a minimum
        assert parse_filter("confidence<=60").query.max_confidence == 0.6  # a percentage
        assert parse_filter("confidence>0.5").query.min_confidence > 0.5
        for text, message in (
            ("type>=auth", "not an ordered value"),
            ("after>=2026-10-06T00:00:00Z", "not an ordered value"),
            ("job>job-1", "not an ordered value"),
            ("time:2026-10-06T00:00:00Z", "not a comparison"),
        ):
            with pytest.raises(InvalidInputError, match=message):
                parse_filter(text)

    def test_free_text_terms_all_match(self, raven: RafContext) -> None:
        assert parse_filter("exfil upload").query.texts == ["exfil", "upload"]
        parsed = parse_filter('type:http "exfil upload"')
        assert parsed.query.texts == ["exfil upload"] and parsed.terms == ["type:http", '"exfil upload"']
        both = raven.store.events.count(parse_filter("files.exfil-test.example upload").query)
        either = raven.store.events.count(parse_filter("files.exfil-test.example").query)
        assert 0 < both < either

    def test_severity_and_confidence_ranges_on_events(self, raven: RafContext) -> None:
        low = list(raven.store.events.iter(parse_filter("severity<=low").query))
        assert low and all(e.severity.rank <= Severity.LOW.rank for e in low)
        doubtful = list(raven.store.events.iter(parse_filter("confidence<0.8").query))
        assert doubtful and all(e.confidence < 0.8 for e in doubtful)
        assert raven.store.events.count(parse_filter("confidence>=0.8").query) == raven.store.events.count(
            EventQuery()
        ) - len(doubtful)

    def test_values_are_checked(self) -> None:
        for text in ("synthetic:maybe", "job:5", "type:", '"open'):
            with pytest.raises(InvalidInputError):
                parse_filter(text)
        assert parse_filter("job:JOB-4").query.job_ids == ["job-4"]
        assert parse_filter("synthetic:no").query.synthetic is False


# --------------------------------------------------------------------------- 21, 23: help topics


def test_help_topics(raf_home: Path, cli: Any) -> None:
    from raf.apps.cli.helptopics import HELP_TOPICS

    query = HELP_TOPICS["query"]
    assert HELP_TOPICS["filters"] == query
    filters = cli("help", "filters")
    assert filters.exit_code == 0 and "R$F FILTER LANGUAGE" in filters.stdout
    for text in ("filter=", "incident:INC-001", "job:job-4", "synthetic:true", "time>=", "never widen"):
        assert text in query
    assert "?q=" not in query
    for token in ("@case", "@lab", "@ghost", "@range"):
        assert token in HELP_TOPICS["refs"]
    relationships = HELP_TOPICS["relationships"]
    assert "Trace does not traverse relationships" in relationships and "Blast / IAM / Trace" not in relationships
    plugins = HELP_TOPICS["plugins"]
    assert "PluginContext" not in plugins and "not enforced" in plugins


# --------------------------------------------------------------------------- 22: evidence item IDs


def test_evidence_item_ids_resolve(raven: RafContext) -> None:
    item = _evidence(raven, "proxy.csv")
    short = item.split(":", 1)[1]
    assert raven.resolve(short).id == item and raven.resolve(short.upper()).id == item
    assert resolve_scope(raven, [short]).id == item
    with pytest.raises(NotFoundError):
        raven.resolve("ev-9999")
    raven.store.objects.upsert_drafts([ObjectDraft.make("host", short)])  # an object *named* like the item
    resolved = raven.resolve(short)
    assert resolved.id == f"host:{short}" and any(item in note for note in resolved.notes)


def test_lens_takes_an_evidence_item_id(raven_home: Path, cli: Any) -> None:
    result = cli("--json", "lens", "ev-0005")
    assert result.exit_code == 0, result.stdout
    assert result.json()["scope"]["id"] == "evidence:ev-0005" and result.json()["total"] > 0


# --------------------------------------------------------------------------- 23: context references


def test_a_named_reference_must_be_of_an_accepted_kind(ctx: RafContext) -> None:
    ctx.store.objects.upsert_drafts([ObjectDraft.make("host", "demo-lab")])  # same name as the lab
    ctx.refs.remember("lab", "demo-lab")
    assert ctx.refs.resolve("@lab", accept=("lab",)) == ("lab", "demo-lab")
    with pytest.raises(InvalidInputError, match="refers to a lab, which this command does not accept"):
        ctx.resolve("@lab")  # never the host of the same name
    ctx.refs.remember("case", "INC-9")
    with pytest.raises(InvalidInputError, match="an evidence case"):
        ctx.refs.resolve("@case", accept=("snapshot",))


def test_ghost_models_are_remembered(raven_home: Path, cli: Any) -> None:
    assert cli("ghost", "create", "gm").exit_code == 0
    assert _refs(raven_home, "@ghost") == ("ghost", "gm")
    assert cli("ghost", "clone", "gm", "gm2").exit_code == 0
    assert _refs(raven_home, "@ghost") == ("ghost", "gm2")
    assert cli("ghost", "show", "gm").exit_code == 0
    assert _refs(raven_home, "@ghost") == ("ghost", "gm")
    assert cli("ghost", "modify", "gm2", "--isolate", "LAB-01").exit_code == 0
    assert _refs(raven_home, "@last", accept=("ghost",)) == ("ghost", "gm2")
    diff = cli("--json", "diff", "@ghost", "current")
    assert diff.exit_code == 4 and "Ghost model" in diff.json()["error"]["message"]


# --------------------------------------------------------------------------- scopes: events, findings, snapshots


def test_events_findings_and_snapshots_are_not_scopes(raven_home: Path, cli: Any) -> None:
    event = cli("--json", "timeline", "INC-001", "--limit", "1").json()["items"][0]["id"]
    finding = cli("--json", "findings", "--limit", "1").json()["items"][0]["id"]
    cases = (
        (("timeline", event), f"'{event}' is an event, which is not a scope.", f"raf show {event}"),
        (("graph", finding), f"'{finding}' is a finding, which is not a scope.", f"raf show {finding}"),
        (("lens", event), f"'{event}' is an event, which is not a scope.", f"raf show {event}"),
        (("replay", finding), f"'{finding}' is a finding, which is not a scope.", f"raf show {finding}"),
        (
            ("lens", "snapshot:before"),
            "'snapshot:before' is a snapshot, which is not a scope.",
            "raf snapshot show before",
        ),
    )
    for args, message, suggestion in cases:
        result = cli("--json", *args)
        assert result.exit_code == 4, (args, result.stdout)
        error = result.json()["error"]
        assert error["code"] == "raf.invalid_input" and error["message"] == message
        assert error["suggestions"] == [suggestion]
    human = cli("timeline", event)
    assert human.exit_code == 4 and "is an event, which is not a scope" in human.stderr
    assert "internal error" not in human.stderr
    assert cli("show", event).exit_code == 0 and cli("show", finding).exit_code == 0  # the suggestions work


def test_object_terms_take_objects(raven: RafContext) -> None:
    event = next(iter(raven.store.events.iter(EventQuery(), with_objects=False))).id
    for key in ("object", "actor", "target", "incident"):
        with pytest.raises(InvalidInputError, match=f"{key}: takes an object"):
            parse_filter(f"{key}:{event}", resolver=raven.resolver)


# --------------------------------------------------------------------------- 24: scope type words


def test_scope_type_words(raven: RafContext) -> None:
    assert resolve_scope(raven, ["ipaddress", "10.30.0.5"]).id == "ip:10.30.0.5"
    assert resolve_scope(raven, ["HOST", "WS-02"]).id == "host:ws-02"
    raven.store.objects.upsert_drafts([ObjectDraft.make("x-asset", "tank-7")])
    assert resolve_scope(raven, ["x-asset", "tank-7"]).id == "x-asset:tank-7"
    with pytest.raises(InvalidInputError, match="'teapot' is not an object type"):
        resolve_scope(raven, ["teapot", "WS-02"])


def test_commands_refuse_records_they_do_not_take(raven_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Event, finding and snapshot IDs only reach commands that handle them; the others say what to run."""
    from raf.core.snapshots.service import SnapshotService
    from tests.conftest import run_cli

    monkeypatch.setenv("RAF_HOME", str(raven_home))
    ctx = open_context()
    event_id = ctx.store.events.query(EventQuery(), limit=1).items[0].id
    finding_id = ctx.store.findings.list(limit=1)[0].id
    SnapshotService(ctx.store).create("refs-check")
    ctx.close()
    for args, suggestion in (
        (("blast", event_id), f"raf show {event_id}"),
        (("iam", "show", finding_id), f"raf show {finding_id}"),
        (("graph", "neighbors", event_id), f"raf show {event_id}"),
        (("show", "snapshot:refs-check"), "raf snapshot show refs-check"),
    ):
        result = run_cli("--json", *args)
        error = json.loads(result.stdout)["error"]
        assert result.exit_code == 4, (args, result.stdout, result.stderr)
        assert "does not accept" in error["message"] and suggestion in error["suggestions"], (args, error)
    # the commands that handle records still take them
    assert run_cli("show", event_id).exit_code == 0
    assert run_cli("show", finding_id).exit_code == 0
    assert run_cli("trace", event_id).exit_code == 0
