"""``raf analyze``: detect an input's type and run the matching analysis pipeline (``analysis-N``)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import typer
from rich.text import Text

from raf.analysis.analyze import AnalysisResult, AnalysisStep, AnalyzeOptions, analyze_path, get_analysis
from raf.core.security.text import terminal_safe
from raf.core.storage.repos.analyses import AnalysisRecord
from raf.sdk import cli as rt

PANEL = "Data"
_ANALYSIS_ID = re.compile(r"analysis-\d{1,9}")
_MARK = {"ok": ("✓", "green"), "skipped": ("-", "dim"), "failed": ("✗", "bold red")}


def _step_line(step: AnalysisStep | dict[str, Any]) -> Text:
    data = step.to_json_dict() if isinstance(step, AnalysisStep) else step
    mark, style = _MARK.get(str(data["status"]), ("?", ""))
    line = Text(f"  {mark} ", style=style)
    line.append(f"{data['name']:<24} ", style="bold" if data["status"] == "ok" else style)
    detail = terminal_safe(str(data.get("detail") or ""))
    if data["status"] == "skipped":
        detail = f"skipped: {detail}"
    line.append(detail, style="red" if data["status"] == "failed" else "dim" if data["status"] == "skipped" else "")
    if float(data.get("duration_ms") or 0) >= 10:
        line.append(f"  {float(data['duration_ms']) / 1000:.2f} s", style="dim")
    return line


def _summary_rows(stats: dict[str, Any]) -> list[tuple[str, Any]]:
    rows: list[tuple[str, Any]] = []
    for key, label in (
        ("objects", "Objects"),
        ("relationships", "Relationships"),
        ("events", "Events"),
        ("flows", "Flows"),
        ("packages", "Packages"),
        ("vulnerable_packages", "Vulnerable"),
        ("secrets", "Secrets"),
        ("detections", "Detections"),
        ("findings", "Findings"),
    ):
        if key in stats:
            rows.append((label, f"{int(stats[key]):>8,}"))
    if stats.get("incidents"):
        rows.append(("Incidents", ", ".join(i.split(":", 1)[1].upper() for i in stats["incidents"])))
    return rows


def render_detections(findings: list[dict[str, Any]], explained: list[dict[str, Any]]) -> None:
    """The detections of an analysis (most severe first) and what was ruled out, one line each."""
    if rt.STATE.quiet or not (findings or explained):
        return
    c = rt.console()
    if findings:
        c.print()
        c.print(Text("Detections:", style="bold"))
        for item in findings:
            line = Text("  ")
            line.append_text(rt.sev_text(str(item.get("severity") or "INFO")))
            line.append(" " * max(1, 10 - len(str(item.get("severity") or ""))))
            line.append(terminal_safe(str(item.get("title") or "")))
            c.print(line)
    if explained:
        c.print()
        c.print(Text("Explained (no finding):", style="bold"))
        for item in explained:
            c.print(
                Text(
                    f"  {terminal_safe(str(item.get('title')))}: {terminal_safe(str(item.get('reason')))}", style="dim"
                )
            )


def render_result(result: AnalysisResult, *, live: bool) -> None:
    c = rt.console()
    if not live:
        rt.header(f"R$F ANALYZE  {result.input_name}", result.id)
        c.print(Text("Running:", style="bold"))
        for step in result.steps[1:]:
            c.print(_step_line(step))
    c.print()
    rt.kv_block(_summary_rows(result.stats), width=15)
    render_detections(result.stats.get("top_findings") or [], result.stats.get("explained") or [])
    if result.status == "partial":
        rt.warn("some steps failed; the rest of the analysis completed (see above)")
    rt.next_steps(result.suggestions, title="Explore")


def render_record(record: AnalysisRecord) -> None:
    stats = record.stats
    rt.header(f"R$F ANALYSIS  {record.id}", f"{stats.get('input_name') or record.input}")
    rt.kv_block(
        [
            ("Input", record.input),
            ("SHA-256", record.input_sha256 or "-"),
            ("Detected", stats.get("detected_label") or record.detected_type),
            ("Status", record.status),
            ("Created", rt.ts_text(record.created_at)),
            ("Jobs", ", ".join(record.job_ids) or "-"),
        ],
        width=10,
    )
    c = rt.console()
    c.print()
    c.print(Text("Steps:", style="bold"))
    for step in record.steps:
        c.print(_step_line(step))
    c.print()
    rt.kv_block(_summary_rows(stats), width=15)
    render_detections(stats.get("top_findings") or [], stats.get("explained") or [])
    rt.next_steps(record.suggestions, title="Explore")


def register(app: typer.Typer) -> None:
    @app.command(
        "analyze",
        rich_help_panel=PANEL,
        help="""Analyze any input: R$F detects what it is and runs the matching pipeline.

  raf analyze capture.pcap                 Protocol → Timeline → Graph → Exposure correlation → Findings
  raf analyze ./fixtures/raven-events.jsonl
  raf analyze ./evidence                   every data file in a directory
  raf analyze ./my-repo                    Dependency scan + Vault secret scan
  raf analyze sbom.cdx.json                SBOM import + advisory matching
  raf analyze backup.raf                   verify and import an R$F bundle
  raf analyze analysis-3                   show an earlier analysis

Every executed module is listed. The result is recorded as analysis-N: explore it with
raf lens/graph/timeline analysis-N (or @last).""",
    )
    def analyze_cmd(
        target: str = typer.Argument(..., help="File, directory, or an earlier analysis-N."),
        format_: str | None = typer.Option(None, "--format", "-f", help="Force a parser for data files."),
        incident: str | None = typer.Option(None, "--incident", help="Attach imported events to this incident."),
        source_name: str | None = typer.Option(None, "--source-name", help="Provenance name for the source."),
        synthetic: bool = typer.Option(False, "--synthetic", help="Mark imported data as synthetic."),
        no_correlate: bool = typer.Option(
            False, "--no-correlate", help="Skip workspace-wide IAM and exposure re-analysis."
        ),
    ) -> None:
        ctx = rt.ctx()
        path = Path(target)
        if _ANALYSIS_ID.fullmatch(target) and not path.exists():
            record = get_analysis(ctx, target)
            ctx.refs.remember("analysis", record.id)
            rt.output("raf.analysis/v1", record.to_json_dict(), lambda: render_record(record))
            return
        live = not rt.STATE.json and not rt.STATE.quiet
        c = rt.console()
        if live:
            rt.header(f"R$F ANALYZE  {path.name or target}")

        def on_step(step: AnalysisStep) -> None:
            if not live:
                return
            if step.name == "Detect":
                c.print(Text("Detected: ", style="bold") + Text(terminal_safe(step.detail)))
                c.print()
                c.print(Text("Running:", style="bold"))
                return
            c.print(_step_line(step))

        options = AnalyzeOptions(
            format=format_,
            incident=incident,
            source_name=source_name,
            synthetic=synthetic,
            correlate=not no_correlate,
            on_step=on_step,
        )
        result = analyze_path(ctx, path, options)
        if live:
            c.print(Text(f"  → {result.id}", style="bold cyan"))
        rt.output("raf.analysis/v1", result.to_json_dict(), lambda: render_result(result, live=live))
        if result.status == "failed":
            raise typer.Exit(1)

    @app.command(
        "detect",
        rich_help_panel=PANEL,
        help="""Run R$F detections over events: web reconnaissance, exposed artifacts, cloud credentials used
from public addresses, bulk storage reads, persistence attempts, large transfers, brute force, password
spraying, MFA fatigue, new external sign-ins, destructive changes, log tampering, suspicious commands,
risky SQL, DNS tunneling and large exports. Detections sharing entities become a suspected incident.

  raf detect                 the whole workspace
  raf detect analysis-3      the events of an analysis (raf analyze runs this for you)
  raf detect INC-001         an incident's events
  raf detect --dry-run       report only: no findings or incidents are stored

Activity covered by an approved change record or carrying its own ticket is listed as explained.""",
    )
    def detect_cmd(
        words: list[str] = typer.Argument(None, help="Scope: analysis-N, an incident, an object, or 'workspace'."),
        dry_run: bool = typer.Option(False, "--dry-run", help="Show detections without storing anything."),
    ) -> None:
        ctx = rt.ctx()
        if ctx.registry is not None:
            ctx.registry.require("timeline")
        from raf.core.query.scope import resolve_scope
        from raf.products.timeline.detections import DetectionService

        scope = resolve_scope(ctx, words or [])
        for message in scope.notes:
            rt.note(message)
        report = DetectionService(ctx).run(scope.event_query(), scope_label=scope.id, persist=not dry_run)
        if not dry_run:
            ctx.audit.record(
                "detections.run",
                affected=[scope.id],
                details={"findings": len(report.findings), "incidents": [i.name for i in report.incidents]},
            )
            for incident in report.incidents[:1]:
                ctx.refs.remember("incident", incident.id)

        def render() -> None:
            rt.header(f"R$F DETECT  {scope.label}", "dry run: nothing stored" if dry_run else None)
            rt.kv_block(
                [
                    ("Events", f"{report.events_examined:,}"),
                    ("Detections", f"{len(report.findings):,}"),
                    ("Explained", f"{len(report.explained):,}"),
                    ("Incidents", ", ".join(dict.fromkeys(i.name for i in report.incidents)) or "-"),
                ]
                + ([("Resolved", f"{report.resolved:,} earlier detection(s)")] if report.resolved else []),
                width=12,
            )
            render_detections(
                [{"severity": f.severity.value, "title": f.title} for f in report.findings],
                [{"title": e.title, "reason": e.reason} for e in report.explained],
            )
            for incident in report.incidents:
                c = rt.console()
                c.print()
                c.print(Text(f"{incident.name}  {terminal_safe(incident.title)}", style="bold"))
                for line in incident.narrative:
                    c.print(Text(f"  {terminal_safe(line)}"))
            steps = [f"raf finding show {report.findings[0].id}"] if report.findings else []
            for incident in report.incidents[:1]:
                steps += [f"raf timeline {incident.name}", f"raf replay {incident.name}", f"raf graph {incident.name}"]
            rt.next_steps(steps)

        rt.output("raf.detections/v1", report.to_json_dict(), render)

    @app.command("analyses", rich_help_panel=PANEL)
    def analyses_cmd(limit: int = typer.Option(20, "--limit", min=1, max=500)) -> None:
        """Earlier analyses of this workspace (newest first)."""
        ctx = rt.ctx()
        records = ctx.store.analyses.list(limit=limit)
        data = {"items": [r.to_json_dict() for r in records], "total": ctx.store.analyses.count()}

        def render() -> None:
            rt.header("R$F ANALYSES")
            if not records:
                rt.console().print("No analyses yet.")
                rt.next_steps(["raf analyze <file or directory>"])
                return
            rt.table(
                ["ID", "CREATED", "TYPE", "STATUS", "INPUT", "EVENTS", "OBJECTS", "FINDINGS"],
                [
                    (
                        r.id,
                        rt.ts_text(r.created_at),
                        r.stats.get("detected_label") or r.detected_type,
                        r.status,
                        r.stats.get("input_name") or Path(r.input).name,
                        r.stats.get("events", "-"),
                        r.stats.get("objects", "-"),
                        r.stats.get("findings", "-"),
                    )
                    for r in records
                ],
            )
            rt.next_steps([f"raf analyze {records[0].id}", f"raf lens {records[0].id}"])

        rt.output("raf.analyses/v1", data, render)
