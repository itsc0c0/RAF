"""``raf import``: ingest files and directories into the current workspace."""

from __future__ import annotations

import json
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import typer
from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn
from rich.text import Text

from raf.analysis.ingest import import_path
from raf.core.errors import IngestionError, InvalidInputError, NotFoundError
from raf.core.ingestion.pipeline import IngestOptions, IngestReport
from raf.sdk import cli as rt

PANEL = "Data"


@contextmanager
def progress_bar(description: str) -> Iterator[Callable[[float, str | None], None] | None]:
    """A transient progress bar on stderr (only for interactive, non-JSON, non-quiet runs)."""
    if rt.STATE.json or rt.STATE.quiet or not sys.stderr.isatty():
        yield None
        return
    progress = Progress(
        TextColumn("[bold]{task.description}"),
        BarColumn(),
        TextColumn("{task.percentage:>3.0f}%"),
        TextColumn("{task.fields[detail]}", style="dim"),
        TimeElapsedColumn(),
        console=rt.err_console(),
        transient=True,
    )
    with progress:
        task = progress.add_task(description, total=1.0, detail="")

        def update(fraction: float, message: str | None) -> None:
            progress.update(task, completed=fraction, detail=message or "")

        yield update


def format_label(report: IngestReport) -> str:
    """``jsonl (jsonl/1.0, raf-native)`` for a file; ``directory (syslog, jsonl)`` with the formats of its files."""
    if report.parser:
        return f"{report.format} ({report.parser}{', ' + report.normalizer if report.normalizer else ''})"
    formats = list(dict.fromkeys(str(f["format"]) for f in report.files if f.get("format")))
    return f"{report.format or '-'}" + (f" ({', '.join(formats)})" if formats else "")


def render_report(report: IngestReport, job_id: str | None, title: str = "R$F IMPORT") -> None:
    rt.header(f"{title}  {report.source}")
    rows: list[tuple[str, Any]] = [
        ("Format", format_label(report)),
        ("Processed", f"{report.processed:,}"),
        ("Accepted", f"{report.accepted:,}"),
        ("Rejected", Text(f"{report.rejected:,}", style="yellow" if report.rejected else "")),
    ]
    if report.warnings:
        rows.append(("Warnings", f"{report.warnings:,}  ({'; '.join(report.warning_samples[:2])})"))
    rows += [
        ("Objects", f"{report.objects_created:,} created, {report.objects_updated:,} updated"),
        ("Relationships", f"{report.relationships_created:,} created, {report.relationships_updated:,} updated"),
        (
            "Events",
            f"{report.events_created:,} created"
            + (f", {report.events_duplicate:,} already present" if report.events_duplicate else ""),
        ),
    ]
    if report.findings_created:
        rows.append(("Findings", f"{report.findings_created:,} imported"))
    if report.incidents:
        rows.append(("Incidents", ", ".join(i.split(":", 1)[1].upper() for i in report.incidents)))
    if report.files:
        rows.append(("Files", f"{len(report.files):,} imported, {len(report.skipped_files):,} skipped"))
    if report.sha256:
        rows.append(("SHA-256", report.sha256))
    if report.duration_ms is not None:
        rows.append(("Duration", f"{report.duration_ms / 1000:.2f} s"))
    rt.kv_block(rows, width=15)
    c = rt.console()
    if report.rejections:
        first = report.rejections[0]
        c.print()
        c.print(
            Text(
                f"R$F could not parse record {first.record}"
                + (f" of {first.source}" if first.source and first.source != report.source else "")
                + ".",
                style="yellow",
            )
        )
        c.print(Text("Reason:", style="bold"))
        c.print(Text(f"  {first.reason}"))
        c.print(Text(f"The remaining {report.accepted:,} records were imported."))
        if job_id:
            c.print(Text("Run:", style="bold"))
            c.print(Text(f"  raf import report {job_id}", style="cyan"))
            c.print(Text("for details.", style="dim"))


def register(app: typer.Typer) -> None:
    @app.command("import", rich_help_panel=PANEL)
    def import_cmd(
        path: str = typer.Argument(..., help="File or directory to import (or: report <job-id>)."),
        job_ref: str | None = typer.Argument(None, hidden=True),
        format_: str | None = typer.Option(
            None, "--format", "-f", help="Force a parser (jsonl, json, csv, syslog, access-log, text, filesystem, ...)."
        ),
        incident: str | None = typer.Option(None, "--incident", help="Attach imported events to this incident."),
        host: str | None = typer.Option(None, "--host", help="Default host for records that lack one."),
        source_name: str | None = typer.Option(None, "--source-name", help="Provenance name for the source."),
        timezone: str | None = typer.Option(None, "--timezone", help="Timezone for naive timestamps (IANA)."),
        synthetic: bool = typer.Option(False, "--synthetic", help="Mark imported data as synthetic."),
    ) -> None:
        """Import data (JSON, JSONL, CSV, syslog, access logs, directories) with full provenance.

        raf import report <job-id> shows the rejected records of an earlier import.
        """
        if path == "report":
            if not job_ref:
                raise InvalidInputError("Usage: raf import report <job-id>")
            _show_report(job_ref)
            return
        if job_ref:
            raise InvalidInputError("Import one path at a time (or a directory).")
        ctx = rt.ctx()
        target = Path(path)
        options = IngestOptions(
            format=format_,
            incident=incident,
            default_host=host,
            source_name=source_name,
            timezone=timezone,
            synthetic=synthetic,
        )
        with progress_bar(f"Importing {target.name}") as on_progress:
            job, report = import_path(ctx, target, options, on_progress=on_progress)
        if report is None:
            # One document, as for every failure: the error, with the failed job (and its own error) in details.
            error = job.error or {}
            raise IngestionError(
                str(error.get("message", "Import failed.")),
                reason=error.get("reason"),
                hint=error.get("hint"),
                suggestions=[f"raf job show {job.id}"],
                details={"job": job.model_dump(mode="json")},
            )
        data = report.to_json_dict() | {"job_id": job.id}

        def render() -> None:
            render_report(report, job.id)
            pivots = []
            if report.incidents:
                name = report.incidents[0].split(":", 1)[1].upper()
                pivots += [f"raf replay {name}", f"raf timeline {name}"]
            pivots += ["raf incidents", "raf objects --type host", "raf findings"]
            rt.next_steps(pivots)

        rt.output("raf.import/v1", data, render)

    def _show_report(job_id: str) -> None:
        ctx = rt.ctx()
        job = ctx.jobs.require(job_id)
        if job.kind not in ("import", "analyze", "evidence.import"):
            raise InvalidInputError(f"{job_id} is a {job.kind} job, not an import.")
        result = job.result or {}
        rejects: list[dict[str, Any]] = []
        rejects_file = result.get("rejects_file")
        if rejects_file and Path(rejects_file).exists():
            with Path(rejects_file).open(encoding="utf-8") as handle:
                for line_no, line in enumerate(handle):
                    if line_no >= 500:
                        break
                    rejects.append(json.loads(line))
        elif result.get("rejections"):
            rejects = list(result["rejections"])
        data = {"job": job.model_dump(mode="json"), "rejections": rejects}

        def render() -> None:
            rt.header(f"IMPORT REPORT {job.id}", job.title)
            rt.kv_block(
                [
                    ("Status", job.status.value),
                    ("Processed", f"{result.get('processed', 0):,}"),
                    ("Accepted", f"{result.get('accepted', 0):,}"),
                    ("Rejected", f"{result.get('rejected', 0):,}"),
                    ("Quarantine", rejects_file or "-"),
                ]
            )
            if not rejects:
                rt.console().print()
                rt.console().print("No rejected records.")
                return
            rt.console().print()
            rt.table(
                ["RECORD", "SOURCE", "REASON", "RAW (untrusted, truncated)"],
                [
                    (r.get("record"), r.get("source") or "-", r.get("reason"), (r.get("raw") or "")[:80])
                    for r in rejects[:100]
                ],
            )

        if job.status.value != "COMPLETED" and not result:
            raise NotFoundError(f"{job_id} has no import report (status {job.status.value}).")
        rt.output("raf.import.report/v1", data, render)
