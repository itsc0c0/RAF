"""``raf evidence``: DFIR cases, hashed read-only evidence and chain of custody."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.text import Text

from raf.products.evidence.service import EvidenceCase, EvidenceItem, EvidenceService, ImportResult, VerifyResult
from raf.sdk import cli as rt

app = typer.Typer(
    add_completion=False,
    help="""DFIR evidence: cases, SHA-256 hashed read-only copies, chain of custody.

  raf evidence case create INC-042
  raf evidence import ./artifact --case INC-042
  raf evidence list --case INC-042
  raf evidence verify --case INC-042""",
)
case_app = typer.Typer(add_completion=False, help="Evidence cases.")
app.add_typer(case_app, name="case")


def _size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:,.0f} {unit}" if unit == "B" else f"{n:,.1f} {unit}"
        n /= 1024  # type: ignore[assignment]
    return f"{n} B"


def render_items(items: list[EvidenceItem]) -> None:
    if not items:
        rt.console().print("No evidence items.")
        return
    rt.table(
        ["ID", "NAME", "TYPE", "SIZE", "SHA-256", "STATUS", "EVENTS", "IMPORTED", "DERIVED FROM"],
        [
            (
                i.id,
                i.name,
                i.type,
                _size(i.size),
                i.sha256[:16],
                i.status,
                i.events,
                rt.ts_text(i.imported_at),
                i.derived_from or "",
            )
            for i in items
        ],
    )


def render_item(item: EvidenceItem) -> None:
    rt.header(f"EVIDENCE {item.id}  {item.name}", f"case {item.case}")
    rt.kv_block(
        [
            ("Case", item.case),
            ("Source", item.source),
            ("Imported", rt.ts_text(item.imported_at)),
            ("SHA-256", item.sha256),
            ("Size", f"{item.size:,} bytes"),
            ("Type", f"{item.type} ({item.media_type})"),
            ("Stored", f"evidence/{item.stored} (read-only)"),
            ("Status", item.status),
            ("Parser", item.parser or "-"),
            ("Events", item.events),
            ("Derived from", item.derived_from or "-"),
            ("Job", item.job or "-"),
        ],
        width=14,
    )
    c = rt.console()
    if item.notes:
        c.print()
        c.print(Text("Notes", style="bold"))
        for note in item.notes:
            c.print(Text(f"  {note}"))
    c.print()
    c.print(Text("Chain of custody", style="bold"))
    for entry in item.custody:
        details = ", ".join(f"{k}={v}" for k, v in entry.details.items() if v not in (None, ""))
        c.print(
            Text(f"  {entry.seq:>2}. {rt.ts_text(entry.at)}  ", style="dim")
            + Text(f"{entry.action:<9}", style="bold")
            + Text(f" {entry.actor}  ")
            + Text(details[:220], style="dim")
        )
        c.print(Text(f"      hash {entry.hash[:16]} ← {entry.prev_hash[:16]}", style="dim"))


def render_case(case: EvidenceCase, items: list[EvidenceItem]) -> None:
    rt.header(f"EVIDENCE CASE {case.name}", case.title or None)
    rt.kv_block(
        [
            ("Status", case.status),
            ("Incident", case.incident or "-"),
            ("Items", len(items)),
            ("Created", f"{rt.ts_text(case.created_at)} by {case.created_by}"),
        ],
        width=10,
    )
    if case.description:
        rt.console().print()
        rt.console().print(Text(case.description))
    rt.console().print()
    render_items(items)


@case_app.command("create", help="Create a case (linked to the incident of the same name when it exists).")
def case_create(
    name: str = typer.Argument(..., help="Case name, e.g. INC-042."),
    title: str = typer.Option("", "--title"),
    description: str = typer.Option("", "--description", "-d"),
    incident: str | None = typer.Option(None, "--incident", help="Link to this incident (default: same name)."),
) -> None:
    ctx = rt.ctx()
    case = EvidenceService(ctx).create_case(name, title=title, description=description, incident=incident)
    ctx.refs.remember("case", case.name)

    def render() -> None:
        rt.success(f"Case '{case.name}' created" + (f", linked to {case.incident}." if case.incident else "."))
        rt.next_steps([f"raf evidence import ./artifact --case {case.name}"])

    rt.output("raf.evidence.case/v1", case.to_json_dict(), render)


@case_app.command("list", help="Evidence cases.")
def case_list() -> None:
    ctx = rt.ctx()
    service = EvidenceService(ctx)
    cases = service.cases()
    counts = {c.name: len(service.items(c.name)) for c in cases}

    def render() -> None:
        if not cases:
            rt.console().print("No evidence cases.")
            rt.next_steps(["raf evidence case create INC-001"])
            return
        rt.table(
            ["CASE", "TITLE", "INCIDENT", "ITEMS", "STATUS", "CREATED"],
            [(c.name, c.title, c.incident or "", counts[c.name], c.status, rt.ts_text(c.created_at)) for c in cases],
        )

    rt.output("raf.evidence.cases/v1", {"items": [c.to_json_dict() | {"items": counts[c.name]} for c in cases]}, render)


@case_app.command("show", help="A case with its items.")
def case_show(name: str = typer.Argument(...)) -> None:
    ctx = rt.ctx()
    service = EvidenceService(ctx)
    case = service.get_case(name)
    items = service.items(case.name)
    rt.output(
        "raf.evidence.case/v1",
        case.to_json_dict() | {"items": [i.to_json_dict() for i in items]},
        lambda: render_case(case, items),
    )


@app.command("import", help="Hash, store read-only and (by default) parse evidence files or a directory.")
def import_cmd(
    path: Path = typer.Argument(..., help="File or directory (directories are walked; symlinks are not followed)."),
    case: str = typer.Option(..., "--case", help="Target case."),
    parse: bool = typer.Option(True, "--parse/--no-parse", help="Parse into events (from the stored copy)."),
    note: str | None = typer.Option(None, "--note", help="Analyst note recorded with each item."),
    derived_from: str | None = typer.Option(None, "--derived-from", help="Item this artifact was derived from."),
    synthetic: bool = typer.Option(False, "--synthetic", help="Mark parsed data as synthetic (fixtures, labs)."),
) -> None:
    ctx = rt.ctx()
    result: ImportResult = EvidenceService(ctx).import_path(
        path, case, parse=parse, note=note, derived_from=derived_from, synthetic=synthetic
    )

    def render() -> None:
        rt.success(f"Imported {len(result.items)} evidence item(s) into case {result.case} ({result.job}).")
        render_items(result.items)
        if result.incident:
            rt.note(f"{result.linked_events} event(s) inside the incident window were linked to {result.incident}.")
        for skipped in result.skipped:
            rt.warn(f"skipped {skipped['path']}: {skipped['reason']}")
        rt.next_steps(
            [
                f"raf evidence verify --case {result.case}",
                f"raf evidence show {result.items[0].id}" if result.items else "raf evidence list",
                f"raf timeline {result.case}"
                if result.incident == f"incident:{result.case.lower()}"
                else (f"raf timeline {result.incident}" if result.incident else "raf timeline workspace"),
            ]
        )

    rt.output("raf.evidence.import/v1", result.to_json_dict(), render)


@app.command("list", help="Evidence items (optionally of one case).")
def list_cmd(case: str | None = typer.Option(None, "--case")) -> None:
    ctx = rt.ctx()
    items = EvidenceService(ctx).items(case)
    rt.output(
        "raf.evidence.list/v1", {"case": case, "items": [i.to_json_dict() for i in items]}, lambda: render_items(items)
    )


@app.command("show", help="One item with its metadata and chain of custody.")
def show_cmd(item: str = typer.Argument(..., help="Item ID (ev-0001).")) -> None:
    ctx = rt.ctx()
    found = EvidenceService(ctx).get_item(item)
    rt.output("raf.evidence.item/v1", found.to_json_dict(), lambda: render_item(found))


@app.command("verify", help="Re-hash stored copies and check every chain of custody.")
def verify_cmd(
    items: list[str] = typer.Argument(None, help="Item IDs (default: all items of --case, or all)."),
    case: str | None = typer.Option(None, "--case"),
) -> None:
    ctx = rt.ctx()
    result: VerifyResult = EvidenceService(ctx).verify(case=case, item_ids=list(items) if items else None)

    def render() -> None:
        rt.header("R$F EVIDENCE VERIFY", f"case {case}" if case else None)
        rt.table(
            ["ITEM", "NAME", "RESULT", "SHA-256", "DETAIL"],
            [
                (
                    r["id"],
                    r["name"],
                    Text("OK", style="green") if r["ok"] else Text("FAILED", style="bold red"),
                    (r["actual"] or "-")[:16],
                    r["reason"] or "",
                )
                for r in result.items
            ],
        )
        if result.verified:
            rt.success("All evidence verified: hashes match and every chain of custody is intact.")
        else:
            rt.warn("Verification FAILED for at least one item.")

    rt.output("raf.evidence.verify/v1", result.to_json_dict(), render)
    if not result.verified:
        raise typer.Exit(5)


@app.command("note", help="Add an analyst note (recorded in the chain of custody).")
def note_cmd(item: str = typer.Argument(...), text: str = typer.Argument(...)) -> None:
    ctx = rt.ctx()
    updated = EvidenceService(ctx).note(item, text)
    rt.output("raf.evidence.item/v1", updated.to_json_dict(), lambda: rt.success(f"Note added to {updated.id}."))


@app.command("export", help="Copy an item out of the store after verifying it (recorded in custody).")
def export_cmd(item: str = typer.Argument(...), output: Path = typer.Option(..., "--output", "-o")) -> None:
    ctx = rt.ctx()
    exported, target = EvidenceService(ctx).export(item, output)
    rt.output(
        "raf.evidence.export/v1",
        {"item": exported.id, "path": str(target), "sha256": exported.sha256},
        lambda: rt.success(f"Exported {exported.id} to {target} (sha256 {exported.sha256[:16]})."),
    )
