"""``raf surface``: the authorized external attack surface, from imported inventories (no scanning)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import typer
from rich.text import Text
from rich.tree import Tree

from raf.core.errors import InvalidInputError
from raf.core.objects.models import Finding
from raf.core.objects.types import Severity
from raf.products.surface.rules import DEFAULT_EXPIRING_DAYS, RULES
from raf.products.surface.scope import ScopeEntry
from raf.products.surface.service import SurfaceAnalysis, SurfaceImportResult, SurfaceService
from raf.products.surface.views import SurfaceAsset, SurfaceSummary
from raf.sdk import cli as rt

app = typer.Typer(
    add_completion=False,
    help="""Authorized external attack surface from imported inventories (R$F never scans).

  raf surface scope add raven.example --owner "IT operations" --authorization SEC-2026-031
  raf surface import inventory.json [--apply-scope]   domains, DNS, IPs, services, certificates, cloud
  raf surface analyze                                  explainable findings (scope, ownership, DNS, TLS ...)
  raf surface show                                     summary and the domain → address → service tree
  raf surface assets --kind certificate                assets with scope, ownership and details""",
)
scope_app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="The authorized scope: domains, CIDR ranges, IPs and cloud accounts the organization declares as its own.",
)
app.add_typer(scope_app, name="scope")

_STATE_STYLE = {"expired": "bold red", "expiring": "yellow", "valid": "green", "unknown": "dim"}


# --------------------------------------------------------------------------- rendering


def _scope_text(status: str, entry: str | None = None) -> Text:
    if status == "in":
        return Text("in" + (f" ({entry})" if entry else ""), style="green")
    if status == "out":
        return Text("OUT", style="bold yellow")
    return Text("-", style="dim")


def _owner_text(asset: SurfaceAsset) -> Text:
    if asset.owners:
        text = Text(", ".join(asset.owners))
        if asset.owner_via:
            text.append(f" (via {asset.owner_via})", style="dim")
        return text
    if asset.claimed_owners:
        return Text("claimed: " + ", ".join(asset.claimed_owners), style="yellow")
    return Text("none", style="yellow" if asset.scope == "in" else "dim")


def render_scope(entries: list[ScopeEntry]) -> None:
    if not entries:
        rt.console().print(Text("No authorized scope is configured in this workspace."))
        rt.next_steps(["raf surface scope add <domain|cidr|ip|provider:account> --owner TEAM --authorization REF"])
        return
    rt.table(
        ["TARGET", "KIND", "OWNER", "AUTHORIZATION", "ADDED"],
        [
            (
                e.target,
                e.kind,
                e.owner or "-",
                e.authorization or Text("none recorded", style="yellow"),
                rt.ts_text(e.added_at),
            )
            for e in entries
        ],
    )


def render_import(result: SurfaceImportResult) -> None:
    rt.header(f"R$F SURFACE IMPORT  {result.source}")
    rows: list[tuple[str, Any]] = [("Format", result.format)]
    if result.organization:
        rows.append(("Organization", result.organization))
    if result.as_of:
        rows.append(("As of", rt.ts_text(result.as_of)))
    rows += [
        (
            "Records",
            Text(f"{result.records:,} read, {result.accepted:,} accepted, ")
            + Text(f"{result.rejected:,} rejected", style="yellow" if result.rejected else ""),
        ),
        ("By kind", ", ".join(f"{k} {v}" for k, v in result.by_kind.items()) or "-"),
        ("Objects", f"{result.objects_created:,} created, {result.objects_updated:,} updated"),
        (
            "Relationships",
            f"{result.relationships_created:,} created, {result.relationships_updated:,} updated",
        ),
    ]
    if result.scope_declared:
        if result.scope_applied:
            applied = [c for c in result.scope_changes if c.result in ("added", "replaced")]
            problems = [c for c in result.scope_changes if c.result in ("conflict", "invalid")]
            text = f"{result.scope_declared} declared, {len(applied)} added"
            if problems:
                text += f", {len(problems)} not applied"
            rows.append(("Scope", text))
        else:
            rows.append(("Scope", Text(f"{result.scope_declared} declared in the file, not applied", style="yellow")))
    rows += [("SHA-256", result.sha256), ("Job", result.job_id or "-")]
    rt.kv_block(rows, width=15)
    problems = [c for c in result.scope_changes if c.result in ("conflict", "invalid")]
    if problems:
        rt.console().print()
        rt.table(["SCOPE ENTRY", "RESULT", "DETAIL"], [(c.target, c.result, c.detail or "") for c in problems])
    if result.rejections:
        rt.console().print()
        rt.table(
            ["RECORD", "REASON"],
            [(r.record, r.reason) for r in result.rejections[:15]],
            title="Rejected records (the rest was imported)",
        )
        if len(result.rejections) > 15:
            rt.note(f"{result.rejected - 15} more rejected records: raf import report {result.job_id}")
    for warning in result.warnings[:10]:
        rt.warn(warning)
    if result.scope_declared and not result.scope_applied:
        rt.note("The file declares an authorized scope. Review it, then re-run with --apply-scope.")


def _severity_counts(counts: dict[str, int]) -> str:
    return ", ".join(f"{s.value} {counts[s.value]}" for s in reversed(Severity) if counts.get(s.value)) or "none"


def render_findings_table(findings: list[Finding], limit: int) -> None:
    if not findings:
        return
    rt.table(
        ["SEVERITY", "FINDING", "RULE", "CONFIDENCE"],
        [(rt.sev_text(f.severity), f.title, f.rule_id, rt.conf_text(f.confidence)) for f in findings[:limit]],
    )
    if len(findings) > limit:
        rt.note(f"{len(findings) - limit} more; use --limit or raf findings --product surface")


def render_analysis(analysis: SurfaceAnalysis, limit: int) -> None:
    rt.header("R$F SURFACE ANALYSIS")
    rt.kv_block(
        [
            ("Reference time", f"{rt.ts_text(analysis.reference_time)} ({analysis.reference_source})"),
            ("Expiring window", f"{analysis.expiring_days} days"),
            ("Scope", f"{analysis.scope_entries} entries" if analysis.scope_entries else Text("none", style="yellow")),
            ("Assets", f"{analysis.assets} ({analysis.in_scope} in scope, {analysis.out_of_scope} out of scope)"),
            (
                "Findings",
                f"{len(analysis.findings)}"
                + (f" ({analysis.created} new, {analysis.resolved} auto-resolved)" if analysis.persisted else "")
                + ("" if analysis.persisted else " (not saved)"),
            ),
            ("By severity", _severity_counts(analysis.by_severity)),
        ],
        width=17,
    )
    for note in analysis.notes:
        rt.note(note)
    if analysis.by_rule:
        rt.console().print()
        rt.table(["RULE", "FINDINGS"], [(rule, analysis.by_rule[rule]) for rule in RULES if rule in analysis.by_rule])
    if analysis.findings:
        rt.console().print()
        render_findings_table(analysis.findings, limit)


def _service_label(service: dict[str, Any]) -> Text:
    text = Text(f"{service.get('port')}/{service.get('transport') or 'tcp'}", style="bold")
    name = str(service.get("name") or "")
    if name and ":" not in name:  # services without a name are keyed by their endpoint
        text.append(f" {name}")
    if service.get("product"):
        text.append(f" · {service['product']}", style="dim")
    if service.get("internet_facing"):
        text.append(" · internet-facing", style="red")
    if service.get("status") not in (None, "active"):
        text.append(f" · {service['status']}", style="yellow")
    return text


def _certificate_label(cert: dict[str, Any]) -> Text:
    text = Text("certificate ", style="dim")
    text.append(str(cert.get("name") or ""))
    state, days, until = cert.get("state"), cert.get("days_remaining"), str(cert.get("not_after") or "")[:10]
    if state == "expired":
        label = f"EXPIRED {until}"
    elif state == "expiring":
        label = f"expires {until} ({days} days)"
    elif state == "valid":
        label = f"until {until}"
    else:
        label = "no expiry recorded"
    text.append(" · ")
    text.append(label, style=_STATE_STYLE.get(str(state), ""))
    return text


def _record_branch(parent: Tree, record: dict[str, Any]) -> None:
    label = Text(f"{record['type']} ", style="cyan")
    label.append(str(record["value"]))
    if record.get("hosts"):
        label.append(f" ({', '.join(record['hosts'])})", style="dim")
    if record.get("view") == "internal":
        label.append(" · internal view", style="dim")
    elif record.get("internal"):
        label.append(" · internal address", style="yellow")
    if record.get("scope") == "out" and not record.get("internal"):
        label.append(" · outside the scope", style="yellow")
    if record.get("status") not in (None, "active"):
        label.append(f" · {record['status']}", style="yellow")
    branch = parent.add(label)
    for cloud in record.get("cloud") or []:
        text = Text(f"cloud {cloud.get('kind') or 'asset'} ", style="dim")
        text.append(str(cloud.get("name")))
        if cloud.get("public"):
            text.append(" · public", style="yellow")
        branch.add(text)
    for service in record.get("services") or []:
        branch.add(_service_label(service))
    for cert in record.get("certificates") or []:
        branch.add(_certificate_label(cert))


def _domain_label(node: dict[str, Any]) -> Text:
    text = Text(str(node["name"]), style="bold")
    details: list[str] = []
    if node["scope"] == "out":
        details.append("OUTSIDE SCOPE")
    if node["owners"]:
        details.append(", ".join(node["owners"]))
    elif node["claimed_owners"]:
        details.append("claimed by " + ", ".join(node["claimed_owners"]))
    elif node["scope"] == "in" and node["inventoried"]:
        details.append("no owner")
    if not node["inventoried"]:
        details.append("not in inventory")
    if node["status"] != "active":
        details.append(node["status"])
    if details:
        text.append("  [" + " · ".join(details) + "]", style="yellow" if node["scope"] == "out" else "dim")
    if node.get("findings"):
        text.append(f"  {node['findings']} finding(s)", style="yellow")
    return text


def _domain_tree(parent: Tree, node: dict[str, Any]) -> None:
    branch = parent.add(_domain_label(node))
    for record in node["records"]:
        _record_branch(branch, record)
    for value in node.get("txt") or []:
        branch.add(Text("TXT ", style="cyan") + Text(str(value), style="dim"))
    for child in node["children"]:
        _domain_tree(branch, child)


def render_summary(summary: SurfaceSummary) -> None:
    rt.header(f"R$F SURFACE  {summary.workspace}", "Authorized external attack surface (from imported data only)")
    scope: Any = (
        f"{len(summary.scope)} entries: " + ", ".join(e.target for e in summary.scope[:6])
        if summary.scope_configured
        else Text("not configured", style="yellow")
    )
    rt.kv_block(
        [
            ("Scope", scope),
            (
                "Assets",
                f"{summary.assets}"
                + (": " + ", ".join(f"{k} {v}" for k, v in summary.by_kind.items()) if summary.by_kind else ""),
            ),
            (
                "In scope",
                f"{summary.in_scope}"
                + (f" ({summary.out_of_scope} outside the scope)" if summary.scope_configured else ""),
            ),
            ("Internet-facing", summary.internet_facing),
            ("Owners", ", ".join(summary.owners) or "-"),
            ("References", f"{summary.references} (names and addresses seen only in DNS answers or certificates)"),
            ("Findings", f"{summary.findings_open} open ({_severity_counts(summary.findings_by_severity)})"),
            ("Reference time", f"{rt.ts_text(summary.reference_time)} ({summary.reference_source})"),
        ],
        width=17,
    )
    for note in summary.notes:
        rt.note(note)
    c = rt.console()
    if summary.tree:
        tree = Tree(Text("Domains", style="bold"), guide_style="dim")
        for node in summary.tree:
            _domain_tree(tree, node)
        c.print()
        c.print(tree)
    if summary.addresses:
        c.print()
        rt.table(
            ["ADDRESS", "SCOPE", "OWNER", "DETAILS"],
            [
                (
                    a.get("name"),
                    _scope_text(str(a.get("scope"))),
                    ", ".join(a.get("owners") or []) or "-",
                    a.get("summary"),
                )
                for a in summary.addresses
            ],
            title="Addresses without a DNS name",
        )
    if summary.cloud:
        c.print()
        rt.table(
            ["CLOUD ASSET", "SCOPE", "OWNER", "DETAILS"],
            [
                (
                    a.get("name"),
                    _scope_text(str(a.get("scope"))),
                    ", ".join(a.get("owners") or []) or "-",
                    a.get("summary"),
                )
                for a in summary.cloud
            ],
            title="Cloud assets",
        )
    if summary.outside:
        c.print()
        rt.table(
            ["ASSET", "KIND", "CLAIMED OWNER", "DETAILS"],
            [
                (a.get("name"), a.get("kind"), ", ".join(a.get("claimed_owners") or []) or "-", a.get("summary"))
                for a in summary.outside
            ],
            title="Outside the authorized scope (recorded, never treated as owned)",
        )
    if summary.top_findings:
        c.print()
        rt.table(
            ["SEVERITY", "FINDING", "RULE"],
            [(rt.sev_text(f["severity"]), f["title"], f["rule"]) for f in summary.top_findings],
            title="Top findings",
        )


def _show(at: str | None, expiring_days: int) -> None:
    ctx = rt.ctx()
    summary = SurfaceService(ctx).summary(at=rt.parse_time_option(at), expiring_days=expiring_days)

    def render() -> None:
        render_summary(summary)
        if not summary.assets:
            rt.next_steps(
                [
                    "raf surface scope add <domain> --owner TEAM --authorization REF",
                    "raf surface import inventory.json",
                    "raf surface sample raven-surface.json",
                ]
            )
        else:
            rt.next_steps(
                ["raf surface analyze", "raf surface assets --out-of-scope", "raf findings --product surface"]
            )

    rt.output("raf.surface.summary/v1", summary.to_json_dict(), render)


# --------------------------------------------------------------------------- commands


@app.callback(invoke_without_command=True)
def surface_cmd(ctx_: typer.Context) -> None:
    if ctx_.invoked_subcommand is not None:
        return
    _show(None, DEFAULT_EXPIRING_DAYS)


@app.command("show", help="Summary of the external surface: counts, scope, the domain tree and top findings.")
def show_cmd(
    at: str | None = typer.Option(None, "--at", help="Reference time for certificate states (default: newest event)."),
    expiring_days: int = typer.Option(DEFAULT_EXPIRING_DAYS, "--expiring-days", min=1, max=3650),
) -> None:
    _show(at, expiring_days)


@scope_app.command("add", help="Add a domain, CIDR range, IP or cloud account (provider:account) to the scope.")
def scope_add_cmd(
    target: str = typer.Argument(..., help="raven.example, 198.51.100.0/28, 198.51.100.20, examplecloud:raven-prod"),
    kind: str | None = typer.Option(None, "--kind", help="domain, cidr, ip or cloud_account (default: inferred)."),
    owner: str | None = typer.Option(None, "--owner", help="Team or person accountable for this scope entry."),
    authorization: str | None = typer.Option(
        None, "--authorization", "--auth", help="Authorization reference, for example a ticket ID."
    ),
    replace: bool = typer.Option(False, "--replace", help="Update the owner/authorization of an existing entry."),
) -> None:
    ctx = rt.ctx()
    entry, result = SurfaceService(ctx).add_scope(target, kind, owner, authorization, replace=replace)

    def render() -> None:
        if result == "unchanged":
            rt.console().print(Text(f"{entry.target} is already in the authorized scope (no change)."))
        else:
            verb = "Updated" if result == "replaced" else "Added"
            rt.success(f"{verb} {entry.kind} {entry.target} in the authorized scope.")
        rt.kv_block(
            [
                ("Owner", entry.owner or "-"),
                ("Authorization", entry.authorization or Text("none recorded", style="yellow")),
                ("Added", rt.ts_text(entry.added_at)),
            ],
            width=15,
        )
        if not entry.authorization:
            rt.warn("no authorization reference was recorded; add one with --authorization REF --replace")
        rt.next_steps(["raf surface scope list", "raf surface import inventory.json", "raf surface analyze"])

    rt.output("raf.surface.scope.entry/v1", {"entry": entry.to_json_dict(), "result": result}, render)


@scope_app.command("list", help="Entries of the authorized scope.")
def scope_list_cmd() -> None:
    ctx = rt.ctx()
    entries = SurfaceService(ctx).scope_entries()
    data = {"items": [e.to_json_dict() for e in entries], "total": len(entries)}
    rt.output("raf.surface.scope/v1", data, lambda: render_scope(entries))


@scope_app.command("remove", help="Remove an entry from the authorized scope (asks for confirmation).")
def scope_remove_cmd(target: str = typer.Argument(..., help="The entry's target, as listed by scope list.")) -> None:
    ctx = rt.ctx()
    service = SurfaceService(ctx)
    entry = service.scope_entry(target)
    rt.confirm(
        f"Remove {entry.target} from the authorized scope?",
        [entry.describe(), "Assets covered only by this entry are treated as out of scope from the next analysis."],
    )
    removed = service.remove_scope(entry.target)

    def render() -> None:
        rt.success(f"Removed {removed.kind} {removed.target} from the authorized scope.")
        rt.next_steps(["raf surface analyze", "raf surface scope list"])

    rt.output("raf.surface.scope.entry/v1", {"entry": removed.to_json_dict(), "result": "removed"}, render)


@app.command("import", help="Import a surface inventory (raf-surface/1 JSON or YAML, JSON Lines, CSV).")
def import_cmd(
    path: Path = typer.Argument(..., help="Inventory file (at most 20 MB)."),
    apply_scope: bool = typer.Option(
        False, "--apply-scope", help="Also add the file's 'scope' entries to the authorized scope (review them first)."
    ),
    format_: str | None = typer.Option(None, "--format", "-f", help="json, jsonl, yaml or csv (default: detected)."),
    source_name: str | None = typer.Option(None, "--source-name", help="Provenance name for the source."),
) -> None:
    ctx = rt.ctx()
    result = SurfaceService(ctx).import_file(path, fmt=format_, apply_scope=apply_scope, source_name=source_name)

    def render() -> None:
        render_import(result)
        steps = ["raf surface analyze", "raf surface show"]
        if result.rejected and result.job_id:
            steps.append(f"raf import report {result.job_id}")
        rt.next_steps(steps)

    rt.output("raf.surface.import/v1", result.to_json_dict(), render)


@app.command("analyze", help="Run the surface rules and record explainable findings.")
def analyze_cmd(
    at: str | None = typer.Option(None, "--at", help="Reference time (default: newest event, else now)."),
    expiring_days: int = typer.Option(
        DEFAULT_EXPIRING_DAYS, "--expiring-days", min=1, max=3650, help="Certificates expiring within N days."
    ),
    no_save: bool = typer.Option(False, "--no-save", help="Do not record findings."),
    limit: int = typer.Option(25, "--limit", min=1, help="Findings shown."),
) -> None:
    ctx = rt.ctx()
    analysis = SurfaceService(ctx).analyze(
        at=rt.parse_time_option(at), expiring_days=expiring_days, persist=not no_save
    )

    def render() -> None:
        render_analysis(analysis, limit)
        steps = [f"raf finding show {analysis.findings[0].id}"] if analysis.findings else []
        rt.next_steps([*steps, "raf surface show", "raf findings --product surface"])

    rt.output("raf.surface.analysis/v1", analysis.to_json_dict(), render)


@app.command("assets", help="Assets of the surface with scope, ownership and details.")
def assets_cmd(
    kind: str | None = typer.Option(None, "--kind", "-k", help="domain, ip, service, certificate or cloud_asset."),
    out_of_scope: bool = typer.Option(False, "--out-of-scope", help="Only assets outside the authorized scope."),
    in_scope: bool = typer.Option(False, "--in-scope", help="Only assets inside the authorized scope."),
    include_references: bool = typer.Option(
        False, "--all", help="Include references (names/addresses seen only in DNS answers or certificates)."
    ),
    limit: int = typer.Option(200, "--limit", min=1),
) -> None:
    if out_of_scope and in_scope:
        raise InvalidInputError("Use either --in-scope or --out-of-scope.")
    ctx = rt.ctx()
    scope = "out" if out_of_scope else "in" if in_scope else "all"
    items, total = SurfaceService(ctx).assets(
        kind=kind, scope=scope, include_references=include_references, limit=limit
    )

    def render() -> None:
        if not items:
            rt.console().print(Text("No surface assets match."))
            rt.next_steps(["raf surface import inventory.json", "raf surface show"])
            return
        rt.table(
            ["KIND", "NAME", "SCOPE", "OWNER", "DETAILS", "FINDINGS"],
            [
                (
                    a.kind + ("" if a.asset else " (ref)"),
                    a.name,
                    _scope_text(a.scope, a.scope_entry),
                    _owner_text(a),
                    a.summary,
                    Text(str(a.findings), style="yellow") if a.findings else "",
                )
                for a in items
            ],
        )
        if total > len(items):
            rt.note(f"{total - len(items)} more; use --limit")

    data = {"items": [a.to_json_dict() for a in items], "total": total, "limit": limit, "offset": 0}
    rt.output("raf.surface.assets/v1", data, render)


@app.command("findings", help="Surface findings (open by default).")
def findings_cmd(
    rule: str | None = typer.Option(None, "--rule", help="Only this rule."),
    min_severity: str | None = typer.Option(None, "--min-severity", help="low, medium, high or critical."),
    status: str = typer.Option("open", "--status", help="open, resolved, acknowledged, false_positive ... or all."),
    limit: int = typer.Option(50, "--limit", min=1),
) -> None:
    ctx = rt.ctx()
    items, total = SurfaceService(ctx).findings(rule=rule, min_severity=min_severity, status=status, limit=limit)

    def render() -> None:
        if not items:
            rt.console().print(Text("No surface findings match."))
            rt.next_steps(["raf surface analyze"])
            return
        render_findings_table(items, limit)
        rt.next_steps([f"raf finding show {items[0].id}"])

    data = {"items": [f.to_json_dict() for f in items], "total": total}
    rt.output("raf.surface.findings/v1", data, render)


@app.command("sample", help="Write the Raven Industries sample inventory (synthetic) to a file.")
def sample_cmd(output: Path = typer.Argument(..., help="Destination file (JSON).")) -> None:
    target = output.expanduser()
    if target.exists():
        if not target.is_file():
            raise InvalidInputError(f"{target} exists and is not a regular file.")
        rt.confirm(f"Overwrite {target}?", ["The file is replaced by the Raven sample inventory."])
    data = SurfaceService.write_sample(target)

    def render() -> None:
        rt.success(f"Wrote the Raven sample inventory to {data['path']} ({data['bytes']:,} bytes).")
        rt.next_steps([f"raf surface import {target} --apply-scope", "raf surface analyze"])

    rt.output("raf.surface.sample/v1", data, render)
