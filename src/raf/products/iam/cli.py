"""``raf iam``: identity and access analysis."""

from __future__ import annotations

import typer
from rich.text import Text

from raf.core.errors import InvalidInputError
from raf.core.objects.types import Severity
from raf.products.iam.service import RULES, AccessPath, EffectiveAccess, IamReport, IamService
from raf.sdk import cli as rt

app = typer.Typer(
    add_completion=False,
    help="""Identity and access analysis (read-only).

  raf iam analyze                 run all IAM analyzers and record findings
  raf iam show sarah              effective access of a principal (groups, roles, resources)
  raf iam path alice production   how a principal could obtain control of a resource""",
)


def render_report(report: IamReport, limit: int) -> None:
    rt.header("R$F IAM ANALYSIS")
    rt.kv_block(
        [
            ("Principals", report.principals),
            ("Privileged", report.privileged_principals),
            ("Findings", len(report.findings)),
            ("Auto-resolved", report.resolved),
            ("Reference time", rt.ts_text(report.reference_time) if report.reference_time else "no events"),
        ],
        width=16,
    )
    c = rt.console()
    if report.by_rule:
        c.print()
        rt.table(
            ["RULE", "FINDINGS"], [(rule, report.by_rule.get(rule, 0)) for rule in RULES if report.by_rule.get(rule)]
        )
    if report.findings:
        c.print()
        rt.table(
            ["SEVERITY", "FINDING", "RULE", "CONFIDENCE"],
            [
                (rt.sev_text(f.severity), f.title, f.rule_id, rt.conf_text(f.confidence))
                for f in report.findings[:limit]
            ],
        )
        if len(report.findings) > limit:
            rt.note(f"{len(report.findings) - limit} more; use --limit or raf findings --product iam")
    else:
        c.print()
        c.print("No IAM findings.")


def render_access(access: EffectiveAccess, limit: int) -> None:
    p = access.principal
    rt.header(f"R$F IAM  {p['name']}", p["id"])
    meta = p.get("metadata") or {}
    rows: list[tuple[str, object]] = [
        ("Type", p["type"]),
        ("Privileged", Text("yes", style="bold red") if access.privileged else "no"),
        ("Last activity", rt.ts_text(access.last_activity) if access.last_activity else "none recorded"),
    ]
    if "mfa" in meta:
        rows.append(("MFA", "enabled" if meta.get("mfa") else Text("disabled", style="yellow")))
    if meta.get("disabled"):
        rows.append(("Status", Text("disabled", style="yellow")))
    rt.kv_block(rows, width=14)
    c = rt.console()
    if access.groups:
        c.print()
        rt.table(
            ["GROUP", "MEMBERSHIP CHAIN", "NESTED"],
            [(g["name"], " → ".join(g["chain"]), "yes" if g["nested"] else "") for g in access.groups],
        )
    if access.roles:
        c.print()
        rt.table(
            ["ROLE", "PRIVILEGED", "WILDCARD", "VIA"],
            [
                (r["name"], "yes" if r["privileged"] else "", "yes" if r["wildcard"] else "", " → ".join(r["chain"]))
                for r in access.roles
            ],
        )
    if access.identities:
        c.print()
        rt.table(["IDENTITY", "PRIVILEGED"], [(i["name"], "yes" if i["privileged"] else "") for i in access.identities])
    if access.resources:
        c.print()
        rt.table(
            ["RESOURCE", "TYPE", "CRITICALITY", "ADMIN", "CONFIDENCE", "VIA"],
            [
                (
                    r["name"],
                    r["type"],
                    r["criticality"] or "",
                    "yes" if r["admin"] else "",
                    f"{r['confidence']:.2f}",
                    r["via"],
                )
                for r in access.resources[:limit]
            ],
        )
        if len(access.resources) > limit:
            rt.note(f"{len(access.resources) - limit} more resources; use --limit")
    if access.findings:
        c.print()
        rt.table(["SEVERITY", "FINDING", "ID"], [(rt.sev_text(f.severity), f.title, f.id) for f in access.findings])


def render_paths(paths: list[AccessPath], source: str, target: str) -> None:
    rt.header(f"R$F IAM PATH  {source} → {target}")
    c = rt.console()
    if not paths:
        c.print(
            "No privilege path found (within the configured depth). Network-only reachability is not a "
            "privilege path; try raf blast for the combined view."
        )
        return
    for index, path in enumerate(paths, 1):
        c.print()
        title = "Best path" if index == 1 else f"Alternative {index - 1}"
        c.print(
            Text(f"{title}  ", style="bold")
            + Text(f"confidence {path.confidence:.2f}, {len(path.hops)} hop(s)", style="dim")
        )
        c.print()
        steps: list[tuple[str, str, str | None]] = []
        for hop in path.hops:
            label = hop.relationship_type if hop.forward else f"{hop.relationship_type} (reverse)"
            steps.append((hop.source_name, "", label))
        steps.append((path.target_name, path.target, None))
        rt.render_chain(steps)
        c.print()
        for i, hop in enumerate(path.hops, 1):
            c.print(Text(f"  {i}. {hop.why}", style="dim"))


@app.command("analyze", help="Run all IAM analyzers over the workspace and record findings.")
def analyze_cmd(
    no_save: bool = typer.Option(False, "--no-save", help="Do not record findings (dry run)."),
    min_severity: str | None = typer.Option(None, "--min-severity", help="Only show findings at or above."),
    limit: int = typer.Option(30, "--limit", min=1),
) -> None:
    ctx = rt.ctx()
    threshold = None
    if min_severity:
        try:
            threshold = Severity(min_severity.upper())
        except ValueError as exc:
            raise InvalidInputError(
                f"Unknown severity '{min_severity}'.", hint="Use info, low, medium, high or critical."
            ) from exc
    report = IamService(ctx).analyze(persist=not no_save)
    if threshold is not None:
        report.findings = [f for f in report.findings if f.severity.rank >= threshold.rank]
    if not no_save:
        ctx.audit.record(
            "iam.analyze",
            affected=[f.id for f in report.findings[:50]],
            details={"findings": len(report.findings), "resolved": report.resolved},
        )

    def render() -> None:
        render_report(report, limit)
        steps = []
        if report.findings:
            steps.append(f"raf finding show {report.findings[0].id}")
        steps += ["raf iam show <principal>", "raf iam path <principal> <resource>"]
        rt.next_steps(steps)

    rt.output("raf.iam.analysis/v1", report.to_json_dict(), render)


@app.command("show", help="Effective access of a principal: groups, roles, identities and resources.")
def show_cmd(
    ref: str = typer.Argument(..., help="User or identity (alice, svc-deploy, @last)."),
    limit: int = typer.Option(40, "--limit", min=1),
) -> None:
    ctx = rt.ctx()
    resolved = ctx.resolve(ref)
    for message in resolved.notes:
        rt.note(message)
    ctx.refs.remember("object", resolved.id)
    access = IamService(ctx).effective_access(resolved.id, findings=True)

    def render() -> None:
        render_access(access, limit)
        rt.next_steps([f"raf blast {resolved.id}", f"raf graph {resolved.id}"])

    rt.output("raf.iam.access/v1", access.to_json_dict(), render)


@app.command("path", help="Privilege paths from a principal (or any object) to control of a target.")
def path_cmd(
    source: str = typer.Argument(..., help="Starting point (alice, WS-04)."),
    target: str = typer.Argument(..., help="Resource to control (production, DB-01)."),
    max_depth: int = typer.Option(10, "--max-depth", min=1, max=16),
    alternatives: int = typer.Option(3, "--paths", min=1, max=10, help="Maximum number of paths."),
) -> None:
    ctx = rt.ctx()
    a, b = ctx.resolve(source), ctx.resolve(target)
    for message in [*a.notes, *b.notes]:
        rt.note(message)
    paths = IamService(ctx).paths(a.id, b.id, max_depth=max_depth, limit=alternatives)
    data = {"source": a.id, "target": b.id, "paths": [p.to_json_dict() for p in paths]}

    def render() -> None:
        render_paths(paths, a.label, b.label)
        if paths:
            rt.next_steps([f"raf blast {a.id}", f"raf ghost clone current fix-{b.id.split(':', 1)[-1]}"])

    rt.output("raf.iam.paths/v1", data, render)
