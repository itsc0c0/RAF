"""``raf policy``: normalize, analyze, evaluate and compare policies."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.text import Text

from raf.core.errors import InvalidInputError
from raf.products.policy.engine import PolicyAnalysis, PolicyDiff
from raf.products.policy.model import Policy
from raf.products.policy.service import Evaluation, PolicyService, resolve_endpoint
from raf.sdk import cli as rt

app = typer.Typer(
    add_completion=False,
    help="""Policy analysis (network/firewall rules and access policies).

  raf policy check policies.json        normalize and analyze a file (nothing is stored)
  raf policy check edge.rules --host VPN-01   the same for an iptables-save rule set
  raf policy import policies.json       store policies in the workspace graph
  raf policy analyze                    analyze stored policies and record findings
  raf policy can USER-17 access DB-01   evaluate a hypothetical flow / access with the decision chain
  raf policy diff old.json current      compare policy revisions (files, current, snapshots)""",
)

_DECISION_STYLE = {"allow": "bold green", "deny": "bold red", "not-evaluated": "yellow"}
_IMPACT_STYLE = {"access-expanded": "red", "access-reduced": "green", "changed": "yellow"}


def render_analysis(analysis: PolicyAnalysis, title: str, limit: int) -> None:
    rt.header(title)
    c = rt.console()
    if analysis.policies:
        rt.table(
            ["POLICY", "DOMAIN", "EVALUATION", "DEFAULT", "RULES", "REVISION", "FINDINGS"],
            [
                (p["name"], p["domain"], p["evaluation"], p["default"], p["rules"], p["revision"] or "", p["findings"])
                for p in analysis.policies
            ],
        )
    if not analysis.workspace_aware:
        rt.note(
            "The workspace has no inventory: zone/host references could not be interpreted, so coverage "
            "between named objects is exact-match only."
        )
    for warning in analysis.warnings:
        rt.warn(warning)
    c.print()
    if not analysis.findings:
        c.print("No policy issues found.")
        return
    rt.table(
        ["SEVERITY", "FINDING", "RULE"],
        [(rt.sev_text(f.severity), f.title, f.rule_id) for f in analysis.findings[:limit]],
    )
    if len(analysis.findings) > limit:
        rt.note(f"{len(analysis.findings) - limit} more; use --limit")
    c.print()
    c.print(Text("Details", style="bold"))
    for f in analysis.findings[:limit]:
        c.print(
            Text(f"  {f.severity.value:<8} ", style="red" if f.severity.rank >= 3 else "yellow") + Text(f.description)
        )


def render_policy(policy: Policy) -> None:
    rt.header(f"R$F POLICY  {policy.name}", policy.object_id)
    rt.kv_block(
        [
            ("Domain", policy.domain),
            ("Evaluation", policy.evaluation),
            ("Default", policy.default),
            ("Revision", policy.revision or "-"),
            ("Source", policy.source or "-"),
            ("Digest", policy.digest()),
        ]
        + ([("Scope", ", ".join(policy.scope))] if policy.scope else []),
        width=12,
    )
    if policy.description:
        rt.console().print()
        rt.console().print(Text(policy.description))
    rt.console().print()
    if policy.domain == "network":
        rt.table(
            ["#", "RULE", "EFFECT", "SOURCE", "DESTINATION", "PORTS", "DESCRIPTION"],
            [
                (
                    r.order + 1,
                    r.id + ("" if r.enabled else " (disabled)"),
                    r.effect,
                    ", ".join(r.sources),
                    ", ".join(r.destinations),
                    ", ".join(r.ports),
                    r.description,
                )
                for r in policy.rules
            ],
        )
    else:
        rt.table(
            ["STATEMENT", "EFFECT", "PRINCIPALS", "ACTIONS", "RESOURCES"],
            [
                (
                    r.id + ("" if r.enabled else " (disabled)"),
                    r.effect,
                    ", ".join(r.sources),
                    ", ".join(r.actions),
                    ", ".join(r.destinations),
                )
                for r in policy.rules
            ],
        )


def render_evaluation(result: Evaluation) -> None:
    rt.header(f"R$F POLICY  can {result.subject['name']} {result.verb} {result.target['name']}?")
    c = rt.console()
    rt.kv_block(
        [
            ("Decision", Text(result.decision.upper(), style=_DECISION_STYLE.get(result.decision, ""))),
            ("Subject", f"{result.subject['name']}  ({result.subject['id']})"),
            ("Target", f"{result.target['name']}  ({result.target['id']})"),
            ("Ports", ", ".join(result.requested_ports) or "-"),
            ("Action", result.action or "any"),
        ]
        + ([("From", ", ".join(result.network_sources))] if result.network_sources else []),
        width=10,
    )
    c.print()
    c.print(Text(result.reason, style="dim"))
    for part in result.parts:
        c.print()
        c.print(
            Text(f"{part.part.upper()}  ", style="bold")
            + Text(part.decision.upper(), style=_DECISION_STYLE.get(part.decision, ""))
            + Text(
                f"  {part.policy}"
                + (
                    f"  allowed: {', '.join(part.allowed_ports)}"
                    if part.part == "network" and part.allowed_ports
                    else ""
                ),
                style="dim",
            )
        )
        for i, line in enumerate(part.explanation, 1):
            c.print(Text(f"  {i}. {line}"))
    if result.indirect:
        c.print()
        c.print(Text("Indirect paths", style="bold yellow"))
        for path in result.indirect:
            c.print(Text(f"  • {path.summary}"))
    for message in result.notes:
        rt.note(message)


def render_diff(diff: PolicyDiff) -> None:
    rt.header(f"R$F POLICY DIFF  {diff.before} → {diff.after}")
    rt.kv_block(
        [
            ("Changes", len(diff.changes)),
            ("Access expanded", diff.expanded),
            ("New findings", len(diff.findings_introduced)),
            ("Resolved", len(diff.findings_resolved)),
        ],
        width=16,
    )
    c = rt.console()
    if diff.policies_added or diff.policies_removed:
        c.print()
        if diff.policies_added:
            c.print(Text("  + policies: " + ", ".join(diff.policies_added), style="green"))
        if diff.policies_removed:
            c.print(Text("  - policies: " + ", ".join(diff.policies_removed), style="red"))
    for change in diff.defaults_changed:
        c.print(Text(f"  ! {change['policy']} default {change['before']} → {change['after']}", style="bold red"))
    if diff.changes:
        c.print()
        rt.table(
            ["POLICY", "RULE", "CHANGE", "IMPACT", "DETAIL"],
            [
                (
                    ch.policy,
                    ch.rule,
                    ch.change,
                    Text(ch.impact, style=_IMPACT_STYLE.get(ch.impact, "")),
                    "; ".join(f"{k}: {v['before']} → {v['after']}" for k, v in ch.fields.items())
                    or (ch.after or ch.before or ""),
                )
                for ch in diff.changes
            ],
        )
    if diff.findings_introduced:
        c.print()
        c.print(Text("Introduced by this revision", style="bold red"))
        for f in diff.findings_introduced:
            c.print(Text(f"  + {f.severity.value:<8} {f.title}"))
    if diff.findings_resolved:
        c.print()
        c.print(Text("Resolved by this revision", style="bold green"))
        for f in diff.findings_resolved:
            c.print(Text(f"  - {f.severity.value:<8} {f.title}"))
    if not diff.changes and not diff.policies_added and not diff.policies_removed:
        c.print()
        c.print("No policy changes.")


_HOST_HELP = "iptables-save: the host the rules belong to (default: the file name without suffix)."


@app.command("check", help="Normalize and analyze policy file(s) without storing anything.")
def check_cmd(
    path: Path = typer.Argument(
        ..., help="Policy file or directory (.json, .yaml, .yml, .csv, or iptables-save: .rules, .iptables, .v4, .v6)."
    ),
    principal: str | None = typer.Option(None, "--principal", help="Principal for AWS-style policies without one."),
    host: str | None = typer.Option(None, "--host", help=_HOST_HELP),
    limit: int = typer.Option(40, "--limit", min=1),
) -> None:
    ctx = rt.ctx()
    sets, analysis = PolicyService(ctx).check(path, principal=principal, host=host)
    data = {"sets": [s.to_json_dict() for s in sets], "analysis": analysis.to_json_dict()}

    def render() -> None:
        formats = ", ".join(sorted({s.format for s in sets}))
        render_analysis(analysis, f"R$F POLICY CHECK  {path.name}  ({formats})", limit)
        rt.next_steps([f"raf policy import {path}", "raf policy can <subject> access <target>"])

    rt.output("raf.policy.check/v1", data, render)


@app.command("import", help="Import policy file(s) into the workspace graph.")
def import_cmd(
    path: Path = typer.Argument(..., help="Policy file or directory."),
    principal: str | None = typer.Option(None, "--principal", help="Principal for AWS-style policies without one."),
    host: str | None = typer.Option(None, "--host", help=_HOST_HELP),
) -> None:
    ctx = rt.ctx()
    result = PolicyService(ctx).import_path(path, principal=principal, host=host)

    def render() -> None:
        rt.success(f"Imported {len(result.policies)} polic{'y' if len(result.policies) == 1 else 'ies'} ({result.job})")
        rt.table(
            ["POLICY", "ID", "DOMAIN", "RULES", "REVISION"],
            [(p["name"], p["object_id"], p["domain"], p["rules"], p["revision"] or "") for p in result.policies],
        )
        for warning in result.warnings:
            rt.warn(warning)
        rt.next_steps(["raf policy analyze", f"raf policy show {result.policies[0]['id']}"])

    rt.output("raf.policy.import/v1", result.to_json_dict(), render)


@app.command("list", help="Policies stored in the workspace.")
def list_cmd() -> None:
    ctx = rt.ctx()
    policies = PolicyService(ctx).stored()
    data = {
        "policies": [
            {
                "id": p.id,
                "object_id": p.object_id,
                "name": p.name,
                "domain": p.domain,
                "evaluation": p.evaluation,
                "default": p.default,
                "rules": len(p.rules),
                "revision": p.revision,
                "digest": p.digest(),
            }
            for p in policies
        ]
    }

    def render() -> None:
        if not policies:
            rt.console().print("No policies imported.")
            rt.next_steps(["raf policy import fixtures/policies/raven-policies.json"])
            return
        rt.table(
            ["POLICY", "ID", "DOMAIN", "DEFAULT", "RULES", "REVISION"],
            [(p.name, p.id, p.domain, p.default, len(p.rules), p.revision or "") for p in policies],
        )

    rt.output("raf.policy.list/v1", data, render)


@app.command("show", help="Show a stored policy with its normalized rules.")
def show_cmd(policy: str = typer.Argument(..., help="Policy id or name (raven-fw).")) -> None:
    ctx = rt.ctx()
    found = PolicyService(ctx).get(policy)
    rt.output("raf.policy/v1", found.to_json_dict(), lambda: render_policy(found))


@app.command("analyze", help="Analyze stored policies (or a path) and record findings.")
def analyze_cmd(
    path: Path | None = typer.Argument(None, help="Optional policy file/directory; default: stored policies."),
    no_save: bool = typer.Option(False, "--no-save", help="Do not record findings."),
    limit: int = typer.Option(40, "--limit", min=1),
) -> None:
    ctx = rt.ctx()
    service = PolicyService(ctx)
    if path is not None:
        sets, analysis = service.check(path)
        if not no_save:
            service.import_sets(sets, source_label=path.name)
            analysis = service.analyze()
        title = f"R$F POLICY ANALYSIS  {path.name}"
    else:
        analysis = service.analyze(persist=not no_save)
        title = "R$F POLICY ANALYSIS"

    def render() -> None:
        render_analysis(analysis, title, limit)
        steps = [f"raf finding show {analysis.findings[0].id}"] if analysis.findings else []
        rt.next_steps([*steps, "raf policy can <subject> access <target>"])

    rt.output("raf.policy.analysis/v1", analysis.to_json_dict(), render)


@app.command(
    "can",
    help="""Evaluate whether SUBJECT can VERB TARGET and show the policy chain.

VERB: access (any), reach/connect (network only), ssh, rdp, https, postgres, or an access-policy
action such as admin, deploy:release, read, write.

  raf policy can alice access DB-01
  raf policy can DEV-01 reach DB-01 --port tcp/5432
  raf policy can frank admin production""",
)
def can_cmd(
    subject: str = typer.Argument(..., help="User, identity, group, role, host, IP or network."),
    verb: str = typer.Argument(..., help="access, reach, ssh, admin, deploy:release ..."),
    target: str = typer.Argument(..., help="Host, service, network or resource."),
    port: list[str] = typer.Option(None, "--port", "-p", help="Port(s) such as tcp/5432 (repeatable)."),
    source: list[str] = typer.Option(None, "--from", help="Source host(s) for the network check (repeatable)."),
) -> None:
    ctx = rt.ctx()
    subject_id, target_id = resolve_endpoint(ctx, subject), resolve_endpoint(ctx, target)
    sources = [resolve_endpoint(ctx, s) for s in source] if source else None
    if subject_id == target_id:
        raise InvalidInputError("Subject and target are the same object.")
    result = PolicyService(ctx).evaluate(subject_id, verb, target_id, ports=list(port or []), source_hosts=sources)
    ctx.audit.record(
        "policy.evaluate", affected=[subject_id, target_id], details={"verb": result.verb, "decision": result.decision}
    )

    def render() -> None:
        render_evaluation(result)
        principal = subject_id.split(":", 1)[0] in ("user", "identity", "group", "role")
        rt.next_steps(
            [
                f"raf iam path {subject_id} {target_id}" if principal else f"raf graph path {subject_id} {target_id}",
                f"raf blast {subject_id}",
                "raf policy analyze",
            ]
        )

    rt.output("raf.policy.evaluation/v1", result.to_json_dict(), render)


@app.command("diff", help="Compare two policy revisions: files/directories, 'current' or snapshot names.")
def diff_cmd(
    before: str = typer.Argument(..., help="Older revision (file, current, snapshot)."),
    after: str = typer.Argument("current", help="Newer revision (default: current workspace)."),
) -> None:
    ctx = rt.ctx()
    diff = PolicyService(ctx).diff(before, after)
    rt.output("raf.policy.diff/v1", diff.to_json_dict() | {"access_expanded": diff.expanded}, lambda: render_diff(diff))
