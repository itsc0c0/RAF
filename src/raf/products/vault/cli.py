"""``raf vault``: find exposed secrets in files and repositories (values are never shown or stored)."""

from __future__ import annotations

import shlex
from collections import Counter
from pathlib import Path

import typer
from rich.text import Text

from raf.core.objects.types import Severity
from raf.products.vault.service import (
    ScanResult,
    SecretResult,
    VaultService,
    finding_location,
)
from raf.sdk import cli as rt

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="""R$F Vault: defensive secret hygiene.

Values are never printed, stored or logged: results show a redacted value
(sk-****91a2) and a keyed fingerprint used for deduplication and allowlists.

Examples:
  raf vault scan ./repo
  raf vault scan /opt/app --host DEV-01 --allowlist vault-allow.yaml
  raf vault allowlist add 3f9a0c51d2e8b7a4 --reason "revoked test key"
  raf vault findings""",
)
allowlist_app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Workspace allowlist (<workspace>/vault-allowlist.yaml): accepted fingerprints, rules or paths.",
)
app.add_typer(allowlist_app, name="allowlist")

_SEVERITY_ORDER = [s.value for s in sorted(Severity, key=lambda s: -s.rank)]


def _quote(ref: str) -> str:
    return shlex.quote(ref)


def _result_rows(results: list[SecretResult], *, reason: bool = False) -> list[list[object]]:
    rows: list[list[object]] = []
    for r in sorted(results, key=lambda x: (-x.severity.rank, x.path, x.line)):
        row: list[object] = [
            rt.sev_text(r.severity),
            rt.conf_text(r.confidence),
            r.rule,
            f"{r.path}:{r.line}",
            r.redacted,
            r.fingerprint[:16],
        ]
        if reason:
            row.append(r.suppressed_by or "")
        rows.append(row)
    return rows


def _stored_text(result: ScanResult) -> str:
    if not result.stored:
        return "no (--no-store)"
    f = result.findings
    text = f"{f.get('created', 0)} new, {f.get('updated', 0)} updated, {f.get('resolved', 0)} resolved"
    if f.get("suppressed"):
        text += f", {f['suppressed']} suppressed"
    return text + (f"  ({result.job_id})" if result.job_id else "")


def render_scan(result: ScanResult) -> None:
    rt.header(f"R$F VAULT SCAN  {result.root}")
    files = f"{result.files_scanned:,} scanned"
    if result.files_skipped:
        reasons = Counter(s.reason.split(" (")[0] for s in result.skipped)
        files += f", {result.files_skipped:,} skipped (" + ", ".join(f"{k} {v}" for k, v in reasons.items()) + ")"
    secrets = f"{len(result.results)} in {result.files_with_secrets} file(s), {result.distinct_secrets} distinct"
    if result.suppressed_count:
        secrets += f", {result.suppressed_count} suppressed"
    severity = " · ".join(f"{s} {result.by_severity[s]}" for s in _SEVERITY_ORDER if result.by_severity.get(s))
    rt.kv_block(
        [
            ("Host", result.host),
            ("Files", files),
            ("Secrets", secrets),
            ("Severity", severity or "-"),
            ("Stored", _stored_text(result)),
        ],
        width=10,
    )
    if result.truncated:
        rt.warn("file limit reached; scan a narrower directory for complete results")
    c = rt.console()
    if result.results:
        c.print()
        rt.table(["SEV", "CONFIDENCE", "RULE", "LOCATION", "VALUE", "FINGERPRINT"], _result_rows(result.results))
    else:
        c.print()
        c.print("No secrets found." if not result.suppressed_count else "No unsuppressed secrets found.")
    if result.suppressed:
        c.print()
        rt.table(
            ["SEV", "CONFIDENCE", "RULE", "LOCATION", "VALUE", "FINGERPRINT", "SUPPRESSED BY"],
            _result_rows(result.suppressed, reason=True),
            title="Suppressed",
        )
    elif result.suppressed_count:
        c.print(Text(f"{result.suppressed_count} suppressed result(s) hidden (--show-suppressed)", style="dim"))


def _next_steps(result: ScanResult) -> list[str]:
    if not result.results:
        return ["raf vault rules"] if not result.suppressed_count else []
    steps = ["raf vault findings"] if result.stored else [f"raf vault scan {_quote(result.root)}  (store results)"]
    first = sorted(result.results, key=lambda r: (-r.severity.rank, r.path, r.line))[0]
    if result.stored and first.file_id:
        steps.append(f"raf graph {_quote(first.file_id)}")
    steps.append(f'raf vault allowlist add {first.fingerprint[:16]} --reason "why this value is acceptable"')
    return steps


@app.command("scan")
def scan_cmd(
    path: Path = typer.Argument(..., help="File or directory to scan (symlinks are not followed)."),
    allowlist: Path | None = typer.Option(None, "--allowlist", help="Extra allowlist file (YAML or JSON)."),
    host: str = typer.Option("local", "--host", help="Host the files live on (links findings to that host)."),
    no_store: bool = typer.Option(False, "--no-store", help="Report only; do not save objects or findings."),
    show_suppressed: bool = typer.Option(False, "--show-suppressed", help="List allowlisted/inline-suppressed hits."),
) -> None:
    """Scan a file or directory for exposed secrets."""
    ctx = rt.ctx()
    result = VaultService(ctx).scan(
        path, allowlist=allowlist, host=host, store=not no_store, show_suppressed=show_suppressed
    )
    if result.stored and result.results:
        first = sorted(result.results, key=lambda r: (-r.severity.rank, r.path, r.line))[0]
        if first.file_id:
            ctx.refs.remember("object", first.file_id)

    def render() -> None:
        render_scan(result)
        rt.next_steps(_next_steps(result))

    rt.output("raf.vault.scan/v1", result.to_json_dict(), render)


@app.command("findings")
def findings_cmd(
    status: str = typer.Option("OPEN", "--status", help="OPEN, ACKNOWLEDGED, RESOLVED, SUPPRESSED, ... or all."),
    severity: str | None = typer.Option(None, "--severity", help="Minimum severity."),
    limit: int = typer.Option(100, "--limit", min=1, max=10000),
) -> None:
    """List stored Vault findings (redacted)."""
    service = VaultService(rt.ctx())
    items, total = service.findings(
        status=status, min_severity=Severity.parse(severity) if severity else None, limit=limit
    )

    def render() -> None:
        rt.header("R$F VAULT FINDINGS", f"{total} {'' if status.lower() == 'all' else status.upper() + ' '}finding(s)")
        if not items:
            rt.console().print("No Vault findings match.")
            rt.next_steps(["raf vault scan <path>"])
            return
        rt.table(
            ["SEV", "CONFIDENCE", "RULE", "LOCATION", "VALUE", "STATUS", "ID"],
            [
                (
                    rt.sev_text(f.severity),
                    rt.conf_text(f.confidence),
                    f.rule_id,
                    finding_location(f),
                    str(f.metadata.get("redacted", "")),
                    f.status.value,
                    f.id,
                )
                for f in items
            ],
        )
        if total > len(items):
            rt.console().print(Text(f"... {total - len(items)} more (use --limit)", style="dim"))
        rt.next_steps([f"raf finding show {items[0].id}", "raf vault secrets"])

    rt.output(
        "raf.vault.findings/v1", {"items": [f.to_json_dict() for f in items], "total": total, "status": status}, render
    )


@app.command("secrets")
def secrets_cmd(
    include_removed: bool = typer.Option(False, "--all", help="Include secrets no longer present."),
    limit: int = typer.Option(100, "--limit", min=1, max=10000),
) -> None:
    """List stored secret objects (redacted values and fingerprints only)."""
    items, total = VaultService(rt.ctx()).secrets(include_removed=include_removed, limit=limit)

    def render() -> None:
        rt.header("R$F VAULT SECRETS", f"{total} secret object(s)")
        if not items:
            rt.console().print("No secrets stored.")
            return
        rt.table(
            ["RULE", "LOCATION", "HOST", "VALUE", "FINGERPRINT", "STATE", "ID"],
            [
                (
                    s["rule"],
                    f"{s['relative_path'] or s['path']}:{s['line']}",
                    s["host"],
                    s["redacted"],
                    str(s["fingerprint"] or "")[:16],
                    "removed" if s["removed"] else "present",
                    s["id"],
                )
                for s in items
            ],
        )

    rt.output("raf.vault.secrets/v1", {"items": items, "total": total}, render)


@app.command("rules")
def rules_cmd() -> None:
    """Detection rules with severity and documented precision."""
    rules = VaultService(rt.ctx()).rules()

    def render() -> None:
        rt.header("R$F VAULT RULES", "Severity = impact if real; confidence = pattern precision (independent).")
        rt.table(
            ["RULE", "SEVERITY", "CONFIDENCE", "PRECISION", "DETECTS"],
            [
                (r["id"], rt.sev_text(str(r["severity"])), r["confidence"], r["precision"], r["description"])
                for r in rules
            ],
        )

    rt.output("raf.vault.rules/v1", {"items": rules}, render)


@allowlist_app.command("add")
def allowlist_add_cmd(
    fingerprint: str | None = typer.Argument(None, help="Fingerprint (or a 12+ character prefix) to accept."),
    reason: str = typer.Option(..., "--reason", help="Why this value is acceptable (required)."),
    rule: str | None = typer.Option(None, "--rule", help="Only for this rule."),
    path_glob: str | None = typer.Option(None, "--path", help="Only for paths matching this glob."),
) -> None:
    """Append an entry to the workspace allowlist."""
    service = VaultService(rt.ctx())
    entry = service.allowlist_add(fingerprint, reason=reason, rule=rule, path_glob=path_glob)
    data = {"path": str(service.allowlist_path()), "entry": entry.to_dict()}
    rt.output(
        "raf.vault.allowlist.add/v1",
        data,
        lambda: rt.success(f"Added to {service.allowlist_path()}: {entry.describe()}"),
    )


@allowlist_app.command("list")
def allowlist_list_cmd() -> None:
    """Show the workspace allowlist."""
    service = VaultService(rt.ctx())
    entries = service.allowlist_entries()

    def render() -> None:
        rt.header("R$F VAULT ALLOWLIST", str(service.allowlist_path()))
        if not entries:
            rt.console().print("The workspace allowlist is empty.")
            return
        rt.table(
            ["FINGERPRINT", "RULE", "PATH", "REASON"],
            [(e.fingerprint or "*", e.rule or "*", e.path or "*", e.reason) for e in entries],
        )

    rt.output(
        "raf.vault.allowlist/v1",
        {"path": str(service.allowlist_path()), "items": [e.to_dict() for e in entries]},
        render,
    )
