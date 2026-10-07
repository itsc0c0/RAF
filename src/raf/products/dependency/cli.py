"""``raf dependency``: dependency inventory, SBOMs and offline advisory checks."""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any

import typer
from rich.text import Text
from rich.tree import Tree

from raf.products.dependency.check import CheckResult, VulnerableItem
from raf.products.dependency.samples import write_sample_project
from raf.products.dependency.service import AdvisoryImportResult, DependencyService, ScanResult
from raf.sdk import cli as rt

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="""R$F Dependency: dependencies, SBOMs and advisories (offline).

Examples:
  raf dependency scan ./repo --name shop
  raf dependency advisories import fixtures/advisories/raven-osv.json
  raf dependency check shop
  raf dependency sbom export shop --output shop.cdx.json
  raf dependency sbom import vendor-sbom.json""",
)
advisories_app = typer.Typer(add_completion=False, no_args_is_help=True, help="Offline OSV advisories.")
sbom_app = typer.Typer(add_completion=False, no_args_is_help=True, help="CycloneDX / SPDX SBOM import and export.")
app.add_typer(advisories_app, name="advisories")
app.add_typer(sbom_app, name="sbom")

_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def _severity_summary(by_severity: dict[str, int]) -> str:
    return " · ".join(f"{s} {by_severity[s]}" for s in _SEVERITY_ORDER if by_severity.get(s)) or "none"


def _vuln_label(ids: list[str]) -> Text:
    return Text(f"  [{', '.join(ids)}]", style="bold red") if ids else Text("")


def _package_branch(branch: Tree, node: dict[str, Any]) -> None:
    for child in node.get("children", []):
        label = Text(f"{child['name']} {child['version']}") + _vuln_label(child.get("vulnerabilities", []))
        _package_branch(branch.add(label), child)


def render_tree(title: str, roots: list[dict[str, Any]]) -> None:
    tree = Tree(Text(title, style="bold"))
    for root in roots:
        label = Text(f"{root['ecosystem']}/{root['name']}", style="bold")
        if root.get("constraint"):
            label.append(f" {root['constraint']}")
        if root.get("scope") and root["scope"] != "runtime":
            label.append(f" ({root['scope']})", style="dim")
        resolved = root.get("resolved", [])
        versions = ", ".join(r["version"] for r in resolved)
        label.append(f" → {versions}" if versions else " → (unresolved)", style="cyan" if versions else "yellow")
        flagged = list(root.get("vulnerabilities", [])) + [v for r in resolved for v in r.get("vulnerabilities", [])]
        branch = tree.add(label + _vuln_label(flagged))
        for package in resolved:
            _package_branch(branch, package)
    rt.console().print(tree)


def _vulnerability_rows(items: list[VulnerableItem]) -> list[list[object]]:
    return [
        [
            rt.sev_text(i.severity),
            rt.conf_text(i.confidence),
            i.advisory,
            f"{i.ecosystem}/{i.package}",
            i.version or f"'{i.constraint or '*'}' (unresolved)",
            ", ".join(i.fixed) or "-",
            i.project,
        ]
        for i in items
    ]


def render_check(result: CheckResult, *, title: bool = True) -> None:
    if title:
        rt.header("R$F DEPENDENCY CHECK")
        rt.kv_block(
            [
                ("Advisories", result.advisories),
                ("Projects", ", ".join(p["name"] for p in result.projects) or "-"),
                ("Checked", f"{result.packages_checked} packages, {result.dependencies_checked} declared dependencies"),
                ("Vulnerable", f"{len(result.items)}  ({_severity_summary(result.by_severity)})"),
                (
                    "Findings",
                    f"{result.findings.get('created', 0)} new, {result.findings.get('updated', 0)} updated, "
                    f"{result.findings.get('resolved', 0)} resolved",
                ),
            ],
            width=12,
        )
    for note in result.notes:
        rt.note(note)
    if result.items:
        rt.console().print()
        rt.table(
            ["SEV", "CONFIDENCE", "ADVISORY", "PACKAGE", "VERSION", "FIXED", "PROJECT"],
            _vulnerability_rows(result.items),
        )


def render_scan(result: ScanResult, verb: str = "SCAN") -> None:
    project = result.project
    rt.header(f"R$F DEPENDENCY {verb}  {project['name']}  ({project['id']})")
    counts = result.counts
    manifests = ", ".join(str(m["path"]) for m in result.manifests[:6]) + (" ..." if len(result.manifests) > 6 else "")
    ecosystems = ", ".join(f"{eco} {c['declared']}/{c['packages']}" for eco, c in result.by_ecosystem.items())
    rows: list[tuple[str, object]] = [
        ("Manifests", f"{counts.get('manifests', 0)}  ({manifests or '-'})"),
        ("Declared", f"{counts.get('declared', 0)} dependencies, {counts.get('unresolved', 0)} without a version"),
        (
            "Packages",
            f"{counts.get('packages', 0)} ({counts.get('direct', 0)} direct, {counts.get('transitive', 0)} "
            f"transitive), {counts.get('edges', 0)} package edges",
        ),
        ("Ecosystems", (ecosystems + "  (declared/packages)") if ecosystems else "-"),
        (
            "Stored",
            f"{result.stored.get('objects_created', 0)} new objects, "
            f"{result.stored.get('relationships_ended', 0)} relationships ended  ({result.job_id})",
        ),
    ]
    if result.check is not None:
        rows.append(("Vulnerable", f"{len(result.check.items)}  ({_severity_summary(result.check.by_severity)})"))
    rt.kv_block(rows, width=12)
    for item in result.skipped[:10]:
        rt.warn(f"skipped {item['path']}: {item['reason']}")
    for warning in result.warnings[:10]:
        rt.note(warning)
    if result.tree:
        rt.console().print()
        render_tree(str(project["name"]), result.tree)
    if result.check is not None:
        render_check(result.check, title=False)


def _scan_next(result: ScanResult) -> list[str]:
    ref = shlex.quote(str(result.project["id"]))
    steps = (
        []
        if result.check is not None
        else ["raf dependency advisories import <osv.json>", f"raf dependency check {ref}"]
    )
    return [*steps, f"raf dependency sbom export {ref} --output sbom.cdx.json", f"raf graph {ref}"]


@app.command("scan")
def scan_cmd(
    path: Path = typer.Argument(..., help="Directory (or single manifest) to scan; symlinks are not followed."),
    name: str | None = typer.Option(None, "--name", help="Project name (default: directory name)."),
    no_check: bool = typer.Option(False, "--no-check", help="Do not match against imported advisories."),
) -> None:
    """Inventory dependencies from manifests and lockfiles."""
    result = DependencyService(rt.ctx()).scan(path, name=name, check=not no_check)

    def render() -> None:
        render_scan(result)
        rt.next_steps(_scan_next(result))

    rt.output("raf.dependency.scan/v1", result.to_json_dict(), render)


@app.command("check")
def check_cmd(project: str | None = typer.Argument(None, help="Project (name or ID); default: all projects.")) -> None:
    """Match packages and declared constraints against imported advisories."""
    result = DependencyService(rt.ctx()).check(project)

    def render() -> None:
        render_check(result)
        if result.items:
            rt.next_steps(["raf findings --product dependency", f"raf show {result.items[0].vulnerability_id}"])

    rt.output("raf.dependency.check/v1", result.to_json_dict(), render)


@app.command("projects")
def projects_cmd() -> None:
    """Projects with dependency data."""
    items = DependencyService(rt.ctx()).projects()

    def render() -> None:
        rt.header("R$F DEPENDENCY PROJECTS")
        if not items:
            rt.console().print("No projects yet.")
            rt.next_steps(["raf dependency scan <dir>", "raf dependency sample ./raven-shop"])
            return
        rt.table(
            ["PROJECT", "PACKAGES", "DIRECT", "DECLARED", "OPEN FINDINGS", "ECOSYSTEMS", "ID"],
            [
                (
                    p["name"],
                    p["packages"],
                    p["direct"],
                    p["dependencies"],
                    p["open_findings"],
                    ", ".join(p["ecosystems"]),
                    p["id"],
                )
                for p in items
            ],
        )

    rt.output("raf.dependency.projects/v1", {"items": items, "total": len(items)}, render)


@app.command("vulnerable")
def vulnerable_cmd(
    include_unused: bool = typer.Option(False, "--all", help="Also packages no project depends on anymore."),
) -> None:
    """Packages affected by imported advisories (from the last checks)."""
    items = DependencyService(rt.ctx()).vulnerable(include_unused=include_unused)

    def render() -> None:
        rt.header("R$F DEPENDENCY VULNERABLE PACKAGES")
        if not items:
            rt.console().print("No affected packages (run raf dependency check after importing advisories).")
            return
        rows = []
        for entry in items:
            pkg = entry["package"]
            exact = entry["basis"] == "exact"
            version = pkg.get("version") if exact else f"(declared {pkg.get('constraint') or 'any version'})"
            for adv in entry["advisories"]:
                rows.append(
                    (
                        rt.sev_text(adv["severity"]),
                        adv["id"],
                        f"{pkg.get('ecosystem')}/{pkg.get('name')} {version}",
                        "installed" if exact else "possible",
                        f"{adv['confidence']:.2f}",
                        ", ".join(adv["fixed"]) or "-",
                        len(entry["projects"]),
                    )
                )
        rt.table(["SEV", "ADVISORY", "PACKAGE", "MATCH", "CONFIDENCE", "FIXED", "PROJECTS"], rows)
        if any(entry["basis"] == "constraint" for entry in items):
            rt.note(
                "possible: only a version constraint is declared and it admits affected versions; commit a "
                "lockfile so the installed version is known."
            )

    rt.output("raf.dependency.vulnerable/v1", {"items": items, "total": len(items)}, render)


@app.command("sample")
def sample_cmd(
    path: Path = typer.Argument(..., help="Directory to create the fictional raven-shop project in."),
    upgraded: bool = typer.Option(False, "--upgraded", help="Write the fixed versions instead."),
) -> None:
    """Write a small fictional project that pairs with fixtures/advisories/raven-osv.json."""
    files = write_sample_project(path, upgraded=upgraded)
    data = {"path": str(path), "files": [str(f) for f in files], "upgraded": upgraded}

    def render() -> None:
        rt.success(f"Wrote {len(files)} files to {path}")
        rt.next_steps([f"raf dependency scan {shlex.quote(str(path))} --name raven-shop"])

    rt.output("raf.dependency.sample/v1", data, render)


@advisories_app.command("import")
def advisories_import_cmd(
    path: Path = typer.Argument(..., help="OSV JSON file (object or list) or directory."),
) -> None:
    """Import OSV advisories from local files (no network)."""
    result = DependencyService(rt.ctx()).import_advisories(path)

    def render() -> None:
        render_import(result)
        rt.next_steps(["raf dependency check", "raf dependency advisories list"])

    rt.output("raf.dependency.advisories.import/v1", result.to_json_dict(), render)


def render_import(result: AdvisoryImportResult) -> None:
    rt.header(f"R$F DEPENDENCY ADVISORIES  {result.source}")
    rt.kv_block(
        [
            ("Documents", result.documents),
            ("Imported", f"{result.imported} ({result.created} new, {result.updated} updated)"),
            ("Rejected", len(result.rejected)),
        ],
        width=11,
    )
    for rejected in result.rejected[:10]:
        rt.warn(f"{rejected['source']}: {rejected['reason']}")
    if result.advisories:
        rt.console().print()
        rt.table(
            ["ADVISORY", "SEVERITY", "CVSS", "AFFECTS", "SUMMARY"],
            [
                (
                    a["id"],
                    rt.sev_text(a["severity"]),
                    a["cvss"] if a["cvss"] is not None else "-",
                    ", ".join(f"{e['ecosystem']}/{e['name']}" for e in a["affected"]) or "-",
                    str(a["summary"])[:70],
                )
                for a in result.advisories[:50]
            ],
        )


@advisories_app.command("list")
def advisories_list_cmd() -> None:
    """Imported advisories."""
    items = DependencyService(rt.ctx()).advisories()

    def render() -> None:
        rt.header("R$F DEPENDENCY ADVISORIES", f"{len(items)} imported")
        if not items:
            rt.console().print("No advisories imported.")
            rt.next_steps(["raf dependency advisories import <osv.json | dir>"])
            return
        rt.table(
            ["ADVISORY", "SEVERITY", "AFFECTS", "FIXED", "SUMMARY"],
            [
                (
                    a["id"],
                    rt.sev_text(a["severity"]),
                    ", ".join(f"{e['ecosystem']}/{e['name']}" for e in a["affected"]) or "-",
                    ", ".join(v for e in a["affected"] for v in e["fixed"]) or "-",
                    str(a["summary"])[:70],
                )
                for a in items
            ],
        )

    rt.output("raf.dependency.advisories/v1", {"items": items, "total": len(items)}, render)


@sbom_app.command("import")
def sbom_import_cmd(
    file: Path = typer.Argument(..., help="CycloneDX JSON or SPDX 2.x JSON document."),
    name: str | None = typer.Option(None, "--name", help="Project name (default: the SBOM's root component)."),
    no_check: bool = typer.Option(False, "--no-check", help="Do not match against imported advisories."),
) -> None:
    """Import an SBOM as a project (packages and dependency graph)."""
    result = DependencyService(rt.ctx()).import_sbom(file, name=name, check=not no_check)

    def render() -> None:
        render_scan(result, verb="SBOM IMPORT")
        rt.next_steps(_scan_next(result))

    rt.output("raf.dependency.sbom.import/v1", result.to_json_dict(), render)


@sbom_app.command("export")
def sbom_export_cmd(
    project: str = typer.Argument(..., help="Project (name or ID)."),
    output: Path = typer.Option(..., "--output", "-o", help="File to write (CycloneDX 1.5 JSON)."),
) -> None:
    """Export a project's packages and dependency graph as CycloneDX 1.5 JSON."""
    info = DependencyService(rt.ctx()).export_sbom(project, output)
    rt.output(
        "raf.dependency.sbom.export/v1",
        info,
        lambda: rt.success(
            f"Wrote {info['components']} components and {info['dependencies']} dependency links to {info['path']}"
        ),
    )
