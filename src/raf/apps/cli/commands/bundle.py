"""Workspace backup/restore and bundle verification (``.raf`` files)."""

from __future__ import annotations

import tempfile
from pathlib import Path

import typer

from raf.analysis.backup import export_workspace, restore_workspace
from raf.core.bundle.format import import_bundle, open_bundle
from raf.sdk import cli as rt

bundle_app = typer.Typer(help="R$F bundles (.raf): verify, inspect, import.", no_args_is_help=True)


@bundle_app.command("verify")
def bundle_verify(path: Path) -> None:
    """Validate a bundle's structure, safety and member hashes."""
    reader = open_bundle(rt.ctx(), path)
    try:
        problems = reader.verify()
        manifest = reader.manifest
    finally:
        reader.close()
    data = {"path": str(path), "valid": not problems, "problems": problems, "manifest": manifest.to_json_dict()}

    def render() -> None:
        rt.header(f"R$F BUNDLE  {path.name}")
        rt.kv_block(
            [
                ("Format", f"{manifest.format}/{manifest.format_version}"),
                ("Created", manifest.created_at),
                ("Workspace", manifest.workspace),
                ("Members", len(manifest.files)),
                ("Counts", ", ".join(f"{k} {v}" for k, v in manifest.counts.items() if v)),
            ],
            width=12,
        )
        if problems:
            for problem in problems:
                rt.warn(problem)
        else:
            rt.success("All member hashes verified.")

    rt.output("raf.bundle.verify/v1", data, render)
    if problems:
        raise typer.Exit(5)


@bundle_app.command("import")
def bundle_import(path: Path) -> None:
    """Merge a bundle's objects, relationships, events, findings and evidence into this workspace."""
    ctx = rt.ctx()
    result = import_bundle(ctx, path)
    ctx.audit.record("bundle.import", affected=[str(path)], details=result["imported"])

    def render() -> None:
        rt.success(f"Imported {path.name}.")
        rt.kv_block([(k, v) for k, v in result["imported"].items() if v])

    rt.output("raf.bundle.import/v1", result, render)


def register(app: typer.Typer) -> None:
    from raf.apps.cli.commands.workspace import workspace_app

    @workspace_app.command("export")
    def ws_export(name: str, output: Path) -> None:
        """Back up a workspace (data, cases, evidence files, snapshots, audit log) to a .raf bundle."""
        rt.STATE.workspace = name
        ctx = rt.ctx()
        manifest = export_workspace(ctx, output)
        ctx.audit.record("workspace.export", affected=[name], details={"path": str(output), **manifest.counts})
        rt.output(
            "raf.workspace.export/v1",
            {"path": str(output), "manifest": manifest.to_json_dict()},
            lambda: rt.success(
                f"Exported workspace '{name}' to {output} "
                f"({', '.join(f'{k} {v}' for k, v in manifest.counts.items() if v)})."
            ),
        )

    @workspace_app.command("import")
    def ws_import(path: Path, name: str = typer.Option(..., "--name", help="Name of the workspace to create.")) -> None:
        """Restore a workspace backup into a NEW workspace (archive validated before anything is written)."""
        rt.STATE.workspace = None
        with tempfile.TemporaryDirectory():
            result = restore_workspace(path, name)

        def render() -> None:
            rt.success(f"Restored workspace '{name}' from {path.name}.")
            rt.next_steps([f"raf workspace use {name}"])

        rt.output("raf.workspace.import/v1", result, render)

    app.add_typer(bundle_app, name="bundle", rich_help_panel="Workspace")
