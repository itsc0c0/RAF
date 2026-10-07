"""``raf snapshot``: capture and manage security-state snapshots."""

from __future__ import annotations

import typer
from rich.text import Text

from raf.analysis.providers import install_state_providers
from raf.core.snapshots.service import Snapshot, SnapshotService, resolve_state
from raf.sdk import cli as rt

snapshot_app = typer.Typer(
    help="Security-state snapshots (objects, relationships, policies, findings).", no_args_is_help=True
)


def _render_snapshot(snap: Snapshot) -> None:
    rt.header(f"SNAPSHOT {snap.name}", snap.description or None)
    stats = snap.stats
    rt.kv_block(
        [
            ("Created", rt.ts_text(snap.created_at)),
            ("Source", snap.source),
            ("Objects", f"{stats.get('objects', 0):,}"),
            ("Relationships", f"{stats.get('relationships', 0):,}"),
            ("Findings", f"{stats.get('findings', 0):,}"),
            ("Storage", f"{stats.get('new_blobs', 0):,} new blobs, {stats.get('shared_blobs', 0):,} shared"),
            ("State hash", snap.content_hash[:16]),
        ],
        width=15,
    )


@snapshot_app.command("create")
def snapshot_create(
    name: str,
    source: str = typer.Option("current", "--source", help="current (workspace) or ghost:<model>."),
    description: str = typer.Option("", "--description", "-d"),
) -> None:
    """Capture a snapshot of the current workspace (or a Ghost model)."""
    ctx = rt.ctx()
    service = SnapshotService(ctx.store)
    if source in ("current", "workspace"):
        snap = service.create(name, source="workspace", description=description)
    else:
        install_state_providers(ctx)
        state = resolve_state(ctx, source)
        snap = service.create_from_state(name, state, source=source, description=description)
    ctx.audit.record("snapshot.create", affected=[snap.id], details={"source": snap.source, **snap.stats})
    ctx.refs.remember("snapshot", snap.name)

    def render() -> None:
        rt.success(f"Snapshot '{snap.name}' created.")
        _render_snapshot(snap)
        others = [s.name for s in service.list() if s.name != snap.name]
        rt.next_steps([f"raf diff {others[-1]} {snap.name}"] if others else [f"raf diff {snap.name} current"])

    rt.output("raf.snapshot/v1", snap.to_json_dict(), render)


@snapshot_app.command("list")
def snapshot_list() -> None:
    """List snapshots."""
    items = SnapshotService(rt.ctx().store).list()

    def render() -> None:
        if not items:
            rt.console().print("No snapshots yet.")
            rt.next_steps(["raf snapshot create baseline"])
            return
        rt.table(
            ["SNAPSHOT", "CREATED", "SOURCE", "OBJECTS", "RELATIONSHIPS", "FINDINGS"],
            [
                (
                    s.name,
                    rt.ts_text(s.created_at),
                    s.source,
                    f"{s.stats.get('objects', 0):,}",
                    f"{s.stats.get('relationships', 0):,}",
                    f"{s.stats.get('findings', 0):,}",
                )
                for s in items
            ],
        )

    rt.output("raf.snapshots/v1", {"items": [s.to_json_dict() for s in items]}, render)


@snapshot_app.command("show")
def snapshot_show(name: str) -> None:
    """Show snapshot details."""
    snap = SnapshotService(rt.ctx().store).require(name)
    rt.output("raf.snapshot/v1", snap.to_json_dict(), lambda: _render_snapshot(snap))


@snapshot_app.command("delete")
def snapshot_delete(name: str) -> None:
    """Delete a snapshot (shared content used by other snapshots is kept)."""
    ctx = rt.ctx()
    service = SnapshotService(ctx.store)
    snap = service.require(name)
    rt.confirm(
        f"Delete snapshot '{snap.name}'?",
        [f"{snap.stats.get('objects', 0):,} objects, {snap.stats.get('relationships', 0):,} relationships"],
    )
    result = service.delete(name)
    ctx.audit.record("snapshot.delete", affected=[snap.id], details=result)
    rt.output(
        "raf.snapshot.delete/v1",
        {"name": snap.name, **result},
        lambda: rt.console().print(Text(f"Deleted snapshot '{snap.name}'.", style="green")),
    )


def register(app: typer.Typer) -> None:
    app.add_typer(snapshot_app, name="snapshot", rich_help_panel="Investigate")
