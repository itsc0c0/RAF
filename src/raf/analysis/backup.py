"""Workspace backup (export) and restore (import) built on the bundle format."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sqlalchemy import select

from raf.core.bundle.format import BundleManifest, export_bundle, import_bundle, open_bundle, table_rows
from raf.core.context.app import RafContext, open_context
from raf.core.errors import ConflictError, IntegrityError
from raf.core.storage import schema as s
from raf.core.workspace.manager import RafHome, WorkspaceManager


def export_workspace(ctx: RafContext, output: Path) -> BundleManifest:
    store = ctx.store
    evidence_files: dict[str, Path] = {}
    with store.engine.connect() as conn:
        for (digest,) in conn.execute(select(s.evidence_items.c.sha256).distinct()):
            candidate = ctx.workspace.evidence_dir / digest[:2] / digest
            if candidate.exists():
                evidence_files[digest] = candidate
    provenance = table_rows(ctx, s.provenance)
    return export_bundle(
        ctx,
        output,
        objects=store.objects.iter_all(),
        relationships=store.relationships.iter_all(),
        events=store.events.iter(_all_events()),
        findings=store.findings.list(limit=10_000_000),
        provenance=({k: v for k, v in row.items() if k != "id"} for row in provenance),
        extra_tables={
            "cases": table_rows(ctx, s.cases),
            "evidence": table_rows(ctx, s.evidence_items),
            "custody": table_rows(ctx, s.custody_events),
            "snapshots": table_rows(ctx, s.snapshots),
            "snapshot_items": table_rows(ctx, s.snapshot_items),
            "blobs": table_rows(ctx, s.blobs),
            "audit": table_rows(ctx, s.audit_log),
        },
        evidence_files=evidence_files,
        scope={"workspace_backup": ctx.workspace.name},
        description=f"Backup of workspace {ctx.workspace.name}",
    )


def _all_events() -> Any:
    from raf.core.storage.repos.events import EventQuery

    return EventQuery()


def restore_workspace(path: Path, name: str) -> dict[str, Any]:
    manager = WorkspaceManager(RafHome.from_env())
    if manager.exists(name):
        raise ConflictError(f"Workspace '{name}' already exists; restore into a new name.")
    ctx = open_context()  # validate the archive before creating anything
    try:
        reader = open_bundle(ctx, path)
        problems = reader.verify()
        reader.close()
    finally:
        ctx.close()
    if problems:
        raise IntegrityError("Backup failed verification; nothing was restored.", details={"problems": problems[:20]})
    manager.create(name, f"Restored from {path.name}")
    target = open_context(workspace=name)
    try:
        result = import_bundle(target, path, restore_tables=True)
        target.audit.record("workspace.import", affected=[name], details={"source": str(path), **result["imported"]})
    finally:
        target.close()
    return {"workspace": name, **result}
