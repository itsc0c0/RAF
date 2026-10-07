"""Application context shared by the CLI, API and services.

A :class:`RafContext` bundles the resolved configuration, the active workspace,
its store, the audit log, the job manager and context references. Interfaces
create one context per invocation (CLI) or per workspace (API) and pass it to
product services; services never construct their own infrastructure.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from raf.core.audit.service import AuditLog, current_user
from raf.core.config.loader import Settings, load_settings
from raf.core.context.refs import ContextRefs
from raf.core.jobs.manager import JobManager
from raf.core.plugins.registry import ProductRegistry
from raf.core.query.resolve import Resolved, Resolver
from raf.core.storage.database import sqlite_url
from raf.core.storage.store import Store
from raf.core.workspace.manager import RafHome, Workspace, WorkspaceManager


@dataclass
class RafContext:
    home: RafHome
    workspaces: WorkspaceManager
    workspace: Workspace
    settings: Settings
    store: Store
    audit: AuditLog
    jobs: JobManager
    refs: ContextRefs
    interface: str = "cli"
    registry: ProductRegistry | None = None
    extras: dict[str, Any] = field(default_factory=dict)

    @property
    def resolver(self) -> Resolver:
        return Resolver(self.store, self.refs)

    def resolve(self, ref: str, **kwargs: Any) -> Resolved:
        return self.resolver.resolve(ref, **kwargs)

    def require_product(self, name: str) -> None:
        if self.registry is not None:
            self.registry.require(name)

    def close(self) -> None:
        self.jobs.shutdown()
        self.store.close()


def open_context(
    *,
    workspace: str | None = None,
    interface: str = "cli",
    command: str = "",
    overrides: Mapping[str, Any] | None = None,
    env: Mapping[str, str] | None = None,
    registry: ProductRegistry | None = None,
) -> RafContext:
    env = os.environ if env is None else env
    home = RafHome.from_env(env)
    home.ensure()
    manager = WorkspaceManager(home, env)
    ws = manager.open(workspace)
    settings = load_settings(home.config_path, ws.config_path, env=env, overrides=overrides)
    url = str(settings.get("storage.url") or "") or sqlite_url(Path(ws.db_path))
    store = Store.open(url)
    actor = f"{current_user()}@{interface}"
    audit = AuditLog(store.engine, workspace=ws.name, interface=interface, command=command)
    jobs = JobManager(store.engine, actor=actor)
    refs = ContextRefs(store.kv, ws.name)
    return RafContext(
        home=home,
        workspaces=manager,
        workspace=ws,
        settings=settings,
        store=store,
        audit=audit,
        jobs=jobs,
        refs=refs,
        interface=interface,
        registry=registry,
    )
