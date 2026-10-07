"""Request dependencies: workspace-scoped application contexts."""

from __future__ import annotations

import threading
from collections.abc import Mapping
from typing import Any

from fastapi import Request

from raf.core.context.app import RafContext, open_context
from raf.core.plugins.registry import ProductRegistry
from raf.core.workspace.manager import RafHome, WorkspaceManager, validate_workspace_name
from raf.sdk.api import Ctx as Ctx  # re-exported for the application's own routers
from raf.sdk.api import get_context as get_context


class ContextPool:
    """One long-lived RafContext per workspace (thread-safe lazy creation)."""

    def __init__(
        self,
        registry: ProductRegistry,
        env: Mapping[str, str] | None = None,
        overrides: Mapping[str, Any] | None = None,
    ) -> None:
        self.registry = registry
        self.env = env
        self.overrides = overrides
        self._contexts: dict[str, RafContext] = {}
        self._lock = threading.Lock()

    def default_workspace(self) -> str:
        return WorkspaceManager(RafHome.from_env(self.env), self.env).current_name()

    def get(self, workspace: str | None) -> RafContext:
        name = validate_workspace_name(workspace) if workspace else self.default_workspace()
        with self._lock:
            ctx = self._contexts.get(name)
            if ctx is None:
                ctx = open_context(
                    workspace=name,
                    interface="api",
                    command="api",
                    env=self.env,
                    overrides=self.overrides,
                    registry=self.registry,
                )
                ctx.jobs.reconcile()
                self._contexts[name] = ctx
            return ctx

    def drop(self, workspace: str) -> None:
        with self._lock:
            ctx = self._contexts.pop(workspace, None)
        if ctx is not None:
            ctx.close()

    def close(self) -> None:
        with self._lock:
            for ctx in self._contexts.values():
                ctx.close()
            self._contexts.clear()


def get_pool(request: Request) -> ContextPool:
    pool: ContextPool = request.app.state.pool
    return pool
