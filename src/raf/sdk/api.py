"""API runtime for R$F product routers: the request-scoped workspace context.

Product routers declare ``ctx: Ctx`` and receive the :class:`RafContext` of the workspace the
request addresses (``?workspace=`` or the ``X-RAF-Workspace`` header, else the current one).
The application (``raf.apps.api``) provides the contexts; products never import the application.
"""

from __future__ import annotations

from typing import Annotated, Protocol

from fastapi import Depends, Header, Query, Request

from raf.core.context.app import RafContext


class ContextProvider(Protocol):
    def get(self, workspace: str | None) -> RafContext: ...


def get_context(
    request: Request,
    workspace: Annotated[str | None, Query(description="Workspace (default: current)")] = None,
    x_raf_workspace: Annotated[str | None, Header()] = None,
) -> RafContext:
    provider: ContextProvider = request.app.state.pool
    return provider.get(workspace or x_raf_workspace)


Ctx = Annotated[RafContext, Depends(get_context)]
