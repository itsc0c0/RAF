"""FastAPI application factory for the R$F API (``/api/v1``) and the web workbench."""

from __future__ import annotations

import importlib
import logging
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from raf.apps.api.deps import ContextPool
from raf.apps.api.routers import core
from raf.apps.api.security import (
    LOOPBACK_NAMES,
    HostGuardMiddleware,
    SecurityHeadersMiddleware,
    TokenAuthMiddleware,
    is_loopback,
)
from raf.core.errors import RafError
from raf.core.plugins.registry import ProductRegistry
from raf.core.workspace.manager import RafHome
from raf.products.catalog import builtin_manifests
from raf.version import API_VERSION, RAF_VERSION

log = logging.getLogger("raf.api")

API_PREFIX = f"/api/{API_VERSION}"
WEB_DIST_CANDIDATES = (
    Path(__file__).resolve().parents[4] / "web" / "dist",  # source checkout
    Path(__file__).resolve().parents[1] / "web_dist",  # packaged build
)


def find_web_dist() -> Path | None:
    for candidate in WEB_DIST_CANDIDATES:
        if (candidate / "index.html").exists():
            return candidate
    return None


def create_app(
    *,
    env: Mapping[str, str] | None = None,
    host: str = "127.0.0.1",
    token: str | None = None,
    allowed_hosts: set[str] | None = None,
    serve_ui: bool = True,
    overrides: Mapping[str, Any] | None = None,
) -> FastAPI:
    registry = ProductRegistry(RafHome.from_env(env), builtin_manifests())
    pool = ContextPool(registry, env=env, overrides=overrides)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        yield
        pool.close()

    app = FastAPI(
        title="R$F API",
        version=RAF_VERSION,
        description="R$F (pronounced RAF): Every security capability. One command away.\n\n"
        "All routes are workspace scoped: pass ?workspace=<name> or the X-RAF-Workspace header "
        "(default: the current workspace).",
        openapi_url=f"{API_PREFIX}/openapi.json",
        docs_url="/api/docs",
        redoc_url=None,
        lifespan=lifespan,
    )
    app.state.pool = pool
    app.state.registry = registry

    if not is_loopback(host) and not token:
        raise RafError(
            "Refusing to expose the R$F API on a non-loopback address without authentication.",
            hint="Provide a token (RAF_API_TOKEN) or bind to 127.0.0.1.",
        )
    app.add_middleware(SecurityHeadersMiddleware)
    if token:
        app.add_middleware(TokenAuthMiddleware, token=token)
    hosts = set(allowed_hosts or set()) | LOOPBACK_NAMES
    if not is_loopback(host):
        hosts.add(host)
    if is_loopback(host) or allowed_hosts:
        app.add_middleware(HostGuardMiddleware, allowed_hosts=hosts)

    @app.exception_handler(RafError)
    async def raf_error_handler(_request: Request, exc: RafError) -> JSONResponse:
        return JSONResponse({"error": exc.to_dict()}, status_code=exc.http_status)

    @app.exception_handler(RequestValidationError)
    async def validation_handler(_request: Request, exc: RequestValidationError) -> JSONResponse:
        problems = [{"loc": list(map(str, e.get("loc", []))), "msg": e.get("msg", "")} for e in exc.errors()]
        return JSONResponse(
            {
                "error": {
                    "code": "raf.invalid_request",
                    "message": "Invalid request.",
                    "details": {"problems": problems},
                }
            },
            status_code=422,
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_handler(_request: Request, exc: StarletteHTTPException) -> JSONResponse:
        return JSONResponse(
            {"error": {"code": f"raf.http_{exc.status_code}", "message": str(exc.detail)}}, status_code=exc.status_code
        )

    @app.exception_handler(Exception)
    async def internal_handler(_request: Request, exc: Exception) -> JSONResponse:
        log.error("internal API error", exc_info=exc, extra={"file_only": True})
        return JSONResponse({"error": {"code": "raf.internal", "message": "Internal error."}}, status_code=500)

    app.include_router(core.router, prefix=API_PREFIX)
    for module_name in ("raf.apps.api.routers.snapshots", "raf.apps.api.routers.analysis"):
        try:
            module = importlib.import_module(module_name)
        except ModuleNotFoundError as exc:
            if exc.name != module_name:
                raise
            continue
        app.include_router(module.router, prefix=API_PREFIX)
    _mount_products(app, registry)

    if serve_ui:
        _mount_ui(app)
    return app


def _mount_products(app: FastAPI, registry: ProductRegistry) -> None:
    for info in registry.products():
        manifest = info.manifest
        if not manifest.api or not info.available:
            continue
        try:
            if info.source == "plugin":
                router = registry.load_plugin_attr(manifest.name, manifest.api)
            else:
                module_name, attr = manifest.api.split(":", 1)
                router = getattr(importlib.import_module(module_name), attr)
        except RafError as exc:
            log.warning("product %s API not mounted: %s", manifest.name, exc)
            continue
        app.include_router(router, prefix=f"{API_PREFIX}/{manifest.name}", tags=[manifest.display_name])


def _mount_ui(app: FastAPI) -> None:
    dist = find_web_dist()
    if dist is None:

        @app.get("/", include_in_schema=False)
        def no_ui() -> JSONResponse:
            return JSONResponse(
                {
                    "message": "R$F API is running. The web UI has not been built "
                    "(cd web && npm install && npm run build).",
                    "docs": "/api/docs",
                }
            )

        return
    root = dist.resolve()

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str) -> FileResponse:
        if path.startswith("api/"):
            raise StarletteHTTPException(status_code=404, detail="Not found")
        candidate = (root / path).resolve()
        if path and candidate.is_file() and candidate.is_relative_to(root):
            return FileResponse(candidate)
        return FileResponse(root / "index.html")
