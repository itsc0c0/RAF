"""FastAPI application factory for the R$F API (``/api/v1``) and the web workbench."""

from __future__ import annotations

import importlib
import logging
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.routing import APIRoute, APIWebSocketRoute
from starlette.exceptions import HTTPException as StarletteHTTPException

from raf.apps.api.deps import ContextPool
from raf.apps.api.routers import core
from raf.apps.api.security import (
    LOOPBACK_NAMES,
    BodyLimitMiddleware,
    HostGuardMiddleware,
    SecurityHeadersMiddleware,
    TokenAuthMiddleware,
    is_loopback,
)
from raf.core.config.loader import load_settings
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
    home = RafHome.from_env(env)
    limits = load_settings(home.config_path, env=env, overrides=overrides)
    app.add_middleware(BodyLimitMiddleware, max_bytes=int(limits.get("api.max_upload_mb")) * 1024 * 1024)
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
    namespaces = _namespaces(core.router)
    for module_name in ("raf.apps.api.routers.snapshots", "raf.apps.api.routers.analysis", "raf.apps.api.routers.tui"):
        try:
            module = importlib.import_module(module_name)
        except ModuleNotFoundError as exc:
            if exc.name != module_name:
                raise
            continue
        app.include_router(module.router, prefix=API_PREFIX)
        namespaces |= _namespaces(module.router)
    _mount_products(app, registry, namespaces)

    if serve_ui:
        _mount_ui(app)
    return app


def _check_routes(router: APIRouter) -> None:
    for route in router.routes:
        nested = getattr(route, "original_router", None)  # a router included in this one (kept lazily by FastAPI)
        if isinstance(nested, APIRouter):
            _check_routes(nested)
        elif not isinstance(route, APIRoute | APIWebSocketRoute):
            raise TypeError(
                f"unsupported route {getattr(route, 'path', type(route).__name__)!r}: only routes declared with "
                "the router's decorators (@router.get, ...) get R$F's availability check"
            )


def _api_router(value: Any) -> APIRouter:
    """A product's ``api`` object: a FastAPI router whose routes can all carry the availability check."""
    if not isinstance(value, APIRouter):
        raise TypeError(f"expected a FastAPI APIRouter, got {type(value).__name__}")
    _check_routes(value)
    return value


def _require_available(product: str) -> Callable[[Request], None]:
    """Router dependency: a product's routes answer 503 while it is disabled or otherwise unavailable."""

    def require_available(request: Request) -> None:
        registry: ProductRegistry = request.app.state.registry
        registry.refresh()  # `raf product disable` in another process applies from the next request
        registry.require(product)

    return require_available


def _namespaces(router: APIRouter) -> set[str]:
    """First path segments of a router's routes (``/objects/{id}`` -> ``objects``)."""
    paths = (getattr(route, "path", None) for route in router.routes)
    return {path.lstrip("/").split("/", 1)[0] for path in paths if isinstance(path, str)}


def _mount_products(app: FastAPI, registry: ProductRegistry, namespaces: set[str]) -> None:
    """Mount every product router at ``/api/v1/<name>`` behind a per-request availability check.

    Built-in routers are mounted even when the product is unavailable at startup, so that enabling
    it later takes effect immediately. Plugin code is imported only from a plugin that is trusted,
    enabled and unmodified, and a plugin cannot add routes under a path of R$F's own routes
    (``namespaces``: ``objects``, ``products``, ``tui`` ... and the built-in product names)."""
    infos = registry.products()
    namespaces = namespaces | {info.name for info in infos if info.source == "builtin"}
    for info in infos:
        manifest = info.manifest
        if not manifest.api:
            continue
        if info.source == "plugin" and manifest.name in namespaces:
            log.warning("plugin %s API not mounted: %s/%s is an R$F route", manifest.name, API_PREFIX, manifest.name)
            continue
        try:
            router = registry.load_attr(manifest.name, manifest.api, _api_router)
        except RafError as exc:
            # untrusted, disabled or modified plugins are not loaded; broken code was logged by the registry
            log.debug("product %s API not mounted: %s", manifest.name, exc)
            continue
        try:
            app.include_router(
                router,
                prefix=f"{API_PREFIX}/{manifest.name}",
                tags=[manifest.display_name],
                dependencies=[Depends(_require_available(manifest.name))],
            )
        except Exception as exc:  # noqa: BLE001 - one broken product (or plugin) must not take the API down
            registry.mark_unavailable(manifest.name, f"API routes could not be mounted: {exc}")


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
