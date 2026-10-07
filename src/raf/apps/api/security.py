"""API protections.

* Loopback binding is the default. Remote binding requires a token.
* Host-header validation defeats DNS rebinding against the local service.
* Optional bearer token (``RAF_API_TOKEN`` / keyring) for every request when set.
"""

from __future__ import annotations

import hmac
import ipaddress
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

LOOPBACK_NAMES = {"localhost", "127.0.0.1", "::1", "[::1]", "testserver"}


def is_loopback(host: str) -> bool:
    if host in {"localhost"}:
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


class HostGuardMiddleware(BaseHTTPMiddleware):
    """Reject requests whose Host header is not an allowed name (DNS rebinding defense)."""

    def __init__(self, app: ASGIApp, allowed_hosts: set[str]) -> None:
        super().__init__(app)
        self.allowed = {h.lower() for h in allowed_hosts}

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        host_header = request.headers.get("host", "")
        host = host_header.rsplit(":", 1)[0] if not host_header.startswith("[") else host_header.split("]")[0] + "]"
        if host.lower() not in self.allowed:
            return JSONResponse(
                {"error": {"code": "raf.forbidden_host", "message": "Host header not allowed for this R$F instance."}},
                status_code=403,
            )
        return await call_next(request)


class TokenAuthMiddleware(BaseHTTPMiddleware):
    """Require ``Authorization: Bearer <token>`` for API routes when a token is configured."""

    def __init__(self, app: ASGIApp, token: str) -> None:
        super().__init__(app)
        self.token = token.encode()

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        if request.url.path.startswith("/api/") and request.url.path not in {"/api/v1/health"}:
            supplied = request.headers.get("authorization", "")
            scheme, _, value = supplied.partition(" ")
            if scheme.lower() != "bearer" or not hmac.compare_digest(value.strip().encode(), self.token):
                return JSONResponse(
                    {"error": {"code": "raf.unauthorized", "message": "Missing or invalid token."}},
                    status_code=401,
                    headers={"WWW-Authenticate": "Bearer"},
                )
        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        if not request.url.path.startswith("/api/docs"):
            response.headers.setdefault(
                "Content-Security-Policy",
                "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                "script-src 'self'; connect-src 'self'; frame-ancestors 'none'",
            )
        return response
