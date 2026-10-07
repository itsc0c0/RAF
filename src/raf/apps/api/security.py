"""API protections.

* Loopback binding is the default. Remote binding requires a token.
* Host-header validation defeats DNS rebinding against the local service.
* Optional bearer token (``RAF_API_TOKEN`` / keyring) for every request when set.
* Request bodies are limited before they are buffered (``api.max_upload_mb``): a declared
  Content-Length above the limit is refused up front, and streamed bodies are counted.
"""

from __future__ import annotations

import hmac
import ipaddress
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

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


class _BodyTooLarge(Exception):
    pass


class BodyLimitMiddleware:
    """Pure ASGI middleware: 413 for request bodies larger than ``max_bytes`` (declared or streamed)."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def _reject(self, send: Send, status: int, message: str) -> None:
        response = JSONResponse({"error": {"code": "raf.request_too_large" if status == 413 else "raf.bad_request",
                                           "message": message}}, status_code=status)
        await send({"type": "http.response.start", "status": response.status_code,
                    "headers": response.raw_headers})
        await send({"type": "http.response.body", "body": response.body})

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit_mb = self.max_bytes // (1024 * 1024)
        for name, value in scope.get("headers") or []:
            if name == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    await self._reject(send, 400, "Invalid Content-Length header.")
                    return
                if declared > self.max_bytes:
                    await self._reject(send, 413, f"Request body exceeds the {limit_mb} MB limit (api.max_upload_mb).")
                    return
        received = 0
        started = False

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise _BodyTooLarge
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except _BodyTooLarge:
            if not started:
                await self._reject(send, 413, f"Request body exceeds the {limit_mb} MB limit (api.max_upload_mb).")
