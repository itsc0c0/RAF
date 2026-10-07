"""Structured errors.

Every error R$F raises intentionally derives from :class:`RafError`. Errors carry
a stable machine-readable ``code``, a human ``message``, an optional ``reason``
(why it happened), a ``hint`` and suggested follow-up commands. Interfaces (CLI,
API) render them for security engineers instead of dumping stack traces.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any


class RafError(Exception):
    """Base class for all expected R$F errors."""

    code: str = "raf.error"
    exit_code: int = 1
    http_status: int = 400

    def __init__(
        self,
        message: str,
        *,
        reason: str | None = None,
        hint: str | None = None,
        suggestions: Sequence[str] = (),
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.reason = reason
        self.hint = hint
        self.suggestions = list(suggestions)
        self.details = dict(details or {})

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.reason:
            data["reason"] = self.reason
        if self.hint:
            data["hint"] = self.hint
        if self.suggestions:
            data["suggestions"] = self.suggestions
        if self.details:
            data["details"] = self.details
        return data

    def __str__(self) -> str:
        if self.reason:
            return f"{self.message} ({self.reason})"
        return self.message


class NotFoundError(RafError):
    code = "raf.not_found"
    exit_code = 3
    http_status = 404


class AmbiguousReferenceError(RafError):
    code = "raf.ambiguous_reference"
    exit_code = 4
    http_status = 409

    def __init__(self, reference: str, candidates: Sequence[str], **kwargs: Any) -> None:
        shown = list(candidates)[:10]
        super().__init__(
            f"'{reference}' matches more than one object.",
            reason="Name resolution found multiple candidates: " + ", ".join(shown),
            hint="Use a full object ID (for example 'host:ws-04') or a type-qualified reference.",
            details={"candidates": list(candidates)},
            **kwargs,
        )
        self.candidates = list(candidates)


class InvalidInputError(RafError):
    code = "raf.invalid_input"
    exit_code = 4
    http_status = 422


class ConflictError(RafError):
    code = "raf.conflict"
    exit_code = 4
    http_status = 409


class ConfigError(RafError):
    code = "raf.config"
    exit_code = 4
    http_status = 422


class WorkspaceError(RafError):
    code = "raf.workspace"
    exit_code = 4
    http_status = 409


class StorageError(RafError):
    code = "raf.storage"
    exit_code = 1
    http_status = 500


class IngestionError(RafError):
    code = "raf.ingestion"
    exit_code = 1
    http_status = 422


class SecurityViolation(RafError):
    """Untrusted input attempted something unsafe (path traversal, archive bomb, ...)."""

    code = "raf.security_violation"
    exit_code = 5
    http_status = 400


class ResourceLimitExceeded(SecurityViolation):
    code = "raf.resource_limit"


class PermissionDeniedError(RafError):
    code = "raf.permission_denied"
    exit_code = 5
    http_status = 403


class ProductDisabledError(RafError):
    code = "raf.product_disabled"
    exit_code = 4
    http_status = 409


class DependencyUnavailableError(RafError):
    """An optional external dependency (Docker, keyring, AI provider) is unavailable."""

    code = "raf.dependency_unavailable"
    exit_code = 6
    http_status = 503


class OperationCancelled(RafError):
    code = "raf.cancelled"
    exit_code = 130
    http_status = 409


class ConfirmationRequired(RafError):
    code = "raf.confirmation_required"
    exit_code = 4
    http_status = 428


class IntegrityError(RafError):
    """Stored data failed an integrity check (hash mismatch, broken chain)."""

    code = "raf.integrity"
    exit_code = 5
    http_status = 409
