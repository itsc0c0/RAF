"""Product / plugin manifests.

Built-in products and third-party plugins are described by the same manifest
model. A manifest declares what the product contributes (CLI commands, API
routes, parsers, analyzers), which other products it depends on (must form a
DAG), and - for plugins - which permissions it requests.
"""

from __future__ import annotations

import re
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field, ValidationError, field_validator

from raf.core.errors import InvalidInputError
from raf.core.objects.models import RafModel
from raf.version import PLUGIN_API_VERSION


class ProductStatus(StrEnum):
    STABLE = "STABLE"
    BETA = "BETA"
    ALPHA = "ALPHA"
    EXPERIMENTAL = "EXPERIMENTAL"


#: Permissions a plugin may request. Enforced by the SDK facade (PluginContext).
PERMISSIONS: dict[str, str] = {
    "read.objects": "Read objects, relationships and incidents",
    "write.objects": "Create or update objects",
    "write.relationships": "Create or update relationships",
    "read.events": "Read normalized events",
    "write.events": "Ingest events",
    "read.findings": "Read findings",
    "write.findings": "Create or update findings",
    "read.evidence": "Read evidence metadata",
    "run.jobs": "Run long operations as jobs",
    "register.parsers": "Register ingestion parsers",
    "network.outbound": "Declares that the plugin makes outbound network connections",
}

_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{1,40}$")
_IMPORT_RE = re.compile(r"^[A-Za-z_][\w.]*:[A-Za-z_]\w*$")


class ProductManifest(RafModel):
    name: str
    display_name: str
    version: str
    api_version: int = PLUGIN_API_VERSION
    status: ProductStatus
    description: str
    category: str = "analysis"
    depends_on: list[str] = Field(default_factory=list)
    commands: list[str] = Field(default_factory=list)
    cli: str | None = None
    api: str | None = None
    parsers: list[str] = Field(default_factory=list)
    analyzers: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)
    entrypoint: str | None = None
    optional: bool = False
    builtin: bool = True
    docs: str | None = None
    ui: dict[str, Any] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        if not _NAME_RE.match(value):
            raise ValueError("name must be lowercase letters, digits and '-' (2-41 chars)")
        return value

    @field_validator("cli", "api", "entrypoint")
    @classmethod
    def _import_path(cls, value: str | None) -> str | None:
        if value is not None and not _IMPORT_RE.match(value):
            raise ValueError("expected 'module.path:attribute'")
        return value

    @field_validator("parsers", "analyzers")
    @classmethod
    def _import_paths(cls, value: list[str]) -> list[str]:
        for item in value:
            if not _IMPORT_RE.match(item):
                raise ValueError(f"invalid import path {item!r}")
        return value

    @field_validator("permissions")
    @classmethod
    def _permissions(cls, value: list[str]) -> list[str]:
        unknown = sorted(set(value) - set(PERMISSIONS))
        if unknown:
            raise ValueError("unknown permissions: " + ", ".join(unknown))
        return sorted(set(value))

    @field_validator("api_version")
    @classmethod
    def _api_version(cls, value: int) -> int:
        if value != PLUGIN_API_VERSION:
            raise ValueError(f"unsupported plugin api_version {value} (this R$F supports {PLUGIN_API_VERSION})")
        return value


def load_manifest_file(path: Path) -> ProductManifest:
    """Load a plugin manifest (YAML, safe loader only)."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise InvalidInputError(f"Could not read plugin manifest {path}.", reason=str(exc)) from exc
    if not isinstance(raw, dict):
        raise InvalidInputError(f"Plugin manifest {path} must be a mapping.")
    raw.setdefault("builtin", False)
    raw.setdefault("status", "EXPERIMENTAL")
    raw.setdefault("display_name", str(raw.get("name", "")).replace("-", " ").title())
    if raw.get("builtin"):
        raise InvalidInputError("Plugins cannot declare themselves built-in.")
    try:
        return ProductManifest.model_validate(raw)
    except ValidationError as exc:
        problems = "; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors())
        raise InvalidInputError(f"Invalid plugin manifest {path}.", reason=problems) from exc
