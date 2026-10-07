"""Local product registry (built-in products + installed plugins).

State lives in ``RAF_HOME/registry.json``. A remote registry is an explicit
future extension point (:class:`RemoteRegistry`); R$F works without one.

Plugin trust model: installing a plugin copies it but leaves it disabled.
``raf plugin trust`` records the SHA-256 of the plugin's files; R$F only loads a
plugin whose files still match that hash. Python plugins run in-process: trust
is the security boundary, permissions are enforced at the SDK facade.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import logging
import shutil
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from raf.core.errors import (
    ConflictError,
    DependencyUnavailableError,
    InvalidInputError,
    NotFoundError,
    ProductDisabledError,
    SecurityViolation,
)
from raf.core.plugins.manifest import ProductManifest, load_manifest_file
from raf.core.timeutil import format_ts, utcnow
from raf.core.workspace.manager import RafHome

log = logging.getLogger("raf.registry")

MANIFEST_FILE = "raf-plugin.yaml"


@dataclass(frozen=True, slots=True)
class ProductInfo:
    manifest: ProductManifest
    enabled: bool
    available: bool
    source: str  # builtin | plugin
    trusted: bool
    unavailable_reason: str | None = None

    @property
    def name(self) -> str:
        return self.manifest.name

    @property
    def display_status(self) -> str:
        if not self.enabled:
            return "DISABLED"
        if not self.available:
            return "UNAVAILABLE"
        return self.manifest.status.value

    def to_dict(self) -> dict[str, Any]:
        m = self.manifest
        return {
            "name": m.name,
            "display_name": m.display_name,
            "version": m.version,
            "status": self.display_status,
            "maturity": m.status.value,
            "description": m.description,
            "category": m.category,
            "depends_on": m.depends_on,
            "commands": m.commands,
            "optional": m.optional,
            "enabled": self.enabled,
            "available": self.available,
            "source": self.source,
            "trusted": self.trusted,
            "unavailable_reason": self.unavailable_reason,
            "permissions": m.permissions,
            "docs": m.docs,
            "ui": m.ui,
        }


def directory_hash(root: Path) -> str:
    """SHA-256 over relative paths and contents of every regular file under ``root``."""
    hasher = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file() and "__pycache__" not in p.parts):
        if path.is_symlink():
            raise SecurityViolation(f"Plugin contains a symlink: {path.relative_to(root)}")
        hasher.update(str(path.relative_to(root).as_posix()).encode())
        hasher.update(b"\0")
        hasher.update(path.read_bytes())
        hasher.update(b"\0")
    return hasher.hexdigest()


class RemoteRegistry(ABC):
    """Interface for a future remote product registry."""

    @abstractmethod
    def search(self, query: str) -> list[dict[str, Any]]: ...

    @abstractmethod
    def fetch(self, name: str, version: str | None, destination: Path) -> Path: ...


class UnconfiguredRemoteRegistry(RemoteRegistry):
    def _fail(self) -> DependencyUnavailableError:
        return DependencyUnavailableError(
            "No remote product registry is configured.",
            reason="R$F currently installs products from local directories only.",
            hint="Install a local plugin with: raf install ./path/to/plugin",
        )

    def search(self, query: str) -> list[dict[str, Any]]:
        raise self._fail()

    def fetch(self, name: str, version: str | None, destination: Path) -> Path:
        raise self._fail()


class ProductRegistry:
    def __init__(self, home: RafHome, builtins: list[ProductManifest], remote: RemoteRegistry | None = None) -> None:
        self.home = home
        self.remote = remote or UnconfiguredRemoteRegistry()
        self._builtins = {m.name: m for m in builtins}
        self._state = self._read_state()
        self._plugin_manifests = self._discover_plugins()
        self._check_dependencies()

    # ------------------------------------------------------------------ state
    def _read_state(self) -> dict[str, Any]:
        try:
            data = json.loads(self.home.registry_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {"disabled": [], "plugins": {}}
        except (OSError, json.JSONDecodeError):
            log.warning("registry state unreadable; using defaults")
            return {"disabled": [], "plugins": {}}
        data.setdefault("disabled", [])
        data.setdefault("plugins", {})
        return data if isinstance(data, dict) else {"disabled": [], "plugins": {}}

    def _write_state(self) -> None:
        self.home.ensure()
        tmp = self.home.registry_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._state, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(self.home.registry_path)

    def _discover_plugins(self) -> dict[str, ProductManifest]:
        manifests: dict[str, ProductManifest] = {}
        for name in sorted(self._state.get("plugins", {})):
            path = self.home.plugins_dir / name / MANIFEST_FILE
            if not path.exists():
                log.warning("plugin %s is registered but missing on disk", name)
                continue
            try:
                manifests[name] = load_manifest_file(path)
            except InvalidInputError as exc:
                log.warning("plugin %s has an invalid manifest: %s", name, exc)
        return manifests

    def _check_dependencies(self) -> None:
        manifests = self.manifests()
        visiting: set[str] = set()
        done: set[str] = set()

        def visit(name: str, chain: list[str]) -> None:
            if name in done:
                return
            if name in visiting:
                raise InvalidInputError("Product dependency cycle: " + " -> ".join([*chain, name]))
            visiting.add(name)
            for dep in manifests[name].depends_on if name in manifests else []:
                visit(dep, [*chain, name])
            visiting.discard(name)
            done.add(name)

        for name in manifests:
            visit(name, [])

    # ------------------------------------------------------------------ queries
    def manifests(self) -> dict[str, ProductManifest]:
        return {**self._builtins, **self._plugin_manifests}

    def _enabled(self, name: str) -> bool:
        if name in self._state.get("disabled", []):
            return False
        if name in self._plugin_manifests:
            entry = self._state["plugins"].get(name, {})
            return bool(entry.get("enabled")) and bool(entry.get("trusted"))
        return True

    def _availability(self, name: str, seen: frozenset[str] = frozenset()) -> tuple[bool, str | None]:
        manifests = self.manifests()
        if name not in manifests:
            return False, f"product '{name}' is not installed"
        if not self._enabled(name):
            return False, f"product '{name}' is disabled"
        for dep in manifests[name].depends_on:
            if dep in seen:
                continue
            ok, _reason = self._availability(dep, seen | {name})
            if not ok:
                return False, f"requires '{dep}', which is unavailable"
        return True, None

    def info(self, name: str) -> ProductInfo:
        manifests = self.manifests()
        if name not in manifests:
            raise NotFoundError(f"Unknown product '{name}'.", suggestions=["raf products"])
        available, reason = self._availability(name)
        is_plugin = name in self._plugin_manifests
        trusted = bool(self._state["plugins"].get(name, {}).get("trusted")) if is_plugin else True
        return ProductInfo(
            manifests[name], self._enabled(name), available, "plugin" if is_plugin else "builtin", trusted, reason
        )

    def products(self) -> list[ProductInfo]:
        return [self.info(name) for name in self.manifests()]

    def is_available(self, name: str) -> bool:
        return self._availability(name)[0]

    def require(self, name: str) -> ProductManifest:
        available, reason = self._availability(name)
        if not available:
            raise ProductDisabledError(
                f"R$F {name.title()} is not available.", reason=reason, suggestions=[f"raf product enable {name}"]
            )
        return self.manifests()[name]

    def dependents(self, name: str) -> list[str]:
        return sorted(n for n, m in self.manifests().items() if name in m.depends_on)

    # ------------------------------------------------------------------ mutations
    def enable(self, name: str) -> ProductInfo:
        info = self.info(name)
        if info.source == "plugin" and not info.trusted:
            raise ConflictError(f"Plugin '{name}' is not trusted yet.", suggestions=[f"raf plugin trust {name}"])
        disabled = set(self._state.get("disabled", []))
        disabled.discard(name)
        self._state["disabled"] = sorted(disabled)
        if info.source == "plugin":
            self._state["plugins"][name]["enabled"] = True
        self._write_state()
        return self.info(name)

    def disable(self, name: str) -> ProductInfo:
        self.info(name)
        disabled = set(self._state.get("disabled", []))
        disabled.add(name)
        self._state["disabled"] = sorted(disabled)
        if name in self._plugin_manifests:
            self._state["plugins"][name]["enabled"] = False
        self._write_state()
        return self.info(name)

    def install_plugin(self, source: Path) -> ProductInfo:
        source = source.expanduser()
        manifest_path = source / MANIFEST_FILE
        if not source.is_dir() or not manifest_path.exists():
            raise InvalidInputError(
                f"{source} is not an R$F plugin directory.", hint=f"A plugin directory contains {MANIFEST_FILE}."
            )
        manifest = load_manifest_file(manifest_path)
        if manifest.name in self._builtins:
            raise ConflictError(f"'{manifest.name}' is a built-in product name.")
        for path in source.rglob("*"):
            if path.is_symlink():
                raise SecurityViolation(f"Plugin contains a symlink ({path.relative_to(source)}); refusing to install.")
        target = self.home.plugins_dir / manifest.name
        if target.exists():
            raise ConflictError(
                f"Plugin '{manifest.name}' is already installed.", suggestions=[f"raf uninstall {manifest.name}"]
            )
        self.home.ensure()
        shutil.copytree(source, target, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".git"))
        self._state["plugins"][manifest.name] = {
            "version": manifest.version,
            "installed_at": format_ts(utcnow()),
            "source": str(source),
            "sha256": directory_hash(target),
            "trusted": False,
            "enabled": False,
        }
        self._write_state()
        self._plugin_manifests[manifest.name] = manifest
        self._check_dependencies()
        return self.info(manifest.name)

    def trust_plugin(self, name: str) -> ProductInfo:
        if name not in self._plugin_manifests:
            raise NotFoundError(f"Plugin '{name}' is not installed.")
        entry = self._state["plugins"][name]
        entry["sha256"] = directory_hash(self.home.plugins_dir / name)
        entry["trusted"] = True
        entry["enabled"] = True
        entry["trusted_at"] = format_ts(utcnow())
        self._write_state()
        return self.info(name)

    def uninstall_plugin(self, name: str) -> dict[str, Any]:
        if name in self._builtins:
            raise ConflictError(
                f"'{name}' is built in and cannot be uninstalled.", suggestions=[f"raf product disable {name}"]
            )
        if name not in self._state["plugins"]:
            raise NotFoundError(f"Plugin '{name}' is not installed.")
        target = self.home.plugins_dir / name
        if target.exists():
            if target.resolve().parent != self.home.plugins_dir.resolve():
                raise SecurityViolation("Refusing to remove a plugin outside the plugins directory.")
            shutil.rmtree(target)
        del self._state["plugins"][name]
        self._state["disabled"] = [d for d in self._state.get("disabled", []) if d != name]
        self._write_state()
        self._plugin_manifests.pop(name, None)
        return {"name": name, "removed": str(target)}

    def verify_plugin(self, name: str) -> bool:
        entry = self._state["plugins"].get(name)
        if not entry or not entry.get("trusted"):
            return False
        return bool(directory_hash(self.home.plugins_dir / name) == entry.get("sha256"))

    def load_plugin_attr(self, name: str, import_path: str) -> Any:
        """Import an attribute from a trusted, unmodified plugin."""
        if name not in self._plugin_manifests:
            raise NotFoundError(f"Plugin '{name}' is not installed.")
        if not self.verify_plugin(name):
            raise SecurityViolation(
                f"Plugin '{name}' is not trusted or was modified after it was trusted.",
                hint=f"Review the plugin, then run: raf plugin trust {name}",
            )
        plugin_dir = str(self.home.plugins_dir / name)
        if plugin_dir not in sys.path:
            sys.path.insert(0, plugin_dir)
        module_name, attr = import_path.split(":", 1)
        module = importlib.import_module(module_name)
        return getattr(module, attr)
