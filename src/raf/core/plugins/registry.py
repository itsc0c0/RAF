"""Local product registry (built-in products + installed plugins).

State lives in ``RAF_HOME/registry.json``. A remote registry is an explicit
future extension point (:class:`RemoteRegistry`); R$F works without one.

Plugin trust model: installing a plugin copies it but leaves it disabled.
``raf plugin trust`` records the SHA-256 of the plugin's files; R$F only loads a
plugin whose files still match that hash, imports its modules from source only
(:mod:`raf.core.plugins.loader`, so cached bytecode never runs) and reports a
plugin whose files changed as unavailable. Python plugins run in-process with
R$F's privileges: trust is the only security boundary. The permissions a
manifest declares are shown for review; nothing enforces them.

A product whose code fails to load (a syntax error, an exception at import time,
an object of the wrong kind) is reported unavailable for the rest of the process
instead of breaking the CLI or the API (:meth:`ProductRegistry.load_attr`).
"""

from __future__ import annotations

import hashlib
import importlib
import json
import logging
import os
import shutil
import threading
from abc import ABC, abstractmethod
from collections import deque
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from raf.core.errors import (
    ConflictError,
    DependencyUnavailableError,
    InvalidInputError,
    NotFoundError,
    ProductDisabledError,
    RafError,
    SecurityViolation,
)
from raf.core.plugins.loader import add_plugin_path
from raf.core.plugins.manifest import ProductManifest, is_product_name, load_manifest_file
from raf.core.timeutil import format_ts, utcnow
from raf.core.workspace.manager import RafHome

log = logging.getLogger("raf.registry")

MANIFEST_FILE = "raf-plugin.yaml"
_NOT_COPIED = frozenset({"__pycache__", ".git"})  # with *.pyc: left out of an installed copy

_Signature = tuple[tuple[str, int, int, int, int], ...]


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


@dataclass(frozen=True, slots=True)
class _Status:
    """Whether a product is available; if not, why and what the operator can do about it."""

    available: bool
    reason: str | None = None
    hint: str | None = None
    suggestions: tuple[str, ...] = ()
    error: type[RafError] = ProductDisabledError


_AVAILABLE = _Status(True)


def _raise(error: OSError) -> None:
    raise error


def _plugin_files(root: Path) -> list[Path]:
    """The regular files of a plugin directory outside ``__pycache__``, in hashing order.

    Symbolic links (to files or directories) and special files are refused: the hash could not
    vouch for what they lead to. An unreadable directory raises :class:`OSError`.
    """
    if root.is_symlink():
        raise SecurityViolation(f"The plugin directory {root.name} is a symlink.")
    if not root.is_dir():
        raise FileNotFoundError(f"plugin directory {root} does not exist")
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, onerror=_raise):
        base = Path(dirpath)
        for name in [*dirnames, *filenames]:
            if (base / name).is_symlink():
                raise SecurityViolation(f"Plugin contains a symlink: {(base / name).relative_to(root)}")
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for name in filenames:
            path = base / name
            if not path.is_file():
                raise SecurityViolation(f"Plugin contains a special file: {path.relative_to(root)}")
            files.append(path)
    return sorted(files)


def directory_hash(root: Path) -> str:
    """SHA-256 over relative paths and contents of every regular file under ``root``.

    ``__pycache__`` directories are not covered: plugin modules are compiled from source and
    cached bytecode is never read (:mod:`raf.core.plugins.loader`). Symbolic links and special
    files raise :class:`SecurityViolation`.
    """
    hasher = hashlib.sha256()
    for path in _plugin_files(root):
        hasher.update(path.relative_to(root).as_posix().encode())
        hasher.update(b"\0")
        hasher.update(path.read_bytes())
        hasher.update(b"\0")
    return hasher.hexdigest()


def _tree_signature(root: Path) -> _Signature:
    """A cheap fingerprint of a plugin's files (any write changes a file's ctime) to cache hashes."""
    rows = []
    for path in _plugin_files(root):
        st = path.stat()
        rows.append((path.relative_to(root).as_posix(), st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_ino))
    return tuple(rows)


def _dependency_cycle(start: str, manifests: Mapping[str, ProductManifest]) -> list[str] | None:
    """The shortest dependency chain from ``start`` back to itself (``[a, b, a]``), if any."""
    parent: dict[str, str] = {}
    queue: deque[str] = deque([start])
    while queue:
        node = queue.popleft()
        for dep in manifests[node].depends_on if node in manifests else ():
            if dep == start:
                chain = [node]
                while chain[-1] != start:
                    chain.append(parent[chain[-1]])
                return [*reversed(chain), start]
            if dep not in parent:
                parent[dep] = node
                queue.append(dep)
    return None


def _describe(exc: BaseException) -> str:
    text = " ".join(str(exc).split())
    return (f"{type(exc).__name__}: {text}" if text else type(exc).__name__)[:300]


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
        self._lock = threading.RLock()
        self._state_signature: tuple[int, ...] | None = None
        self._state = self._read_state()
        self._plugin_manifests = self._discover_plugins()
        self._cycles: dict[str, list[str]] = {}
        self._load_failures: dict[str, str] = {}  # this process only: code that failed to load
        self._hash_cache: dict[str, tuple[_Signature, str]] = {}
        self._check_dependencies()

    # ------------------------------------------------------------------ state
    def _registry_signature(self) -> tuple[int, ...] | None:
        try:
            st = self.home.registry_path.stat()
        except OSError:
            return None
        return (st.st_mtime_ns, st.st_ctime_ns, st.st_size, st.st_ino)

    def _read_state(self) -> dict[str, Any]:
        self._state_signature = self._registry_signature()
        try:
            data = json.loads(self.home.registry_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {"disabled": [], "plugins": {}}
        except (OSError, ValueError):
            log.warning("registry state unreadable; using defaults")
            return {"disabled": [], "plugins": {}}
        if not isinstance(data, dict):
            log.warning("registry state is not a JSON object; using defaults")
            return {"disabled": [], "plugins": {}}
        if not isinstance(data.get("disabled"), list):
            data["disabled"] = []
        plugins = data.get("plugins")
        data["plugins"] = {k: v for k, v in plugins.items() if isinstance(v, dict)} if isinstance(plugins, dict) else {}
        return data

    def _write_state(self) -> None:
        self.home.ensure()
        tmp = self.home.registry_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._state, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(self.home.registry_path)
        self._state_signature = self._registry_signature()

    def refresh(self) -> None:
        """Re-read ``registry.json`` when another process changed it (``raf product disable`` while
        ``raf serve`` runs, for example). Costs one ``stat`` when nothing changed."""
        if self._registry_signature() == self._state_signature:
            return
        with self._lock:
            if self._registry_signature() == self._state_signature:
                return
            self._state = self._read_state()
            self._plugin_manifests = self._discover_plugins()
            self._check_dependencies()

    def _discover_plugins(self) -> dict[str, ProductManifest]:
        manifests: dict[str, ProductManifest] = {}
        for name in sorted(self._state.get("plugins", {})):
            if not is_product_name(name) or name in self._builtins:
                log.warning("registry.json lists an invalid plugin name %r; ignoring it", name)
                continue
            path = self.home.plugins_dir / name / MANIFEST_FILE
            if not path.exists():
                log.warning("plugin %s is registered but missing on disk", name)
                continue
            try:
                manifest = load_manifest_file(path)
            except InvalidInputError as exc:
                log.warning("plugin %s has an invalid manifest: %s", name, exc)
                continue
            if manifest.name != name:
                log.warning("plugin %s: its manifest is named %r; ignoring it", name, manifest.name)
                continue
            manifests[name] = manifest
        return manifests

    def _check_dependencies(self) -> None:
        """Find dependency cycles. A cycle among built-in products is a bug in R$F and raises; a
        plugin on a cycle is reported unavailable, so that ``raf uninstall`` still works."""
        manifests = self.manifests()
        cycles: dict[str, list[str]] = {}
        for name in manifests:
            cycle = _dependency_cycle(name, manifests)
            if cycle is None:
                continue
            if not any(member in self._plugin_manifests for member in cycle):
                raise InvalidInputError("Product dependency cycle: " + " -> ".join(cycle))
            log.warning("plugin %s is unavailable: dependency cycle %s", name, " -> ".join(cycle))
            cycles[name] = cycle
        self._cycles = cycles

    # ------------------------------------------------------------------ queries
    def manifests(self) -> dict[str, ProductManifest]:
        return {**self._builtins, **self._plugin_manifests}

    def is_plugin(self, name: str) -> bool:
        return name in self._plugin_manifests

    def _enabled(self, name: str) -> bool:
        if name in self._state.get("disabled", []):
            return False
        if name in self._plugin_manifests:
            entry = self._state["plugins"].get(name, {})
            return bool(entry.get("enabled")) and bool(entry.get("trusted"))
        return True

    def _integrity_problem(self, name: str) -> str | None:
        """Why a trusted plugin's files no longer match the trusted hash (hashes cached per file signature)."""
        root = self.home.plugins_dir / name
        try:
            signature = _tree_signature(root)
            cached = self._hash_cache.get(name)
            if cached is not None and cached[0] == signature:
                digest = cached[1]
            else:
                digest = directory_hash(root)
                self._hash_cache[name] = (signature, digest)
        except SecurityViolation as exc:
            return f"plugin '{name}' failed its integrity check: {exc.message}"
        except OSError as exc:
            return f"the files of plugin '{name}' cannot be read: {exc.strerror or exc}"
        if digest != self._state["plugins"].get(name, {}).get("sha256"):
            return f"plugin '{name}' was modified after it was trusted"
        return None

    def _status(self, name: str, seen: frozenset[str] = frozenset(), *, dependencies: bool = True) -> _Status:
        manifests = self.manifests()
        if name not in manifests:
            return _Status(False, f"product '{name}' is not installed", suggestions=("raf products",))
        plugin = name in self._plugin_manifests
        if name in self._cycles:
            return _Status(
                False,
                "dependency cycle: " + " -> ".join(self._cycles[name]),
                hint="Fix depends_on in the plugin's raf-plugin.yaml, then install it again.",
                suggestions=(f"raf uninstall {name}",),
            )
        if plugin and not self._state["plugins"].get(name, {}).get("trusted"):
            return _Status(
                False,
                f"plugin '{name}' is not trusted yet",
                hint=f"Review its files in {self.home.plugins_dir / name} first: a trusted plugin runs with "
                "your privileges.",
                suggestions=(f"raf plugin trust {name}",),
            )
        if not self._enabled(name):
            return _Status(False, f"product '{name}' is disabled", suggestions=(f"raf product enable {name}",))
        if plugin and (problem := self._integrity_problem(name)) is not None:
            return _Status(
                False,
                problem,
                hint=f"Review the plugin, then run: raf plugin trust {name}",
                suggestions=(f"raf plugin verify {name}",),
                error=SecurityViolation,
            )
        if name in self._load_failures:
            if plugin:
                hint = f"Fix the plugin and trust it again (raf plugin trust {name}); restart a running raf serve."
                return _Status(False, self._load_failures[name], hint, (f"raf product disable {name}",))
            return _Status(False, self._load_failures[name], "This is a bug in R$F; the log has the details.")
        if dependencies:
            for dep in manifests[name].depends_on:
                if dep in seen:
                    continue
                status = self._status(dep, seen | {name})
                if not status.available:
                    return _Status(False, f"requires '{dep}', which is unavailable", status.hint, status.suggestions)
        return _AVAILABLE

    def info(self, name: str) -> ProductInfo:
        manifests = self.manifests()
        if name not in manifests:
            raise NotFoundError(f"Unknown product '{name}'.", suggestions=["raf products"])
        status = self._status(name)
        is_plugin = name in self._plugin_manifests
        trusted = bool(self._state["plugins"].get(name, {}).get("trusted")) if is_plugin else True
        return ProductInfo(
            manifests[name],
            self._enabled(name),
            status.available,
            "plugin" if is_plugin else "builtin",
            trusted,
            status.reason,
        )

    def products(self) -> list[ProductInfo]:
        return [self.info(name) for name in self.manifests()]

    def is_available(self, name: str) -> bool:
        return self._status(name).available

    def _unavailable_error(self, name: str, status: _Status) -> RafError:
        error = status.error(
            f"R$F {name.title()} is not available.",
            reason=status.reason,
            hint=status.hint,
            suggestions=status.suggestions,
        )
        # Over HTTP an unavailable product answers 503, like any other unavailable dependency.
        error.http_status = DependencyUnavailableError.http_status
        return error

    def require(self, name: str) -> ProductManifest:
        """The manifest of an available product; otherwise raises why it is unavailable, with the
        commands that fix it (CLI exit 4, or 5 for a plugin that fails its integrity check; HTTP 503)."""
        status = self._status(name)
        if not status.available:
            raise self._unavailable_error(name, status)
        return self.manifests()[name]

    def dependents(self, name: str) -> list[str]:
        return sorted(n for n, m in self.manifests().items() if name in m.depends_on)

    # ------------------------------------------------------------------ loading product code
    def mark_unavailable(self, name: str, reason: str) -> None:
        """Report a product unavailable for the rest of this process (its code failed to load)."""
        if name not in self._load_failures:
            log.warning("product %s is unavailable: %s", name, reason)
            self._load_failures[name] = reason

    def load_attr[T](self, name: str, import_path: str, convert: Callable[[Any], T]) -> T:
        """Load ``module.path:attribute`` contributed by product ``name`` and pass it through ``convert``
        (which raises when the object is not of the expected kind).

        Plugin code is loaded only from a trusted, enabled and unmodified plugin, from source only
        (:meth:`load_plugin_attr`). Any failure - an integrity mismatch, a syntax error, an exception
        raised while importing, an object of the wrong kind - marks the product unavailable for the
        rest of the process (logged) and raises its unavailability error, so that callers skip the
        contribution: a broken product never breaks the platform.
        """
        if name in self._plugin_manifests:
            gate = self._status(name, dependencies=False)
            if not gate.available:
                raise self._unavailable_error(name, gate)
        try:
            if name in self._plugin_manifests:
                value = self.load_plugin_attr(name, import_path)
            else:
                module_name, attr = import_path.split(":", 1)
                value = getattr(importlib.import_module(module_name), attr)
            return convert(value)
        except (Exception, SystemExit) as exc:  # product code must never break the platform
            log.info("loading %s from %s failed", import_path, name, exc_info=exc, extra={"file_only": True})
            self.mark_unavailable(name, f"failed to load {import_path}: {_describe(exc)}")
            raise self._unavailable_error(name, self._status(name)) from exc

    def load_plugin_attr(self, name: str, import_path: str) -> Any:
        """Import an attribute from a trusted, unmodified plugin; its modules are compiled from source."""
        if name not in self._plugin_manifests:
            raise NotFoundError(f"Plugin '{name}' is not installed.")
        if not self.verify_plugin(name):
            raise SecurityViolation(
                f"Plugin '{name}' is not trusted or was modified after it was trusted.",
                hint=f"Review the plugin, then run: raf plugin trust {name}",
            )
        add_plugin_path(self.home.plugins_dir / name)
        module_name, attr = import_path.split(":", 1)
        module = importlib.import_module(module_name)
        return getattr(module, attr)

    def verify_plugin(self, name: str) -> bool:
        """Whether a trusted plugin's files still match its trusted hash (False when it is not trusted).

        Raises :class:`SecurityViolation` when the plugin directory contains a symbolic link or a
        special file."""
        entry = self._state["plugins"].get(name)
        if not entry or not entry.get("trusted"):
            return False
        try:
            return bool(directory_hash(self.home.plugins_dir / name) == entry.get("sha256"))
        except OSError:
            return False

    # ------------------------------------------------------------------ mutations
    def enable(self, name: str) -> ProductInfo:
        info = self.info(name)
        if info.source == "plugin" and not info.trusted:
            raise ConflictError(f"Plugin '{name}' is not trusted yet.", suggestions=[f"raf plugin trust {name}"])
        with self._lock:
            disabled = set(self._state.get("disabled", []))
            disabled.discard(name)
            self._state["disabled"] = sorted(disabled)
            if info.source == "plugin":
                self._state["plugins"][name]["enabled"] = True
            self._write_state()
        return self.info(name)

    def disable(self, name: str) -> ProductInfo:
        self.info(name)
        with self._lock:
            disabled = set(self._state.get("disabled", []))
            disabled.add(name)
            self._state["disabled"] = sorted(disabled)
            if name in self._plugin_manifests:
                self._state["plugins"][name]["enabled"] = False
            self._write_state()
        return self.info(name)

    def _validate_dependencies(self, manifest: ProductManifest) -> None:
        manifests = {**self.manifests(), manifest.name: manifest}
        missing = [dep for dep in manifest.depends_on if dep not in manifests]
        if missing:
            raise InvalidInputError(
                f"Plugin '{manifest.name}' depends on {', '.join(repr(dep) for dep in missing)}, which "
                + ("is" if len(missing) == 1 else "are")
                + " not installed.",
                hint="Install the products it depends on first.",
                suggestions=["raf products"],
            )
        cycle = _dependency_cycle(manifest.name, manifests)
        if cycle is not None:
            raise InvalidInputError(
                "Product dependency cycle: " + " -> ".join(cycle),
                hint="A product cannot depend on itself, directly or through other products: fix depends_on.",
            )

    def _validate_commands(self, manifest: ProductManifest, reserved: Collection[str]) -> None:
        if not manifest.cli:
            return
        taken = {
            command: owner for owner, m in self.manifests().items() if m.cli for command in (m.commands or [owner])
        }
        for command in manifest.commands or [manifest.name]:
            if command in reserved or command in taken:
                owner = "R$F itself" if command in reserved else f"product '{taken[command]}'"
                raise ConflictError(
                    f"Plugin '{manifest.name}' declares the command '{command}', which {owner} already provides.",
                    hint=f"Rename the command in {MANIFEST_FILE} (commands: [...]).",
                )

    def install_plugin(self, source: Path, reserved_commands: Collection[str] = ()) -> ProductInfo:
        """Copy a plugin directory to ``RAF_HOME/plugins/<name>`` (disabled and untrusted).

        Everything is validated before anything is written: the manifest, symbolic links, the
        dependencies (installed, no cycle) and the command names (a plugin cannot take a command
        that R$F itself - ``reserved_commands`` - or another product already provides).
        """
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
            copied = not _NOT_COPIED.intersection(path.relative_to(source).parts) and path.suffix != ".pyc"
            if copied and not path.is_file() and not path.is_dir():
                raise SecurityViolation(
                    f"Plugin contains a special file ({path.relative_to(source)}); refusing to install."
                )
        target = self.home.plugins_dir / manifest.name
        if target.exists():
            raise ConflictError(
                f"Plugin '{manifest.name}' is already installed.", suggestions=[f"raf uninstall {manifest.name}"]
            )
        self._validate_dependencies(manifest)
        self._validate_commands(manifest, reserved_commands)
        with self._lock:
            self.home.ensure()
            try:
                shutil.copytree(source, target, ignore=shutil.ignore_patterns(*_NOT_COPIED, "*.pyc"))
                digest = directory_hash(target)
            except BaseException:
                shutil.rmtree(target, ignore_errors=True)
                raise
            self._state["plugins"][manifest.name] = {
                "version": manifest.version,
                "installed_at": format_ts(utcnow()),
                "source": str(source.resolve()),
                "sha256": digest,
                "trusted": False,
                "enabled": False,
            }
            self._write_state()
            self._plugin_manifests[manifest.name] = manifest
            self._check_dependencies()
        return self.info(manifest.name)

    def trust_plugin(self, name: str) -> ProductInfo:
        """Record the hash of the plugin's current files, and enable it."""
        if name not in self._plugin_manifests:
            raise NotFoundError(f"Plugin '{name}' is not installed.")
        digest = directory_hash(self.home.plugins_dir / name)
        with self._lock:
            entry = self._state["plugins"][name]
            entry["sha256"] = digest
            entry["trusted"] = True
            entry["enabled"] = True
            entry["trusted_at"] = format_ts(utcnow())
            self._state["disabled"] = [d for d in self._state.get("disabled", []) if d != name]
            self._write_state()
            self._load_failures.pop(name, None)
            self._hash_cache.pop(name, None)
        return self.info(name)

    def uninstall_plugin(self, name: str) -> dict[str, Any]:
        if name in self._builtins:
            raise ConflictError(
                f"'{name}' is built in and cannot be uninstalled.", suggestions=[f"raf product disable {name}"]
            )
        if name not in self._state["plugins"]:
            raise NotFoundError(f"Plugin '{name}' is not installed.")
        target = self.home.plugins_dir / name
        with self._lock:
            # an invalid name in registry.json only loses its entry: never touch files outside plugins/
            if is_product_name(name) and target.exists():
                if target.resolve().parent != self.home.plugins_dir.resolve():
                    raise SecurityViolation("Refusing to remove a plugin outside the plugins directory.")
                shutil.rmtree(target)
            del self._state["plugins"][name]
            self._state["disabled"] = [d for d in self._state.get("disabled", []) if d != name]
            self._write_state()
            self._plugin_manifests.pop(name, None)
            self._load_failures.pop(name, None)
            self._hash_cache.pop(name, None)
            self._check_dependencies()
        return {"name": name, "removed": str(target)}
