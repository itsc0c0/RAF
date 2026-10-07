"""R$F home directory and workspaces.

``RAF_HOME`` (default ``~/.raf``) contains global configuration, product
registry state, plugins, logs and one directory per workspace. A workspace
isolates data, cases, findings, snapshots, evidence and configuration.
"""

from __future__ import annotations

import builtins
import contextlib
import json
import os
import re
import shutil
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from raf.core.errors import ConflictError, InvalidInputError, NotFoundError, SecurityViolation, WorkspaceError
from raf.core.timeutil import format_ts, utcnow
from raf.version import RAF_VERSION

WORKSPACE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
DEFAULT_WORKSPACE = "default"


def validate_workspace_name(name: str) -> str:
    candidate = name.strip()
    if not WORKSPACE_NAME_RE.match(candidate):
        raise InvalidInputError(
            f"Invalid workspace name '{name}'.",
            hint="Use 1-63 lowercase letters, digits, '-' or '_' (starting with a letter or digit).",
        )
    return candidate


@dataclass(frozen=True, slots=True)
class RafHome:
    root: Path

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> RafHome:
        env = os.environ if env is None else env
        raw = env.get("RAF_HOME")
        root = Path(raw).expanduser() if raw else Path.home() / ".raf"
        return cls(root.absolute())

    @property
    def workspaces_dir(self) -> Path:
        return self.root / "workspaces"

    @property
    def config_path(self) -> Path:
        return self.root / "config.toml"

    @property
    def state_path(self) -> Path:
        return self.root / "state.json"

    @property
    def registry_path(self) -> Path:
        return self.root / "registry.json"

    @property
    def plugins_dir(self) -> Path:
        return self.root / "plugins"

    @property
    def logs_dir(self) -> Path:
        return self.root / "logs"

    def ensure(self) -> None:
        for directory in (self.root, self.workspaces_dir, self.plugins_dir, self.logs_dir):
            directory.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError):  # e.g. not the owner
            self.root.chmod(0o700)

    def read_state(self) -> dict[str, Any]:
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, json.JSONDecodeError):
            return {}
        return data if isinstance(data, dict) else {}

    def write_state(self, state: dict[str, Any]) -> None:
        self.ensure()
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(self.state_path)


@dataclass(frozen=True, slots=True)
class Workspace:
    name: str
    path: Path

    @property
    def db_path(self) -> Path:
        return self.path / "raf.db"

    @property
    def config_path(self) -> Path:
        return self.path / "config.toml"

    @property
    def meta_path(self) -> Path:
        return self.path / "workspace.json"

    @property
    def evidence_dir(self) -> Path:
        return self.path / "evidence"

    @property
    def rejects_dir(self) -> Path:
        return self.path / "rejects"

    @property
    def uploads_dir(self) -> Path:
        return self.path / "uploads"

    @property
    def labs_dir(self) -> Path:
        return self.path / "labs"

    @property
    def exports_dir(self) -> Path:
        return self.path / "exports"

    @property
    def secrets_dir(self) -> Path:
        return self.path / "secrets"

    def ensure_dirs(self) -> None:
        for directory in (
            self.path,
            self.evidence_dir,
            self.rejects_dir,
            self.uploads_dir,
            self.labs_dir,
            self.exports_dir,
            self.secrets_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)
        self.secrets_dir.chmod(0o700)

    def metadata(self) -> dict[str, Any]:
        try:
            data = json.loads(self.meta_path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def disk_usage(self) -> int:
        total = 0
        for root, _dirs, files in os.walk(self.path):
            for name in files:
                try:
                    total += (Path(root) / name).lstat().st_size
                except OSError:
                    continue
        return total


@dataclass(frozen=True, slots=True)
class WorkspaceInfo:
    name: str
    path: str
    description: str
    created_at: str | None
    current: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "path": self.path,
            "description": self.description,
            "created_at": self.created_at,
            "current": self.current,
        }


class WorkspaceManager:
    def __init__(self, home: RafHome, env: Mapping[str, str] | None = None) -> None:
        self.home = home
        self.env = os.environ if env is None else env

    def _path(self, name: str) -> Path:
        return self.home.workspaces_dir / validate_workspace_name(name)

    def exists(self, name: str) -> bool:
        return (self._path(name) / "workspace.json").exists()

    def names(self) -> builtins.list[str]:
        if not self.home.workspaces_dir.exists():
            return []
        return sorted(
            p.name
            for p in self.home.workspaces_dir.iterdir()
            if p.is_dir() and (p / "workspace.json").exists() and WORKSPACE_NAME_RE.match(p.name)
        )

    def list(self) -> builtins.list[WorkspaceInfo]:
        current = self.current_name()
        infos = []
        for name in self.names():
            meta = Workspace(name, self._path(name)).metadata()
            infos.append(
                WorkspaceInfo(
                    name=name,
                    path=str(self._path(name)),
                    description=str(meta.get("description", "")),
                    created_at=meta.get("created_at"),
                    current=name == current,
                )
            )
        return infos

    def create(self, name: str, description: str = "") -> Workspace:
        name = validate_workspace_name(name)
        if self.exists(name):
            raise ConflictError(f"Workspace '{name}' already exists.", suggestions=[f"raf workspace use {name}"])
        self.home.ensure()
        ws = Workspace(name, self._path(name))
        ws.ensure_dirs()
        ws.meta_path.write_text(
            json.dumps(
                {
                    "name": name,
                    "description": description,
                    "created_at": format_ts(utcnow()),
                    "raf_version": RAF_VERSION,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return ws

    def get(self, name: str) -> Workspace:
        name = validate_workspace_name(name)
        if not self.exists(name):
            raise NotFoundError(
                f"Workspace '{name}' does not exist.",
                suggestions=[f"raf workspace create {name}", "raf workspace list"],
            )
        return Workspace(name, self._path(name))

    def current_name(self) -> str:
        explicit = self.env.get("RAF_WORKSPACE")
        if explicit:
            return validate_workspace_name(explicit)
        state = self.home.read_state()
        name = state.get("current_workspace")
        if isinstance(name, str) and WORKSPACE_NAME_RE.match(name):
            return name
        return DEFAULT_WORKSPACE

    def open(self, name: str | None = None) -> Workspace:
        """Open ``name`` (or the current workspace); the default workspace is created on demand."""
        target = validate_workspace_name(name) if name else self.current_name()
        if not self.exists(target):
            if target == DEFAULT_WORKSPACE:
                return self.create(DEFAULT_WORKSPACE, "Default workspace")
            return self.get(target)
        ws = Workspace(target, self._path(target))
        ws.ensure_dirs()
        return ws

    def use(self, name: str) -> Workspace:
        ws = self.get(name)
        state = self.home.read_state()
        state["current_workspace"] = ws.name
        self.home.write_state(state)
        return ws

    def delete(self, name: str) -> dict[str, Any]:
        ws = self.get(name)
        root = self.home.workspaces_dir.resolve()
        target = ws.path.resolve()
        if target.parent != root or ws.path.is_symlink():
            raise SecurityViolation("Refusing to delete a workspace outside RAF_HOME.", details={"path": str(ws.path)})
        summary = {"name": ws.name, "path": str(target), "bytes": ws.disk_usage()}

        def _on_error(func: Any, path: str, _exc: BaseException) -> None:
            Path(path).chmod(stat.S_IWRITE | stat.S_IREAD)
            func(path)

        shutil.rmtree(target, onexc=_on_error)
        state = self.home.read_state()
        if state.get("current_workspace") == ws.name:
            state["current_workspace"] = DEFAULT_WORKSPACE
            self.home.write_state(state)
        return summary

    def require_not_current_env(self, name: str) -> None:
        if self.env.get("RAF_WORKSPACE") == name:
            raise WorkspaceError(f"Workspace '{name}' is selected via RAF_WORKSPACE; unset it first.")
