"""Layered configuration resolution with origin tracking."""

from __future__ import annotations

import json
import logging
import os
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from raf.core.config.schema import KEY_INDEX, KEYS, ConfigKey, get_key
from raf.core.errors import ConfigError, DependencyUnavailableError

log = logging.getLogger("raf.config")

KEYRING_SERVICE = "raf"


@dataclass(frozen=True, slots=True)
class ConfigEntry:
    key: str
    value: Any
    origin: str  # default | global | workspace | env | override
    description: str
    secret: bool


def read_toml(path: Path) -> dict[str, Any]:
    """Read a TOML file into a flat ``section.key`` mapping."""
    if not path.exists():
        return {}
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(
            f"Could not read configuration file {path}.",
            reason=str(exc),
            hint="Fix the file or remove it to fall back to defaults.",
        ) from exc
    flat: dict[str, Any] = {}

    def walk(prefix: str, value: Any) -> None:
        if isinstance(value, dict):
            for k, v in value.items():
                walk(f"{prefix}.{k}" if prefix else str(k), v)
        else:
            flat[prefix] = value

    walk("", data)
    return flat


def _toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return repr(value)
    return json.dumps(str(value), ensure_ascii=False)


def write_toml(path: Path, flat: Mapping[str, Any]) -> None:
    """Atomically write a flat mapping as TOML (sections from the first key part)."""
    sections: dict[str, dict[str, Any]] = {}
    for key in sorted(flat):
        section, _, name = key.partition(".")
        sections.setdefault(section, {})[name] = flat[key]
    lines = ["# R$F configuration. Edit with 'raf config set'.", ""]
    for section, values in sections.items():
        lines.append(f"[{section}]")
        lines.extend(f"{name} = {_toml_value(value)}" for name, value in values.items())
        lines.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text("\n".join(lines), encoding="utf-8")
    tmp.chmod(0o600)
    tmp.replace(path)


class Settings:
    """Resolved configuration. Values are typed; every value knows its origin layer."""

    def __init__(self, entries: dict[str, ConfigEntry], env: Mapping[str, str]) -> None:
        self._entries = entries
        self._env = env

    def get(self, key: str) -> Any:
        get_key(key)
        return self._entries[key].value

    def __getitem__(self, key: str) -> Any:
        return self.get(key)

    def origin(self, key: str) -> str:
        return self._entries[key].origin

    def entries(self) -> list[ConfigEntry]:
        return [self._entries[k.key] for k in KEYS]

    def secret(self, key: str) -> str | None:
        """Resolve a secret from the environment or the OS keyring (never from files)."""
        spec = get_key(key)
        if not spec.secret:
            raise ConfigError(f"{key} is not a secret key.")
        value = self._env.get(spec.env_var)
        if value:
            return value
        return keyring_get(key)

    def with_overrides(self, overrides: Mapping[str, Any]) -> Settings:
        entries = dict(self._entries)
        for key, raw in overrides.items():
            spec = get_key(key)
            entries[key] = ConfigEntry(key, spec.coerce(raw), "override", spec.description, spec.secret)
        return Settings(entries, self._env)


def load_settings(
    global_path: Path | None,
    workspace_path: Path | None = None,
    *,
    env: Mapping[str, str] | None = None,
    overrides: Mapping[str, Any] | None = None,
) -> Settings:
    env = os.environ if env is None else env
    layers: list[tuple[str, dict[str, Any]]] = []
    if global_path is not None:
        layers.append(("global", read_toml(global_path)))
    if workspace_path is not None:
        layers.append(("workspace", read_toml(workspace_path)))
    entries: dict[str, ConfigEntry] = {}
    for spec in KEYS:
        value, origin = (None if spec.secret else spec.default), "default"
        for layer_name, layer in layers:
            if spec.key in layer:
                if spec.secret:
                    log.warning(
                        "ignoring secret %s found in %s config file; use %s or the keyring",
                        spec.key,
                        layer_name,
                        spec.env_var,
                    )
                    continue
                value, origin = spec.coerce(layer[spec.key]), layer_name
        if not spec.secret and spec.env_var in env:
            value, origin = spec.coerce(env[spec.env_var]), "env"
        if spec.secret and env.get(spec.env_var):
            origin = "env"
        entries[spec.key] = ConfigEntry(spec.key, value, origin, spec.description, spec.secret)
    for layer_name, layer in layers:
        for unknown in sorted(set(layer) - set(KEY_INDEX)):
            log.warning("unknown configuration key %s in %s config (ignored)", unknown, layer_name)
    settings = Settings(entries, env)
    return settings.with_overrides(overrides) if overrides else settings


def set_value(path: Path, key: str, raw: Any) -> Any:
    spec = get_key(key)
    if spec.secret:
        raise ConfigError(
            f"{key} is a secret and is never stored in plaintext configuration.",
            hint=f"Set the {spec.env_var} environment variable, or store it in the OS keyring with "
            f"'raf secret set {key}'.",
        )
    value = spec.coerce(raw)
    flat = read_toml(path)
    flat[key] = value
    write_toml(path, flat)
    return value


def unset_value(path: Path, key: str) -> bool:
    get_key(key)
    flat = read_toml(path)
    if key not in flat:
        return False
    del flat[key]
    write_toml(path, flat)
    return True


# --------------------------------------------------------------------------- keyring


def _keyring() -> Any:
    try:
        import keyring
    except ImportError as exc:
        raise DependencyUnavailableError(
            "The OS keyring integration is not installed.",
            hint="Install it with: pip install 'raf[keyring]' - or provide the secret via environment variable.",
        ) from exc
    return keyring


def keyring_get(key: str) -> str | None:
    try:
        kr = _keyring()
    except DependencyUnavailableError:
        return None
    try:
        value = kr.get_password(KEYRING_SERVICE, key)
    except Exception:  # noqa: BLE001 - any keyring backend failure means "not available"
        return None
    return str(value) if value else None


def keyring_set(key: str, value: str) -> None:
    spec: ConfigKey = get_key(key)
    if not spec.secret:
        raise ConfigError(f"{key} is not a secret; use 'raf config set'.")
    kr = _keyring()
    try:
        kr.set_password(KEYRING_SERVICE, key, value)
    except Exception as exc:
        raise DependencyUnavailableError("The OS keyring rejected the secret.", reason=str(exc)) from exc


def keyring_delete(key: str) -> bool:
    kr = _keyring()
    try:
        kr.delete_password(KEYRING_SERVICE, key)
    except Exception:  # noqa: BLE001
        return False
    return True
