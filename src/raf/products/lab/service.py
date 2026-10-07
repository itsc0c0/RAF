"""R$F Lab service: lab definitions, input validation and the container lifecycle.

A lab is a definition stored in the workspace (key-value namespace ``lab``) plus, from its
first ``start`` on, one container created with the secure defaults of
:func:`raf.products.lab.backend.build_create_argv`. ``create`` only validates and records the
definition; Docker or Podman is needed from ``start`` on. State-changing operations and
commands run in a lab are recorded in the workspace audit log.
"""

from __future__ import annotations

import contextlib
import logging
import os
import re
import stat
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, ValidationError, field_validator, model_validator

from raf.core.context.app import RafContext
from raf.core.context.refs import ContextRefs
from raf.core.errors import (
    ConfigError,
    ConflictError,
    DependencyUnavailableError,
    IntegrityError,
    InvalidInputError,
    NotFoundError,
    RafError,
    ResourceLimitExceeded,
    SecurityViolation,
)
from raf.core.objects.models import RafModel
from raf.core.timeutil import format_ts, utcnow
from raf.products.lab.backend import (
    BACKEND_HINT,
    BACKEND_NAMES,
    CONTAINER_ID_RE,
    DEFAULT_IMAGE,
    LAB_NAME_RE,
    NETWORK_ISOLATED,
    NETWORK_OUTBOUND,
    ROOT_USER,
    UNPRIVILEGED_USER,
    ContainerSpec,
    ContainerState,
    ExecResult,
    LabBackend,
    LabBackendError,
    MountSpec,
    build_create_argv,
    container_name,
    get_backend,
    is_lab_input_target,
    lab_input_target,
    mount_text_problem,
    normalize_cpus,
    normalize_memory,
    terminal_safe,
    validate_backend_choice,
    validate_image,
    validate_pids_limit,
)

log = logging.getLogger("raf.lab")

NAMESPACE = "lab"
MAX_MOUNTS = 8
MAX_DESCRIPTION = 500
MOUNT_SCAN_LIMIT = 100_000
EXEC_DEFAULT_TIMEOUT = 60
EXEC_MAX_TIMEOUT = 3600
EXEC_DEFAULT_OUTPUT_KB = 1024
EXEC_MAX_OUTPUT_KB = 16 * 1024
EXEC_MAX_ARGS = 256
EXEC_MAX_COMMAND_BYTES = 64 * 1024

OUTBOUND_WARNING = (
    "outbound network access enabled (--network bridge): the lab can reach the host's networks and the internet"
)
ROOT_WARNING = "the lab runs as root (uid 0) inside the container; all capabilities stay dropped"

#: Refused together with everything below them and every directory that contains them.
SENSITIVE_TREES = (
    "/etc",
    "/proc",
    "/sys",
    "/dev",
    "/boot",
    "/run",
    "/var/run",
    "/var/lib/docker",
    "/var/lib/containers",
)
#: Refused as a whole (too broad to share with a lab); their subdirectories may be mounted.
BROAD_DIRECTORIES = ("/", "/tmp", "/var/tmp")  # noqa: S108 - paths that are refused, never used
#: Credential stores in the home directory, protected like SENSITIVE_TREES.
HOME_CREDENTIAL_DIRS = (
    ".ssh",
    ".gnupg",
    ".aws",
    ".azure",
    ".kube",
    ".docker",
    ".config/gcloud",
    ".local/share/containers",
)
RUNTIME_SOCKETS = frozenset({"docker.sock", "podman.sock"})

_LAB_ID_RE = re.compile(r"[0-9a-f]{32}")
_STATE_RE = re.compile(r"[a-z][a-z-]{0,23}")
_DESCRIPTION_BAD_RE = re.compile(r"[\x00-\x1f\x7f]")


# --------------------------------------------------------------------------- input validation


def validate_lab_name(name: str) -> str:
    text = name if isinstance(name, str) else ""
    if not LAB_NAME_RE.fullmatch(text):
        raise InvalidInputError(
            f"Invalid lab name '{terminal_safe(str(name))[:80]}'.",
            hint="Use 2-41 characters: lowercase letters, digits and '-', starting with a letter or digit "
            "(for example protocol-test).",
        )
    return text


def validate_description(text: str) -> str:
    value = text.strip()
    if len(value) > MAX_DESCRIPTION:
        raise InvalidInputError(f"The description is longer than {MAX_DESCRIPTION} characters.")
    if _DESCRIPTION_BAD_RE.search(value):
        raise InvalidInputError("The description must be a single line without control characters.")
    return value


def validate_command(argv: Sequence[str]) -> list[str]:
    """A command for ``exec``: an argument vector, never a shell string."""
    command = [str(arg) for arg in argv]
    if not command:
        raise InvalidInputError("No command given.", hint="raf lab exec NAME -- CMD [ARGS...]")
    if len(command) > EXEC_MAX_ARGS:
        raise InvalidInputError(f"Too many arguments ({len(command)}); at most {EXEC_MAX_ARGS}.")
    if any("\x00" in arg for arg in command):
        raise InvalidInputError("Command arguments must not contain NUL bytes.")
    if sum(len(arg.encode("utf-8", "surrogateescape")) for arg in command) > EXEC_MAX_COMMAND_BYTES:
        raise InvalidInputError(f"The command line is longer than {EXEC_MAX_COMMAND_BYTES // 1024} KB.")
    return command


def home_directory() -> Path | None:
    try:
        return Path.home().absolute()
    except (RuntimeError, KeyError, OSError):
        return None


def _variants(path: Path) -> set[Path]:
    """The path as written and as resolved (``/var/run`` is usually ``/run``)."""
    found = {path}
    with contextlib.suppress(OSError, RuntimeError):
        found.add(path.resolve())
    return found


def _refuse(shown: str, why: str, hint: str | None = None) -> SecurityViolation:
    return SecurityViolation(
        f"Refusing to mount {shown}: {why}.",
        hint=hint or "Mount a dedicated directory that contains only the files the experiment needs.",
    )


def _check_location(resolved: Path, shown: str, *, raf_home: Path, home: Path | None) -> None:
    home_variants = _variants(home) if home is not None else set()
    if resolved in home_variants:
        raise _refuse(shown, "your home directory is too broad to share with a lab")
    for broad in BROAD_DIRECTORIES:
        if resolved in _variants(Path(broad)):
            raise _refuse(shown, f"{broad} is too broad to share with a lab")
    protected: list[tuple[Path, str]] = [(Path(tree), tree) for tree in SENSITIVE_TREES]
    protected.append((raf_home, "the R$F home directory"))
    if home is not None:
        protected += [(home / sub, f"~/{sub}") for sub in HOME_CREDENTIAL_DIRS]
    for tree, label in protected:
        for variant in _variants(tree):
            if resolved == variant:
                raise _refuse(shown, f"it is {label}, a protected location")
            if resolved.is_relative_to(variant):
                raise _refuse(shown, f"it is inside {label}, a protected location")
            if variant.is_relative_to(resolved):
                raise _refuse(shown, f"it contains {label}, a protected location")


def _scan_directory(root: Path, shown: str, *, limit: int) -> None:
    """Refuse directories that contain runtime sockets, any unix socket or device files.

    A read-only bind mount does not stop a process from connecting to a unix socket, so a
    socket inside a mounted directory would be a channel from the lab to a host service.
    Symlinks are not followed: inside the container they resolve within the container.
    """
    pending = [root]
    seen = 0
    while pending:
        current = pending.pop()
        try:
            with os.scandir(current) as iterator:
                entries = list(iterator)
        except OSError as exc:
            raise _refuse(
                shown,
                f"{terminal_safe(str(current))[:200]} cannot be read, so it cannot be checked",
                "Mount a directory you can read completely.",
            ) from exc
        for entry in entries:
            seen += 1
            if seen > limit:
                raise ResourceLimitExceeded(
                    f"Refusing to mount {shown}: it contains more than {limit:,} entries.",
                    hint="Mount a narrower directory (R$F checks every entry for sockets and device files).",
                )
            relative = terminal_safe(str(Path(entry.path).relative_to(root)))[:200]
            if entry.name.lower() in RUNTIME_SOCKETS:
                raise _refuse(shown, f"it contains {relative}; container runtime sockets are never mounted into labs")
            try:
                mode = entry.stat(follow_symlinks=False).st_mode
            except OSError as exc:
                raise _refuse(shown, f"{relative} cannot be inspected", "Mount a directory you can read.") from exc
            if stat.S_ISSOCK(mode) or stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
                kind = "a unix socket" if stat.S_ISSOCK(mode) else "a device file"
                raise _refuse(
                    shown,
                    f"it contains {kind} ({relative})",
                    "Sockets and device files would give the lab a channel to host services; "
                    "mount a directory without them.",
                )
            if stat.S_ISDIR(mode):
                pending.append(Path(entry.path))


def validate_mount_source(
    raw: str,
    *,
    raf_home: Path,
    home: Path | None,
    require_absolute: bool = False,
    scan_limit: int = MOUNT_SCAN_LIMIT,
) -> Path:
    """Validate a host path for a read-only lab mount and return it fully resolved.

    Refused: missing paths, paths containing ',' ':' quotes or control characters (before and
    after resolving symlinks), container runtime sockets, anything that is not a regular file
    or directory, '/', '/tmp', '/var/tmp', the home directory itself, system locations
    (SENSITIVE_TREES), the R$F home, credential directories in the home directory, any
    directory containing one of those, and directories containing sockets or device files.
    """
    text = str(raw)
    shown = terminal_safe(text)[:200] or "''"
    if not text.strip():
        raise InvalidInputError("Empty mount path.", hint="raf lab create NAME --mount ./samples")
    problem = mount_text_problem(text)
    if problem:
        raise _refuse(shown, problem, "Rename the file or directory, or copy it to a plain path.")
    path = Path(text).expanduser()
    if path.name.lower() in RUNTIME_SOCKETS:
        raise _refuse(shown, "container runtime sockets are never mounted into labs")
    if not path.is_absolute():
        if require_absolute:
            raise InvalidInputError(
                f"Mount path {shown} must be absolute.", hint="Paths are resolved on the R$F server; use /full/path."
            )
        path = Path.cwd() / path
    try:
        resolved = path.resolve(strict=True)
    except FileNotFoundError as exc:
        raise NotFoundError(f"Mount path {shown} does not exist.", hint="Mount an existing file or directory.") from exc
    except (OSError, RuntimeError) as exc:
        raise InvalidInputError(f"Cannot resolve mount path {shown}.", reason=str(exc)) from exc
    problem = mount_text_problem(str(resolved))
    if problem:
        raise _refuse(shown, f"it resolves to {terminal_safe(str(resolved))[:200]} ({problem})")
    if resolved.name.lower() in RUNTIME_SOCKETS:
        raise _refuse(shown, "it resolves to a container runtime socket; those are never mounted into labs")
    _check_location(resolved, shown, raf_home=raf_home, home=home)
    try:
        mode = resolved.stat().st_mode
    except OSError as exc:
        raise InvalidInputError(f"Cannot access mount path {shown}.", reason=str(exc)) from exc
    if stat.S_ISDIR(mode):
        _scan_directory(resolved, shown, limit=scan_limit)
    elif not stat.S_ISREG(mode):
        raise _refuse(shown, "only regular files and directories can be mounted (this is a socket, device or pipe)")
    return resolved


def _validated[T](parse: Callable[[Any], T], value: Any) -> T:
    """Run an R$F validator inside a pydantic validator (which expects ValueError)."""
    try:
        return parse(value)
    except RafError as exc:
        raise ValueError(exc.message) from exc


def _from_setting[T](key: str, value: Any, parse: Callable[[Any], T]) -> T:
    try:
        return parse(value)
    except InvalidInputError as exc:
        raise ConfigError(
            f"Invalid {key} setting.", reason=exc.message, hint=f"Fix it with: raf config set {key} <value>"
        ) from exc


# --------------------------------------------------------------------------- definitions


class LabMount(RafModel):
    """A host path mounted read-only at ``target`` (always /lab/input/<name>)."""

    source: str
    target: str

    @field_validator("source")
    @classmethod
    def _source(cls, value: str) -> str:
        if not value.startswith("/") or mount_text_problem(value):
            raise ValueError("mount sources are absolute paths without ',', ':', quotes or control characters")
        return value

    @field_validator("target")
    @classmethod
    def _target(cls, value: str) -> str:
        if not is_lab_input_target(value):
            raise ValueError("mount targets are /lab/input/<name>")
        return value


class LabDefinition(RafModel):
    """A lab as stored in the workspace. Re-validated whenever it is loaded."""

    definition_version: int = 1
    id: str
    name: str
    image: str
    mounts: list[LabMount] = Field(default_factory=list)
    network: Literal["none", "bridge"] = "none"
    memory: str
    cpus: str
    pids_limit: int
    root: bool = False
    description: str = ""
    backend: Literal["auto", "docker", "podman"] = "auto"
    container_id: str | None = None
    state: str = "defined"
    state_at: datetime | None = None
    created_at: datetime
    updated_at: datetime

    @field_validator("id")
    @classmethod
    def _id(cls, value: str) -> str:
        if not _LAB_ID_RE.fullmatch(value):
            raise ValueError("invalid lab id")
        return value

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        if not LAB_NAME_RE.fullmatch(value):
            raise ValueError("invalid lab name")
        return value

    @field_validator("image")
    @classmethod
    def _image(cls, value: str) -> str:
        if _validated(validate_image, value) != value:
            raise ValueError("invalid image reference")
        return value

    @field_validator("memory")
    @classmethod
    def _memory(cls, value: str) -> str:
        if _validated(normalize_memory, value) != value:
            raise ValueError("memory limit is not normalized")
        return value

    @field_validator("cpus")
    @classmethod
    def _cpus(cls, value: str) -> str:
        if _validated(normalize_cpus, value) != value:
            raise ValueError("CPU limit is not normalized")
        return value

    @field_validator("pids_limit")
    @classmethod
    def _pids(cls, value: int) -> int:
        return _validated(validate_pids_limit, value)

    @field_validator("description")
    @classmethod
    def _description(cls, value: str) -> str:
        if _validated(validate_description, value) != value:
            raise ValueError("description is not normalized")
        return value

    @field_validator("container_id")
    @classmethod
    def _container_id(cls, value: str | None) -> str | None:
        if value is not None and not CONTAINER_ID_RE.fullmatch(value):
            raise ValueError("invalid container id")
        return value

    @field_validator("state")
    @classmethod
    def _state(cls, value: str) -> str:
        if not _STATE_RE.fullmatch(value):
            raise ValueError("invalid state")
        return value

    @model_validator(mode="after")
    def _mounts(self) -> LabDefinition:
        targets = [m.target for m in self.mounts]
        if len(targets) > MAX_MOUNTS or len(set(targets)) != len(targets):
            raise ValueError("mounts must have distinct targets (at most 8)")
        return self

    @property
    def allow_outbound(self) -> bool:
        return self.network == NETWORK_OUTBOUND

    @property
    def user(self) -> str:
        return ROOT_USER if self.root else UNPRIVILEGED_USER


@dataclass(slots=True)
class LifecycleResult:
    lab: LabDefinition
    container: ContainerState | None
    changed: bool = True
    created: bool = False
    note: str | None = None


def _audit_command(command: Sequence[str]) -> list[str]:
    shown = [arg if len(arg) <= 200 else arg[:197] + "..." for arg in command[:32]]
    if len(command) > 32:
        shown.append(f"... ({len(command) - 32} more arguments)")
    return shown


# --------------------------------------------------------------------------- service


class LabService:
    """Lab definitions and lifecycle for one workspace.

    ``backend`` replaces the container backend for every lab (tests, embedding); by default
    backends come from :func:`raf.products.lab.backend.get_backend`.
    """

    def __init__(self, ctx: RafContext, backend: LabBackend | None = None) -> None:
        self.ctx = ctx
        self.kv = ctx.store.kv
        self.workspace = ctx.workspace.name
        self._injected = backend
        self._backends: dict[str, LabBackend] = {}

    # ------------------------------------------------------------------ settings
    def _configured(self, key: str) -> Any:
        """A setting's value when it was set explicitly (``None`` while it is the built-in default)."""
        settings = self.ctx.settings
        return settings.get(key) if settings.origin(key) != "default" else None

    def default_backend_choice(self) -> str:
        configured = self._configured("lab.backend")
        return "auto" if configured is None else _from_setting("lab.backend", configured, validate_backend_choice)

    def default_image(self) -> str:
        configured = self._configured("lab.default_image")
        return DEFAULT_IMAGE if configured is None else _from_setting("lab.default_image", configured, validate_image)

    def default_memory(self) -> str:
        return _from_setting("lab.memory", self.ctx.settings.get("lab.memory"), normalize_memory)

    def default_cpus(self) -> str:
        return _from_setting("lab.cpus", self.ctx.settings.get("lab.cpus"), normalize_cpus)

    def default_pids_limit(self) -> int:
        return _from_setting("lab.pids_limit", self.ctx.settings.get("lab.pids_limit"), validate_pids_limit)

    # ------------------------------------------------------------------ backends
    def backend(self, choice: str | None = None) -> LabBackend:
        if self._injected is not None:
            return self._injected
        key = validate_backend_choice(choice) if choice else self.default_backend_choice()
        if key not in self._backends:
            self._backends[key] = get_backend(key)
        return self._backends[key]

    def _backend_for(self, lab: LabDefinition) -> LabBackend:
        """The backend that holds (or will hold) the lab's container."""
        return self.backend(lab.backend if lab.backend in BACKEND_NAMES else None)

    def backend_status(self, choice: str | None = None) -> dict[str, Any]:
        backend = self.backend(choice)
        availability = backend.availability()
        return {
            "backend": backend.name,
            "available": availability.available,
            "reason": availability.reason,
            "version": availability.version,
        }

    @staticmethod
    def _require_available(backend: LabBackend) -> None:
        availability = backend.availability()
        if not availability.available:
            raise DependencyUnavailableError(
                f"Container backend '{backend.name}' is not available.", reason=availability.reason, hint=BACKEND_HINT
            )

    # ------------------------------------------------------------------ storage
    def _load(self, key: str, raw: Any) -> LabDefinition:
        try:
            lab = LabDefinition.model_validate(raw)
        except ValidationError as exc:
            problems = "; ".join(
                f"{'.'.join(map(str, e['loc'])) or 'definition'}: {e['msg']}" for e in exc.errors()[:5]
            )
            raise IntegrityError(
                f"The stored definition of lab '{key}' is invalid; R$F will not use it.",
                reason=terminal_safe(problems)[:1000],
                hint=f"Remove it with 'raf lab destroy {key} --forget --yes' and create the lab again.",
            ) from exc
        if lab.name != key:
            raise IntegrityError(
                f"The stored definition of lab '{key}' names another lab ('{lab.name}'); R$F will not use it.",
                hint=f"Remove it with 'raf lab destroy {key} --forget --yes' and create the lab again.",
            )
        return lab

    def _definitions(self) -> tuple[list[LabDefinition], list[str]]:
        valid: list[LabDefinition] = []
        invalid: list[str] = []
        for key, raw in self.kv.items(NAMESPACE).items():
            try:
                valid.append(self._load(key, raw))
            except IntegrityError as exc:  # reported to callers as "invalid"; logged for the record
                log.info("skipping lab %r: %s", key, exc)
                invalid.append(terminal_safe(key)[:80])
        return valid, invalid

    def labs(self) -> list[LabDefinition]:
        """Valid lab definitions of this workspace, by name."""
        return self._definitions()[0]

    def invalid_definitions(self) -> list[str]:
        """Names of stored definitions that failed validation (shown, never used)."""
        return self._definitions()[1]

    def get(self, name: str) -> LabDefinition:
        name = validate_lab_name(name)
        raw = self.kv.get(NAMESPACE, name)
        if raw is None:
            raise NotFoundError(
                f"Lab '{name}' does not exist in workspace '{self.workspace}'.",
                suggestions=["raf lab list", f"raf lab create {name}"],
            )
        return self._load(name, raw)

    def exists(self, name: str) -> bool:
        return self.kv.get(NAMESPACE, validate_lab_name(name)) is not None

    def _save(self, lab: LabDefinition) -> None:
        self.kv.set(NAMESPACE, lab.name, lab.to_json_dict())

    def resolve_name(self, ref: str) -> str:
        """A lab name, or a context reference (``@lab``, ``@last``) to the last lab used."""
        text = ref
        if ContextRefs.is_reference(text):
            kind, stored = self.ctx.refs.resolve(text, accept=("lab",))
            if kind != "lab":
                raise InvalidInputError(f"'{text}' does not refer to a lab.", hint="Use a lab name, @lab or @last.")
            return validate_lab_name(stored)
        return validate_lab_name(text)

    # ------------------------------------------------------------------ views
    def container_name(self, name: str) -> str:
        return container_name(self.workspace, name)

    def container_spec(self, lab: LabDefinition) -> ContainerSpec:
        return ContainerSpec(
            name=self.container_name(lab.name),
            lab=lab.name,
            lab_id=lab.id,
            workspace=self.workspace,
            image=lab.image,
            network=lab.network,
            memory=lab.memory,
            cpus=lab.cpus,
            pids_limit=lab.pids_limit,
            root=lab.root,
            mounts=tuple(MountSpec(m.source, m.target) for m in lab.mounts),
        )

    def payload(
        self, lab: LabDefinition, *, live: bool = False, note: str | None = None, detail: bool = False
    ) -> dict[str, Any]:
        """JSON document for a lab (CLI ``raf.lab/v1`` and API)."""
        data: dict[str, Any] = {
            "name": lab.name,
            "state": lab.state,
            "live": live,
            "image": lab.image,
            "network": lab.network,
            "allow_outbound": lab.allow_outbound,
            "mounts": [{"source": m.source, "target": m.target, "read_only": True} for m in lab.mounts],
            "memory": lab.memory,
            "cpus": lab.cpus,
            "pids_limit": lab.pids_limit,
            "user": lab.user,
            "root": lab.root,
            "backend": lab.backend,
            "container": self.container_name(lab.name),
            "container_id": lab.container_id,
            "description": lab.description,
            "created_at": format_ts(lab.created_at),
            "updated_at": format_ts(lab.updated_at),
            "state_at": format_ts(lab.state_at),
        }
        if note:
            data["note"] = note
        if detail:
            program = lab.backend if lab.backend in BACKEND_NAMES else "docker"
            data["container_args"] = build_create_argv(self.container_spec(lab), executable=program)
        return data

    def _record(self, lab: LabDefinition, state: str, container_id: str | None) -> None:
        """Remember the observed state (saved only when it changed)."""
        if not _STATE_RE.fullmatch(state):
            state = "unknown"
        if container_id is not None and not CONTAINER_ID_RE.fullmatch(container_id):
            container_id = lab.container_id
        if lab.state == state and lab.container_id == container_id:
            return
        now = utcnow()
        lab.state, lab.container_id, lab.state_at, lab.updated_at = state, container_id, now, now
        self._save(lab)

    def _owned(self, lab: LabDefinition, info: ContainerState) -> bool:
        labels = info.labels
        return (
            labels.get("raf.lab") == lab.name
            and labels.get("raf.workspace") == self.workspace
            and labels.get("raf.lab.id") == lab.id
        )

    def _require_owned(self, lab: LabDefinition, info: ContainerState) -> None:
        if self._owned(lab, info):
            return
        labels = info.labels
        owner = f"raf.workspace={labels.get('raf.workspace', '-')}, raf.lab={labels.get('raf.lab', '-')}"
        raise ConflictError(
            f"Container {self.container_name(lab.name)} exists but was not created for lab '{lab.name}' "
            f"of workspace '{self.workspace}'.",
            reason=f"its labels say {terminal_safe(owner)[:300]}",
            hint="R$F never modifies containers it did not create for this lab. Remove or rename that "
            "container, or use another lab name.",
        )

    def _require_consistent(self, lab: LabDefinition, info: ContainerState, backend: LabBackend) -> None:
        problems: list[str] = []
        if info.privileged:
            problems.append("it is privileged")
        if info.network is not None and info.network != lab.network:
            problems.append(f"its network is {info.network}, the lab expects {lab.network}")
        if problems:
            raise ConflictError(
                f"Container {self.container_name(lab.name)} no longer matches lab '{lab.name}': "
                + "; ".join(problems)
                + ".",
                hint=f"Remove the container ({backend.name} rm -f {self.container_name(lab.name)}); "
                f"'raf lab start {lab.name}' then recreates it from the definition.",
            )

    def observe(self, lab: LabDefinition, *, detail: bool = False) -> dict[str, Any]:
        """The lab with its live state when its backend is available (last known state otherwise)."""
        backend = self._backend_for(lab)
        availability = backend.availability()
        if not availability.available:
            return self.payload(lab, live=False, detail=detail, note=f"last known state; {backend.name} is unavailable")
        try:
            info = backend.inspect(self.container_name(lab.name))
        except (LabBackendError, DependencyUnavailableError) as exc:
            return self.payload(lab, live=False, detail=detail, note=f"last known state; {exc}")
        note = None
        if info is None:
            self._record(lab, "defined", None)
        elif not self._owned(lab, info):
            self._record(lab, "conflict", lab.container_id)
            note = f"a container named {self.container_name(lab.name)} exists but belongs to another lab"
        else:
            self._record(lab, info.state, info.id)
        return self.payload(lab, live=True, detail=detail, note=note)

    def status(self, name: str | None = None, *, backend: str | None = None) -> dict[str, Any]:
        """Backend availability plus the (live when possible) state of one or all labs."""
        data = self.backend_status(backend)
        if name is not None:
            data["labs"] = [self.observe(self.get(name), detail=True)]
        else:
            labs, invalid = self._definitions()
            data["labs"] = [self.observe(lab) for lab in labs]
            if invalid:
                data["invalid"] = invalid
        return data

    # ------------------------------------------------------------------ lifecycle
    def validate_mounts(self, mounts: Sequence[str], *, require_absolute: bool = False) -> list[LabMount]:
        if len(mounts) > MAX_MOUNTS:
            raise InvalidInputError(f"Too many mounts ({len(mounts)}); at most {MAX_MOUNTS}.")
        result: list[LabMount] = []
        for raw in mounts:
            source = validate_mount_source(
                raw, raf_home=self.ctx.home.root, home=home_directory(), require_absolute=require_absolute
            )
            target = lab_input_target(source.name)
            clash = next((m for m in result if m.target == target), None)
            if clash is not None:
                raise InvalidInputError(
                    f"Mounts {clash.source} and {source} would both appear at {target}.",
                    hint="Mount files or directories with different names, or put them in one directory.",
                )
            result.append(LabMount(source=str(source), target=target))
        return result

    def create(
        self,
        name: str,
        *,
        image: str | None = None,
        mounts: Sequence[str] = (),
        allow_outbound: bool = False,
        memory: str | None = None,
        cpus: str | float | None = None,
        root: bool = False,
        description: str = "",
        backend: str | None = None,
        require_absolute_mounts: bool = False,
    ) -> LabDefinition:
        """Validate and record a lab definition. No container is created (that happens on start)."""
        name = validate_lab_name(name)
        if self.kv.get(NAMESPACE, name) is not None:
            raise ConflictError(
                f"Lab '{name}' already exists in workspace '{self.workspace}'.",
                suggestions=[f"raf lab status {name}", f"raf lab destroy {name}"],
            )
        now = utcnow()
        lab = LabDefinition(
            id=uuid.uuid4().hex,
            name=name,
            image=validate_image(image) if image else self.default_image(),
            mounts=self.validate_mounts(mounts, require_absolute=require_absolute_mounts),
            network=NETWORK_OUTBOUND if allow_outbound else NETWORK_ISOLATED,
            memory=normalize_memory(memory) if memory is not None else self.default_memory(),
            cpus=normalize_cpus(cpus) if cpus is not None else self.default_cpus(),
            pids_limit=self.default_pids_limit(),
            root=bool(root),
            description=validate_description(description),
            backend=validate_backend_choice(backend) if backend else self.default_backend_choice(),
            created_at=now,
            updated_at=now,
        )
        self._save(lab)
        details: dict[str, Any] = {
            "image": lab.image,
            "network": lab.network,
            "mounts": [m.source for m in lab.mounts],
            "memory": lab.memory,
            "cpus": lab.cpus,
            "pids_limit": lab.pids_limit,
            "user": lab.user,
            "backend": lab.backend,
        }
        warnings = [w for w, on in ((OUTBOUND_WARNING, lab.allow_outbound), (ROOT_WARNING, lab.root)) if on]
        if warnings:
            details["warning"] = "; ".join(warnings)
        self.ctx.audit.record("lab.create", affected=[f"lab:{name}"], details=details)
        self.ctx.refs.remember("lab", name)
        return lab

    def _revalidated_mounts(self, lab: LabDefinition) -> None:
        """Mount sources are checked again before a container is created: paths may have changed."""
        for mount in lab.mounts:
            current = validate_mount_source(
                mount.source, raf_home=self.ctx.home.root, home=home_directory(), require_absolute=True
            )
            if str(current) != mount.source or lab_input_target(current.name) != mount.target:
                raise SecurityViolation(
                    f"Mount source {mount.source} changed since lab '{lab.name}' was created.",
                    reason=f"it now resolves to {terminal_safe(str(current))[:200]}",
                    hint=f"Destroy and recreate the lab: raf lab destroy {lab.name}",
                )

    def start(self, name: str) -> LifecycleResult:
        """Create the container if needed (secure defaults), then start it."""
        lab = self.get(name)
        backend = self._backend_for(lab)
        self._require_available(backend)
        container = self.container_name(lab.name)
        info = backend.inspect(container)
        if info is not None:
            self._require_owned(lab, info)
            self._require_consistent(lab, info, backend)
        already_running = info is not None and info.running
        created = False
        if not already_running:
            # The runtime binds mount sources again on every start, so they are checked every time.
            self._revalidated_mounts(lab)
        if info is None:
            container_id = backend.create(self.container_spec(lab))
            created = True
            if backend.name in BACKEND_NAMES:
                lab.backend = "docker" if backend.name == "docker" else "podman"
            self._record(lab, "created", container_id)  # remembered even if starting fails
            info = backend.inspect(container_id)
            if info is None:
                raise LabBackendError(f"Container {container} disappeared right after it was created.")
            self._require_owned(lab, info)
        if not already_running:
            backend.start(info.id)
            info = backend.inspect(info.id)
            if info is None:
                raise LabBackendError(f"Container {container} disappeared while starting.")
        self._record(lab, info.state, info.id)
        details: dict[str, Any] = {
            "container": container,
            "container_id": info.id[:12],
            "backend": backend.name,
            "image": lab.image,
            "network": lab.network,
            "created": created,
            "already_running": already_running,
            "state": info.state,
        }
        if lab.allow_outbound:
            details["warning"] = OUTBOUND_WARNING
        self.ctx.audit.record("lab.start", affected=[f"lab:{lab.name}"], details=details)
        self.ctx.refs.remember("lab", lab.name)
        note = None
        if already_running:
            note = "the lab was already running"
        elif not info.running:
            note = f"the container is {info.state} after start" + (f": {info.error}" if info.error else "")
        return LifecycleResult(lab, info, changed=not already_running, created=created, note=note)

    def stop(self, name: str) -> LifecycleResult:
        lab = self.get(name)
        backend = self._backend_for(lab)
        self._require_available(backend)
        info = backend.inspect(self.container_name(lab.name))
        if info is None:
            self._record(lab, "defined", None)
            return LifecycleResult(lab, None, changed=False, note="the lab has no container; nothing to stop")
        self._require_owned(lab, info)
        was_running = info.running or info.state in {"paused", "restarting"}
        if was_running:
            backend.stop(info.id)
            info = backend.inspect(info.id) or info
        self._record(lab, info.state, info.id)
        self.ctx.audit.record(
            "lab.stop",
            affected=[f"lab:{lab.name}"],
            details={
                "container": self.container_name(lab.name),
                "backend": backend.name,
                "was_running": was_running,
                "state": info.state,
            },
        )
        return LifecycleResult(
            lab, info, changed=was_running, note=None if was_running else f"the lab was not running ({info.state})"
        )

    def destroy(self, name: str, *, forget: bool = False) -> dict[str, Any]:
        """Remove the lab's container (if any) and its definition.

        ``forget`` deletes the definition even when the container cannot be removed (backend
        unavailable) or when the stored definition is invalid; a container is then left in place.
        """
        name = validate_lab_name(name)
        container = self.container_name(name)
        try:
            lab = self.get(name)
        except IntegrityError:
            if not forget:
                raise
            self.kv.delete(NAMESPACE, name)
            forgotten = "invalid definition removed; no container was touched"
            self.ctx.audit.record(
                "lab.destroy",
                affected=[f"lab:{name}"],
                details={"container": container, "container_removed": False, "forget": True, "note": forgotten},
            )
            return {
                "name": name,
                "destroyed": True,
                "container": container,
                "container_removed": False,
                "note": forgotten,
            }
        backend = self._backend_for(lab)
        availability = backend.availability()
        removed = False
        note: str | None = None
        if not availability.available:
            if lab.container_id is not None and not forget:
                raise DependencyUnavailableError(
                    f"Cannot remove the container of lab '{name}': container backend '{backend.name}' "
                    "is not available.",
                    reason=availability.reason,
                    hint=BACKEND_HINT,
                    suggestions=[f"raf lab destroy {name} --forget   (deletes only the R$F definition)"],
                )
            if lab.container_id is not None:
                note = f"{backend.name} is unavailable: container {container} (if it still exists) was left in place"
        else:
            info = backend.inspect(container)
            if info is not None:
                if self._owned(lab, info):
                    backend.remove(info.id)
                    removed = True
                else:
                    note = f"container {container} belongs to another lab and was left untouched"
        self.kv.delete(NAMESPACE, name)
        details: dict[str, Any] = {
            "container": container,
            "container_removed": removed,
            "backend": backend.name,
            "forget": forget,
        }
        if note:
            details["note"] = note
        self.ctx.audit.record("lab.destroy", affected=[f"lab:{name}"], details=details)
        result: dict[str, Any] = {"name": name, "destroyed": True, "container": container, "container_removed": removed}
        if note:
            result["note"] = note
        return result

    def _running(self, lab: LabDefinition) -> tuple[LabBackend, ContainerState]:
        backend = self._backend_for(lab)
        self._require_available(backend)
        info = backend.inspect(self.container_name(lab.name))
        if info is None:
            self._record(lab, "defined", None)
            raise ConflictError(f"Lab '{lab.name}' is not running.", suggestions=[f"raf lab start {lab.name}"])
        self._require_owned(lab, info)
        self._record(lab, info.state, info.id)
        if not info.running:
            raise ConflictError(
                f"Lab '{lab.name}' is not running (state: {info.state}).", suggestions=[f"raf lab start {lab.name}"]
            )
        return backend, info

    def exec(
        self,
        name: str,
        argv: Sequence[str],
        *,
        timeout: int = EXEC_DEFAULT_TIMEOUT,
        max_output_kb: int = EXEC_DEFAULT_OUTPUT_KB,
    ) -> ExecResult:
        """Run one command (an argument vector) in the running lab; output is captured and bounded."""
        command = validate_command(argv)
        if not 1 <= timeout <= EXEC_MAX_TIMEOUT:
            raise InvalidInputError(f"Timeout must be between 1 and {EXEC_MAX_TIMEOUT} seconds.")
        if not 1 <= max_output_kb <= EXEC_MAX_OUTPUT_KB:
            raise InvalidInputError(f"Output limit must be between 1 and {EXEC_MAX_OUTPUT_KB} KB.")
        lab = self.get(name)
        backend, info = self._running(lab)
        result = backend.exec(info.id, command, timeout=float(timeout), max_output=max_output_kb * 1024)
        self.ctx.audit.record(
            "lab.exec",
            affected=[f"lab:{lab.name}"],
            details={
                "command": _audit_command(command),
                "exit_code": result.exit_code,
                "timed_out": result.timed_out,
                "truncated": result.stdout_truncated or result.stderr_truncated,
                "container": self.container_name(lab.name),
            },
        )
        self.ctx.refs.remember("lab", lab.name)
        return result

    def shell(self, name: str) -> int:
        """Interactive /bin/sh in the running lab (the caller must own a terminal)."""
        lab = self.get(name)
        backend, info = self._running(lab)
        self.ctx.audit.record(
            "lab.shell",
            affected=[f"lab:{lab.name}"],
            details={"container": self.container_name(lab.name), "backend": backend.name},
        )
        self.ctx.refs.remember("lab", lab.name)
        return backend.shell(info.id)
