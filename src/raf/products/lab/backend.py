"""Container backends for R$F Lab: the Docker and Podman command-line interfaces.

Security model
--------------
* Every lab container is created by one pure function, :func:`build_create_argv`, so the
  isolation flags can be reviewed and tested in one place. :class:`ContainerSpec` re-checks
  its invariants when it is built, so not even a tampered lab definition can produce a
  privileged, host-networked or socket-mounting container.
* Backends run the container CLI with an argument vector (``shell=False``), a timeout and
  bounded output capture. No string from a user, an image or a container is interpreted by
  a shell. The interactive ``shell`` session is the one call without a timeout: it lasts as
  long as the user keeps it open.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import subprocess
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import IO, Any, NamedTuple, Protocol

from raf.core.errors import DependencyUnavailableError, InvalidInputError, RafError, SecurityViolation
from raf.core.security.text import terminal_safe

# --------------------------------------------------------------------------- constants

DEFAULT_IMAGE = "alpine:3.20"
LAB_INPUT_DIR = "/lab/input"
LAB_WORK_DIR = "/lab/work"
UNPRIVILEGED_USER = "1000:1000"
ROOT_USER = "0:0"
NETWORK_ISOLATED = "none"
NETWORK_OUTBOUND = "bridge"
NETWORK_MODES = (NETWORK_ISOLATED, NETWORK_OUTBOUND)
TMPFS_TMP = "/tmp:rw,noexec,nosuid,size=64m"  # noqa: S108 - a path inside the container, not on the host
TMPFS_WORK = f"{LAB_WORK_DIR}:rw,nosuid,size=256m"
SHELL = "/bin/sh"
#: PID 1 of every lab container. A constant (never built from input): it idles until the
#: container is stopped and exits promptly on SIGTERM, so no init binary is required.
KEEPALIVE_SCRIPT = 'trap "exit 0" TERM INT; sleep 2147483647 & wait'

BACKEND_NAMES = ("docker", "podman")
BACKEND_CHOICES = ("auto", *BACKEND_NAMES)
BACKEND_HINT = "Install Docker or Podman and make sure the daemon is running; 'raf lab status' shows the backend."

MIN_MEMORY_MB, MAX_MEMORY_MB = 32, 16 * 1024
MIN_CPUS, MAX_CPUS = 0.1, 16.0
MIN_PIDS, MAX_PIDS = 16, 4096

# Timeouts in seconds. ``create`` includes pulling a missing image.
AVAILABILITY_TIMEOUT = 5.0
INSPECT_TIMEOUT = 15.0
CREATE_TIMEOUT = 300.0
START_TIMEOUT = 60.0
STOP_GRACE_SECONDS = 10
STOP_TIMEOUT = 40.0
REMOVE_TIMEOUT = 60.0
DEFAULT_MAX_OUTPUT = 1024 * 1024
INSPECT_MAX_OUTPUT = 4 * 1024 * 1024

# --------------------------------------------------------------------------- errors


class LabBackendError(RafError):
    """The container CLI ran but the operation failed (bad image, daemon error, ...)."""

    code = "raf.lab.backend"
    exit_code = 1
    http_status = 502


# --------------------------------------------------------------------------- text helpers


def one_line(text: str, limit: int = 500) -> str:
    """A bounded, single-line, terminal-safe rendering of a backend message."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    joined = terminal_safe(" ".join(lines[:3]))
    return joined if len(joined) <= limit else joined[: limit - 3] + "..."


_CONNECTION_ERRORS = (
    "failed to connect to the docker api",
    "cannot connect to the docker daemon",
    "is the docker daemon running",
    "cannot connect to podman",
    "unable to connect to podman",
)


def is_connection_error(message: str) -> bool:
    lowered = message.lower()
    return any(marker in lowered for marker in _CONNECTION_ERRORS)


# --------------------------------------------------------------------------- validation

_DOMAIN_COMPONENT = r"(?:[A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9-]*[A-Za-z0-9])"
_DOMAIN = rf"{_DOMAIN_COMPONENT}(?:\.{_DOMAIN_COMPONENT})*(?::[0-9]{{1,5}})?"
_PATH_COMPONENT = r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*"
_TAG = r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}"
_DIGEST = r"sha256:[a-f0-9]{64}"
#: ``[registry[:port]/]path[/path...][:tag][@sha256:<64 hex>]`` - no spaces, no shell syntax.
IMAGE_RE = re.compile(rf"(?:{_DOMAIN}/)?{_PATH_COMPONENT}(?:/{_PATH_COMPONENT})*(?::{_TAG})?(?:@{_DIGEST})?")
IMAGE_MAX_LENGTH = 255

LAB_NAME_RE = re.compile(r"[a-z0-9][a-z0-9-]{1,40}")
_WORKSPACE_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}")
_LAB_ID_RE = re.compile(r"[0-9a-f]{32}")
_CONTAINER_NAME_RE = re.compile(r"raf-lab-[a-z0-9][a-z0-9_.-]{0,120}")
CONTAINER_ID_RE = re.compile(r"[0-9a-f]{12,64}")
_MEMORY_RE = re.compile(r"([1-9][0-9]{0,5})([mg])")
_CPUS_RE = re.compile(r"[0-9]{1,2}(?:\.[0-9]{1,2})?")
_MOUNT_TEXT_RE = re.compile(r'[,:"\\\x00-\x1f\x7f]')


def validate_image(value: str) -> str:
    """Strictly validate an image reference (registry/name:tag or @sha256 digest)."""
    text = value if isinstance(value, str) else ""
    if not text or len(text) > IMAGE_MAX_LENGTH or not IMAGE_RE.fullmatch(text):
        shown = terminal_safe(str(value))[:120]
        raise InvalidInputError(
            f"Invalid image reference '{shown}'.",
            hint="Use [registry/]name[:tag][@sha256:<digest>], for example alpine:3.20 or "
            "registry.example.com/team/tools:1.4 (lowercase repository names, no spaces or shell syntax).",
        )
    return text


def normalize_memory(value: str) -> str:
    """``512m`` / ``2g`` within 32m..16g, normalized to lowercase."""
    text = str(value).strip().lower()
    match = _MEMORY_RE.fullmatch(text)
    if match is None:
        raise InvalidInputError(
            f"Invalid memory limit '{terminal_safe(str(value))[:40]}'.",
            hint="Use megabytes or gigabytes with a unit, for example 512m or 2g.",
        )
    amount, unit = int(match.group(1)), match.group(2)
    megabytes = amount * (1024 if unit == "g" else 1)
    if not MIN_MEMORY_MB <= megabytes <= MAX_MEMORY_MB:
        raise InvalidInputError(f"Memory limit {text} is outside the allowed range.", hint="Use 32m to 16g.")
    return f"{amount}{unit}"


def normalize_cpus(value: str | float) -> str:
    """CPU limit within 0.1..16, normalized (``1.0`` -> ``1``)."""
    text = str(value).strip()
    if isinstance(value, bool) or not _CPUS_RE.fullmatch(text):
        raise InvalidInputError(
            f"Invalid CPU limit '{terminal_safe(str(value))[:40]}'.",
            hint="Use a number of CPUs such as 1, 0.5 or 2 (up to two decimals).",
        )
    amount = float(text)
    if not MIN_CPUS <= amount <= MAX_CPUS:
        raise InvalidInputError(f"CPU limit {text} is outside the allowed range.", hint="Use 0.1 to 16 CPUs.")
    return f"{amount:g}"


def validate_pids_limit(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not MIN_PIDS <= value <= MAX_PIDS:
        raise InvalidInputError(f"Invalid process limit {value!r}.", hint=f"Use {MIN_PIDS} to {MAX_PIDS}.")
    return value


def validate_backend_choice(value: str) -> str:
    text = str(value).strip().lower()
    if text not in BACKEND_CHOICES:
        raise InvalidInputError(
            f"Unknown lab backend '{terminal_safe(str(value))[:40]}'.", hint="Use auto, docker or podman."
        )
    return text


def mount_text_problem(text: str) -> str | None:
    """Why ``text`` cannot appear in a ``--mount`` value (``None`` when it can)."""
    found = _MOUNT_TEXT_RE.search(text)
    if found is None:
        return None
    char = found.group()
    if char in ",:":
        return f"'{char}' is not allowed in mount paths (bind syntax injection)"
    if char in '"\\':
        return "quotes and backslashes are not allowed in mount paths"
    return "control characters are not allowed in mount paths"


def lab_input_target(basename: str) -> str:
    return f"{LAB_INPUT_DIR}/{basename}"


def is_lab_input_target(target: str) -> bool:
    prefix = LAB_INPUT_DIR + "/"
    if not target.startswith(prefix):
        return False
    basename = target[len(prefix) :]
    return bool(basename) and "/" not in basename and basename not in {".", ".."} and not mount_text_problem(basename)


def container_name(workspace: str, lab: str) -> str:
    """``raf-lab-<workspace>-<lab>``, reduced to characters every container runtime accepts."""

    def clean(part: str) -> str:
        return re.sub(r"[^a-z0-9_.-]+", "-", part.lower()).strip("-.") or "x"

    return f"raf-lab-{clean(workspace)}-{clean(lab)}"


# --------------------------------------------------------------------------- container specification


@dataclass(frozen=True, slots=True)
class MountSpec:
    """A host path bind-mounted read-only at ``target`` (always under /lab/input)."""

    source: str
    target: str


@dataclass(frozen=True, slots=True)
class ContainerSpec:
    name: str
    lab: str
    lab_id: str
    workspace: str
    image: str
    network: str = NETWORK_ISOLATED
    memory: str = "512m"
    cpus: str = "1"
    pids_limit: int = 256
    root: bool = False
    mounts: tuple[MountSpec, ...] = ()

    def __post_init__(self) -> None:
        problems: list[str] = []
        if not _CONTAINER_NAME_RE.fullmatch(self.name):
            problems.append(f"container name {self.name!r}")
        if not LAB_NAME_RE.fullmatch(self.lab):
            problems.append(f"lab name {self.lab!r}")
        if not _LAB_ID_RE.fullmatch(self.lab_id):
            problems.append("lab id")
        if not _WORKSPACE_RE.fullmatch(self.workspace):
            problems.append(f"workspace {self.workspace!r}")
        if self.network not in NETWORK_MODES:
            problems.append(f"network {self.network!r} (only none or bridge)")
        try:
            validate_image(self.image)
            if normalize_memory(self.memory) != self.memory:
                problems.append(f"memory {self.memory!r}")
            if normalize_cpus(self.cpus) != self.cpus:
                problems.append(f"cpus {self.cpus!r}")
            validate_pids_limit(self.pids_limit)
        except InvalidInputError as exc:
            problems.append(exc.message)
        targets: set[str] = set()
        for mount in self.mounts:
            if not mount.source.startswith("/") or mount_text_problem(mount.source):
                problems.append(f"mount source {mount.source!r}")
            if not is_lab_input_target(mount.target) or mount.target in targets:
                problems.append(f"mount target {mount.target!r}")
            targets.add(mount.target)
        if problems:
            raise SecurityViolation(
                "Refusing to build an unsafe lab container specification.", reason="; ".join(problems)[:1000]
            )


def build_create_argv(spec: ContainerSpec, *, executable: str = "docker") -> list[str]:
    """The complete ``<executable> create ...`` argument vector for a lab container.

    Never emitted: ``--privileged``, ``--cap-add``, ``--network host``, ``--pid``/``--ipc``/``--uts``
    host namespaces, ``--device``, ``--volume`` or any socket mount. Mounts are read-only binds
    under /lab/input; the root filesystem is read-only; /tmp and /lab/work are size-limited tmpfs.
    """
    argv = [
        executable,
        "create",
        "--name",
        spec.name,
        "--label",
        f"raf.lab={spec.lab}",
        "--label",
        f"raf.workspace={spec.workspace}",
        "--label",
        f"raf.lab.id={spec.lab_id}",
        "--network",
        spec.network,
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--read-only",
        "--tmpfs",
        TMPFS_TMP,
        "--tmpfs",
        TMPFS_WORK,
        "--pids-limit",
        str(spec.pids_limit),
        "--memory",
        spec.memory,
        "--memory-swap",
        spec.memory,
        "--cpus",
        spec.cpus,
        "--user",
        ROOT_USER if spec.root else UNPRIVILEGED_USER,
        "--workdir",
        LAB_WORK_DIR,
        "--env",
        f"HOME={LAB_WORK_DIR}",
    ]
    for mount in spec.mounts:
        argv += ["--mount", f"type=bind,source={mount.source},target={mount.target},readonly"]
    argv += ["--entrypoint", SHELL, spec.image, "-c", KEEPALIVE_SCRIPT]
    return argv


# --------------------------------------------------------------------------- results


class Availability(NamedTuple):
    available: bool
    reason: str | None = None
    version: str | None = None


@dataclass(frozen=True, slots=True)
class ContainerState:
    """What R$F needs from ``container inspect``."""

    id: str
    name: str
    state: str
    running: bool
    labels: dict[str, str] = field(default_factory=dict)
    network: str | None = None
    privileged: bool = False
    image: str = ""
    started_at: str | None = None
    finished_at: str | None = None
    exit_code: int | None = None
    error: str | None = None


@dataclass(frozen=True, slots=True)
class CommandResult:
    exit_code: int
    stdout: str
    stderr: str
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    timed_out: bool = False
    duration_s: float = 0.0


#: ``exec`` returns the captured, bounded result of the command.
ExecResult = CommandResult

_STATE_RE = re.compile(r"[a-z][a-z-]{0,23}")


def _text_or_none(value: Any, limit: int = 200) -> str | None:
    if value is None or value == "":
        return None
    return one_line(str(value), limit)


def _section(data: dict[str, Any], key: str) -> dict[str, Any]:
    value = data.get(key)
    return value if isinstance(value, dict) else {}


def parse_container_state(data: dict[str, Any]) -> ContainerState:
    """Map ``docker/podman container inspect`` JSON to :class:`ContainerState`."""
    state, config, host = _section(data, "State"), _section(data, "Config"), _section(data, "HostConfig")
    raw_labels = config.get("Labels")
    labels = {str(k): str(v) for k, v in raw_labels.items()} if isinstance(raw_labels, dict) else {}
    status = str(state.get("Status") or "unknown").strip().lower()
    exit_code = state.get("ExitCode")
    return ContainerState(
        id=str(data.get("Id") or data.get("ID") or ""),
        name=str(data.get("Name") or "").lstrip("/"),
        state=status if _STATE_RE.fullmatch(status) else "unknown",
        running=bool(state.get("Running")),
        labels=labels,
        network=_text_or_none(host.get("NetworkMode"), 64),
        privileged=bool(host.get("Privileged")),
        image=_text_or_none(config.get("Image"), IMAGE_MAX_LENGTH) or "",
        started_at=_text_or_none(state.get("StartedAt"), 64),
        finished_at=_text_or_none(state.get("FinishedAt"), 64),
        exit_code=exit_code if isinstance(exit_code, int) and not isinstance(exit_code, bool) else None,
        error=_text_or_none(state.get("Error"), 500),
    )


# --------------------------------------------------------------------------- process execution


class Runner(Protocol):
    def __call__(self, argv: Sequence[str], *, timeout: float, max_output: int = ...) -> CommandResult: ...


class InteractiveRunner(Protocol):
    def __call__(self, argv: Sequence[str]) -> int: ...


class _Drain(threading.Thread):
    """Read a pipe to EOF, keeping at most ``limit`` bytes (the rest is counted, not stored)."""

    def __init__(self, stream: IO[bytes] | None, limit: int) -> None:
        super().__init__(daemon=True)
        self._stream = stream
        self._limit = limit
        self.data = bytearray()
        self.truncated = False

    def run(self) -> None:
        stream = self._stream
        if stream is None:
            return
        try:
            fd = stream.fileno()
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                room = self._limit - len(self.data)
                if room > 0:
                    self.data += chunk[:room]
                if len(chunk) > max(room, 0):
                    self.truncated = True
        except (OSError, ValueError):
            pass
        finally:
            with contextlib.suppress(OSError):
                stream.close()

    def text(self) -> str:
        return bytes(self.data).decode("utf-8", "replace")


def _exit_status(code: int) -> int:
    """Shell convention for processes killed by a signal (128 + signal number)."""
    return 128 - code if code < 0 else code


def run_command(argv: Sequence[str], *, timeout: float, max_output: int = DEFAULT_MAX_OUTPUT) -> CommandResult:
    """Run ``argv`` without a shell: stdin closed, output captured up to ``max_output`` bytes per
    stream, the process killed after ``timeout`` seconds."""
    args = [str(part) for part in argv]
    started = time.monotonic()
    try:
        proc = subprocess.Popen(
            args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False
        )
    except FileNotFoundError:
        return CommandResult(127, "", f"{args[0]}: command not found")
    except (OSError, ValueError) as exc:
        return CommandResult(126, "", f"{args[0]}: {exc}")
    out, err = _Drain(proc.stdout, max_output), _Drain(proc.stderr, max_output)
    out.start()
    err.start()
    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        proc.wait()
    out.join(timeout=5)
    err.join(timeout=5)
    return CommandResult(
        exit_code=_exit_status(proc.returncode),
        stdout=out.text(),
        stderr=err.text(),
        stdout_truncated=out.truncated,
        stderr_truncated=err.truncated,
        timed_out=timed_out,
        duration_s=round(time.monotonic() - started, 3),
    )


def run_interactive(argv: Sequence[str]) -> int:
    """Run an interactive session on the caller's terminal (stdin/stdout/stderr inherited).

    Deliberately without a timeout: the session ends when the user leaves the shell (or the
    lab is stopped). Killing it on a timer would leave the user's terminal in raw mode.
    """
    try:
        completed = subprocess.run([str(part) for part in argv], check=False, shell=False)
    except FileNotFoundError:
        return 127
    return _exit_status(completed.returncode)


# --------------------------------------------------------------------------- backends


class LabBackend(Protocol):
    """What R$F Lab needs from a container runtime."""

    name: str

    def availability(self) -> Availability: ...

    def create(self, spec: ContainerSpec) -> str: ...

    def start(self, container: str) -> None: ...

    def stop(self, container: str) -> None: ...

    def remove(self, container: str) -> None: ...

    def inspect(self, container: str) -> ContainerState | None: ...

    def exec(self, container: str, argv: Sequence[str], *, timeout: float, max_output: int) -> ExecResult: ...

    def shell(self, container: str) -> int: ...


class ContainerCliBackend:
    """Shared implementation for container CLIs with Docker's command shape."""

    name: str = "docker"
    program: str = "docker"
    version_template: str = "{{.ServerVersion}}"

    def __init__(
        self,
        *,
        executable: str | None = None,
        runner: Runner | None = None,
        interactive: InteractiveRunner | None = None,
    ) -> None:
        self.executable = executable if executable is not None else shutil.which(self.program)
        self._run: Runner = runner if runner is not None else run_command
        self._interactive: InteractiveRunner = interactive if interactive is not None else run_interactive
        self._availability: Availability | None = None

    @property
    def installed(self) -> bool:
        return self.executable is not None

    def _exe(self) -> str:
        if self.executable is None:
            raise DependencyUnavailableError(
                f"Container backend '{self.name}' is not available.",
                reason=f"the {self.program} CLI was not found on PATH",
                hint=BACKEND_HINT,
            )
        return self.executable

    def _unavailable(self, reason: str) -> DependencyUnavailableError:
        self._availability = Availability(False, reason, None)
        return DependencyUnavailableError(
            f"Container backend '{self.name}' is not available.", reason=reason, hint=BACKEND_HINT
        )

    def availability(self, *, refresh: bool = False) -> Availability:
        """Probe ``<cli> info`` once (cached); never raises."""
        if self._availability is None or refresh:
            self._availability = self._probe()
        return self._availability

    def _probe(self) -> Availability:
        if self.executable is None:
            return Availability(False, f"the {self.program} CLI was not found on PATH", None)
        result = self._run(
            [self.executable, "info", "--format", self.version_template],
            timeout=AVAILABILITY_TIMEOUT,
            max_output=64 * 1024,
        )
        if result.timed_out:
            return Availability(False, f"'{self.program} info' did not answer within {AVAILABILITY_TIMEOUT:g} s", None)
        if result.exit_code != 0:
            message = one_line(result.stderr or result.stdout)
            return Availability(False, message or f"'{self.program} info' failed (exit code {result.exit_code})", None)
        version = one_line(result.stdout, 64)
        if not version or version == "<no value>":
            return Availability(False, f"'{self.program} info' reported no server version", None)
        return Availability(True, None, version)

    def _call(self, argv: list[str], *, timeout: float, action: str, hint: str | None = None) -> CommandResult:
        result = self._run(argv, timeout=timeout, max_output=DEFAULT_MAX_OUTPUT)
        if result.timed_out:
            raise LabBackendError(f"'{self.program} {action}' did not finish within {timeout:g} s.", hint=hint)
        if result.exit_code != 0:
            message = one_line(result.stderr or result.stdout) or f"exit code {result.exit_code}"
            if is_connection_error(message):
                raise self._unavailable(message)
            raise LabBackendError(f"'{self.program} {action}' failed.", reason=message, hint=hint)
        return result

    def create(self, spec: ContainerSpec) -> str:
        result = self._call(
            build_create_argv(spec, executable=self._exe()),
            timeout=CREATE_TIMEOUT,
            action="create",
            hint=f"Check the image name; the daemon pulls {spec.image} if it is not present locally.",
        )
        lines = result.stdout.strip().splitlines()
        container_id = lines[-1].strip() if lines else ""
        if not CONTAINER_ID_RE.fullmatch(container_id):
            raise LabBackendError(
                f"'{self.program} create' returned an unexpected container ID.", reason=one_line(result.stdout, 200)
            )
        return container_id

    def start(self, container: str) -> None:
        self._call(
            [self._exe(), "start", container],
            timeout=START_TIMEOUT,
            action="start",
            hint=f"Lab images must provide {SHELL}; see the backend message above.",
        )

    def stop(self, container: str) -> None:
        self._call([self._exe(), "stop", "-t", str(STOP_GRACE_SECONDS), container], timeout=STOP_TIMEOUT, action="stop")

    def remove(self, container: str) -> None:
        self._call([self._exe(), "rm", "-f", "-v", container], timeout=REMOVE_TIMEOUT, action="rm")

    def inspect(self, container: str) -> ContainerState | None:
        result = self._run(
            [self._exe(), "container", "inspect", container], timeout=INSPECT_TIMEOUT, max_output=INSPECT_MAX_OUTPUT
        )
        if result.timed_out:
            raise LabBackendError(f"'{self.program} container inspect' did not finish within {INSPECT_TIMEOUT:g} s.")
        if result.exit_code != 0:
            message = one_line(result.stderr or result.stdout) or f"exit code {result.exit_code}"
            lowered = message.lower()
            if "no such container" in lowered or "no such object" in lowered:
                return None
            if is_connection_error(message):
                raise self._unavailable(message)
            raise LabBackendError(f"'{self.program} container inspect' failed.", reason=message)
        if result.stdout_truncated:
            raise LabBackendError(f"'{self.program} container inspect' returned more data than expected.")
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise LabBackendError(
                f"'{self.program} container inspect' returned invalid JSON.", reason=str(exc)
            ) from exc
        if isinstance(data, list):
            data = data[0] if data else None
        if not isinstance(data, dict):
            return None
        return parse_container_state(data)

    def exec(self, container: str, argv: Sequence[str], *, timeout: float, max_output: int) -> ExecResult:
        result = self._run([self._exe(), "exec", container, *argv], timeout=timeout, max_output=max_output)
        if result.exit_code != 0 and not result.timed_out and is_connection_error(result.stderr):
            raise self._unavailable(one_line(result.stderr))
        return result

    def shell(self, container: str) -> int:
        return self._interactive([self._exe(), "exec", "-it", container, SHELL])


class DockerBackend(ContainerCliBackend):
    name = "docker"
    program = "docker"
    version_template = "{{.ServerVersion}}"


class PodmanBackend(ContainerCliBackend):
    name = "podman"
    program = "podman"
    version_template = "{{.Version.Version}}"


def detect_backend() -> ContainerCliBackend:
    """Docker when its daemon answers, else Podman when it answers, else the first installed CLI
    (so ``availability()`` explains what is wrong), else Docker."""
    candidates: list[ContainerCliBackend] = [DockerBackend(), PodmanBackend()]
    installed = [backend for backend in candidates if backend.installed]
    for backend in installed:
        if backend.availability().available:
            return backend
    return installed[0] if installed else candidates[0]


def make_backend(choice: str = "auto") -> LabBackend:
    selected = validate_backend_choice(choice)
    if selected == "docker":
        return DockerBackend()
    if selected == "podman":
        return PodmanBackend()
    return detect_backend()


BackendFactory = Callable[[str], LabBackend]

_FACTORY: list[BackendFactory] = [make_backend]


def set_backend_factory(factory: BackendFactory | None) -> None:
    """Replace how backends are built (tests, embedding); ``None`` restores the default."""
    _FACTORY[0] = factory if factory is not None else make_backend


def get_backend(choice: str = "auto") -> LabBackend:
    return _FACTORY[0](validate_backend_choice(choice))
