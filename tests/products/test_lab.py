"""R$F Lab: secure container arguments, input validation, lifecycle, CLI and API.

No test here needs Docker or Podman. Lifecycle tests install an in-memory backend through the
module-level backend factory; the real Docker/Podman backends run against a scripted runner;
the bounded process runner is exercised with the Python interpreter. test_lab_docker.py checks the
isolation inside running labs on a real daemon (opt-in).
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import sys
import tempfile
import warnings
from collections.abc import Iterator, Sequence
from itertools import pairwise
from pathlib import Path
from typing import Any

import pytest

from raf.core.audit.service import AuditEntry
from raf.core.context.app import RafContext
from raf.core.errors import (
    DependencyUnavailableError,
    InvalidInputError,
    NotFoundError,
    ResourceLimitExceeded,
    SecurityViolation,
)
from raf.products.lab import backend as lab_backend
from raf.products.lab import cli as lab_cli
from raf.products.lab.backend import (
    Availability,
    CommandResult,
    ContainerSpec,
    ContainerState,
    DockerBackend,
    LabBackendError,
    MountSpec,
    PodmanBackend,
    Runner,
    build_create_argv,
    container_name,
    make_backend,
    normalize_cpus,
    normalize_memory,
    run_command,
    terminal_safe,
    validate_image,
)
from raf.products.lab.service import LabService, validate_lab_name, validate_mount_source
from tests.conftest import REPO_ROOT

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from fastapi.testclient import TestClient

from raf.apps.api.app import create_app

DAEMON_DOWN = (
    "failed to connect to the docker API at unix:///var/run/docker.sock; check if the path is correct and if "
    "the daemon is running: dial unix /var/run/docker.sock: connect: no such file or directory"
)
HINT = "Install Docker or Podman and make sure the daemon is running"


# --------------------------------------------------------------------------- test doubles


class FakeBackend:
    """In-memory container runtime: records every call, never runs anything."""

    def __init__(self, *, available: bool = True, reason: str | None = None) -> None:
        self.name = "fake"
        self.available = available
        self.reason = reason
        self.containers: dict[str, dict[str, Any]] = {}
        self.created: list[list[str]] = []
        self.calls: list[tuple[str, ...]] = []
        self.exec_result = CommandResult(0, "hello from the lab\n", "")

    def availability(self) -> Availability:
        if self.available:
            return Availability(True, None, "fake-1.0")
        return Availability(False, self.reason, None)

    def add(self, name: str, labels: dict[str, str], *, state: str = "running", network: str = "none") -> str:
        cid = hashlib.sha256(name.encode()).hexdigest()
        self.containers[cid] = {
            "id": cid,
            "name": name,
            "labels": labels,
            "state": state,
            "network": network,
            "privileged": False,
        }
        return cid

    def _find(self, ref: str) -> dict[str, Any]:
        for cid, container in self.containers.items():
            if ref in (cid, container["name"]):
                return container
        raise AssertionError(f"no container {ref}")

    def create(self, spec: ContainerSpec) -> str:
        self.calls.append(("create", spec.name))
        self.created.append(build_create_argv(spec, executable="docker"))
        labels = {"raf.lab": spec.lab, "raf.workspace": spec.workspace, "raf.lab.id": spec.lab_id}
        return self.add(spec.name, labels, state="created", network=spec.network)

    def start(self, container: str) -> None:
        self.calls.append(("start", container))
        self._find(container)["state"] = "running"

    def stop(self, container: str) -> None:
        self.calls.append(("stop", container))
        self._find(container)["state"] = "exited"

    def remove(self, container: str) -> None:
        self.calls.append(("remove", container))
        del self.containers[self._find(container)["id"]]

    def inspect(self, container: str) -> ContainerState | None:
        self.calls.append(("inspect", container))
        found = [c for cid, c in self.containers.items() if container in (cid, c["name"])]
        if not found:
            return None
        c = found[0]
        return ContainerState(
            id=c["id"],
            name=c["name"],
            state=c["state"],
            running=c["state"] == "running",
            labels=dict(c["labels"]),
            network=c["network"],
            privileged=c["privileged"],
        )

    def exec(self, container: str, argv: Sequence[str], *, timeout: float, max_output: int) -> CommandResult:
        self.calls.append(("exec", container, *argv))
        return self.exec_result

    def shell(self, container: str) -> int:
        self.calls.append(("shell", container))
        return 0


class ScriptedRunner:
    """Stands in for the docker/podman executable: answers by sub-command, records every argv."""

    def __init__(self, responses: dict[str, CommandResult]) -> None:
        self.responses = responses
        self.calls: list[list[str]] = []

    def __call__(self, argv: Sequence[str], *, timeout: float, max_output: int = 0) -> CommandResult:
        self.calls.append(list(argv))
        command = "inspect" if argv[1] == "container" else argv[1]
        return self.responses.get(command, CommandResult(0, "", ""))


@pytest.fixture
def fake(raf_home: Path, monkeypatch: pytest.MonkeyPatch) -> FakeBackend:
    backend = FakeBackend()
    monkeypatch.setattr(lab_backend, "_FACTORY", [lambda choice: backend])
    return backend


@pytest.fixture
def samples(tmp_path: Path) -> Path:
    root = tmp_path / "work" / "samples"
    (root / "nested").mkdir(parents=True)
    (root / "a.txt").write_text("sample\n", encoding="utf-8")
    return root


def make_spec(**overrides: Any) -> ContainerSpec:
    fields: dict[str, Any] = {
        "name": container_name("default", "demo"),
        "lab": "demo",
        "lab_id": "a" * 32,
        "workspace": "default",
        "image": "alpine:3.20",
    }
    fields.update(overrides)
    return ContainerSpec(**fields)


def assert_never_unsafe(argv: Sequence[str]) -> None:
    for flag in (
        "--privileged",
        "--cap-add",
        "--device",
        "--pid",
        "--ipc",
        "--uts",
        "--userns",
        "--cgroupns",
        "--volume",
        "-v",
        "--volumes-from",
        "--group-add",
    ):
        assert not any(arg == flag or arg.startswith(flag + "=") for arg in argv), flag
    pairs = list(pairwise(argv))
    assert ("--network", "host") not in pairs
    assert not any(arg.startswith("--network=") for arg in argv)
    joined = " ".join(argv)
    for needle in ("docker.sock", "podman.sock", "seccomp=unconfined", "apparmor=unconfined", "label=disable"):
        assert needle not in joined
    for flag, value in pairs:
        if flag == "--mount":
            assert value.startswith("type=bind,source=/") and ",target=/lab/input/" in value
            assert value.endswith(",readonly")


def lab_audit(ctx: RafContext) -> list[AuditEntry]:
    return list(reversed(ctx.audit.list(limit=200, operation="lab.")))


# --------------------------------------------------------------------------- container arguments


def test_create_argv_has_every_secure_default() -> None:
    argv = build_create_argv(make_spec())
    assert argv[:2] == ["docker", "create"]
    pairs = set(pairwise(argv))
    assert {
        ("--name", "raf-lab-default-demo"),
        ("--network", "none"),
        ("--cap-drop", "ALL"),
        ("--security-opt", "no-new-privileges"),
        ("--tmpfs", "/tmp:rw,noexec,nosuid,size=64m"),
        ("--tmpfs", "/lab/work:rw,nosuid,size=256m,mode=1777"),
        ("--pids-limit", "256"),
        ("--memory", "512m"),
        ("--cpus", "1"),
        ("--user", "1000:1000"),
        ("--label", "raf.lab=demo"),
        ("--label", "raf.workspace=default"),
    } <= pairs
    assert "--read-only" in argv
    assert "--mount" not in argv
    assert argv[argv.index("--entrypoint") + 1 : argv.index("--entrypoint") + 3] == ["/bin/sh", "alpine:3.20"]
    assert_never_unsafe(argv)


def test_outbound_root_and_mounts_are_explicit_and_keep_the_hardening() -> None:
    spec = make_spec(
        network="bridge",
        root=True,
        memory="2g",
        cpus="0.5",
        pids_limit=512,
        mounts=(MountSpec("/data/samples", "/lab/input/samples"),),
    )
    argv = build_create_argv(spec, executable="podman")
    pairs = set(pairwise(argv))
    assert argv[0] == "podman" and "--read-only" in argv
    assert {
        ("--network", "bridge"),
        ("--user", "0:0"),
        ("--cap-drop", "ALL"),
        ("--security-opt", "no-new-privileges"),
        ("--memory", "2g"),
        ("--cpus", "0.5"),
        ("--pids-limit", "512"),
        ("--mount", "type=bind,source=/data/samples,target=/lab/input/samples,readonly"),
    } <= pairs
    assert_never_unsafe(argv)


@pytest.mark.parametrize(
    "overrides",
    [
        {"network": "host"},
        {"network": "container:other"},
        {"image": "alpine --privileged"},
        {"memory": "64g"},
        {"cpus": "1.0"},
        {"pids_limit": 1_000_000},
        {"mounts": (MountSpec("/var/run/docker.sock,target=/x", "/lab/input/x"),)},
        {"mounts": (MountSpec("/data", "/etc"),)},
        {"mounts": (MountSpec("relative", "/lab/input/relative"),)},
        {"mounts": (MountSpec("/a/x", "/lab/input/x"), MountSpec("/b/x", "/lab/input/x"))},
        {"name": "my-container"},
        {"lab": "Bad"},
        {"lab_id": "nope"},
        {"workspace": "../x"},
    ],
)
def test_container_spec_refuses_unsafe_values(overrides: dict[str, Any]) -> None:
    with pytest.raises(SecurityViolation):
        make_spec(**overrides)


def test_container_names_are_sanitized() -> None:
    assert container_name("default", "protocol-test") == "raf-lab-default-protocol-test"
    assert container_name("Team_A", "x--y") == "raf-lab-team_a-x--y"
    assert container_name("..", "a b") == "raf-lab-x-a-b"


# --------------------------------------------------------------------------- input validation


@pytest.mark.parametrize("name", ["protocol-test", "ab", "a1", "0-lab", "x" * 41])
def test_valid_lab_names(name: str) -> None:
    assert validate_lab_name(name) == name


@pytest.mark.parametrize(
    "name", ["", "a", "-lab", "Lab", "lab_1", "lab.1", "x" * 42, "../etc", "lab name", "lab\n", "@lab", "lab;id"]
)
def test_invalid_lab_names(name: str) -> None:
    with pytest.raises(InvalidInputError):
        validate_lab_name(name)


@pytest.mark.parametrize(
    "image",
    [
        "alpine",
        "alpine:3.20",
        "library/alpine:3.20",
        "docker.io/library/alpine:3.20",
        "ghcr.io/org/tool:v1.2.3",
        "localhost:5000/tools/x",
        "registry.example.com:8443/a/b/c:tag_1",
        "alpine@sha256:" + "a" * 64,
        "alpine:3.20@sha256:" + "0" * 64,
    ],
)
def test_valid_images(image: str) -> None:
    assert validate_image(image) == image


@pytest.mark.parametrize(
    "image",
    [
        "",
        "Alpine",
        "alpine:",
        "alpine:3.20 --privileged",
        "alpine;rm -rf /",
        "$(id)",
        "`id`",
        "alpine\n",
        " alpine",
        "-alpine",
        "alpine:-tag",
        "alpine@sha256:abc",
        "alpine:tag:tag",
        "../alpine",
        "alpine/",
        "http://alpine",
        "a" * 300,
    ],
)
def test_invalid_images(image: str) -> None:
    with pytest.raises(InvalidInputError):
        validate_image(image)


def test_resource_limits_are_validated_and_bounded() -> None:
    assert normalize_memory("512M") == "512m" and normalize_memory("2g") == "2g"
    assert normalize_cpus("1.0") == "1" and normalize_cpus(0.5) == "0.5" and normalize_cpus("16") == "16"
    for memory in ("0m", "16m", "17g", "64g", "lots", "512", "-1m", "1.5g", "512mb"):
        with pytest.raises(InvalidInputError):
            normalize_memory(memory)
    for cpus in ("0", "0.05", "17", "1e3", "-1", "one", "1.234"):
        with pytest.raises(InvalidInputError):
            normalize_cpus(cpus)


# --------------------------------------------------------------------------- mounts


def test_mount_refusals(tmp_path: Path) -> None:
    raf_home = tmp_path / "rafhome"
    raf_home.mkdir()
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)

    def refused(path: Path | str) -> str:
        with pytest.raises(SecurityViolation) as info:
            validate_mount_source(str(path), raf_home=raf_home, home=home)
        return info.value.message

    assert "too broad" in refused("/")
    assert "/etc" in refused("/etc")
    assert "/etc" in refused("/etc/passwd")
    assert "/proc" in refused("/proc/self")
    assert "/dev" in refused("/dev/null")
    assert "too broad" in refused("/tmp")
    assert "home directory" in refused(home)
    assert "~/.ssh" in refused(home / ".ssh")
    assert "R$F home" in refused(raf_home)
    assert "contains the R$F home" in refused(tmp_path)

    runtime_socket = tmp_path / "docker.sock"
    runtime_socket.write_text("", encoding="utf-8")
    assert "runtime sockets" in refused(runtime_socket)
    assert "runtime sockets" in refused("/var/run/docker.sock")  # refused by name, present or not
    (tmp_path / "innocent").symlink_to(runtime_socket)
    assert "resolves to a container runtime socket" in refused(tmp_path / "innocent")
    holder = tmp_path / "holder"
    (holder / "deep").mkdir(parents=True)
    (holder / "deep" / "podman.sock").write_text("", encoding="utf-8")
    assert "podman.sock" in refused(holder)

    for bad in ("with:colon", "with,comma"):
        (tmp_path / bad).mkdir()
        assert "bind syntax injection" in refused(tmp_path / bad)
    (tmp_path / "etc-link").symlink_to("/etc")
    assert "/etc" in refused(tmp_path / "etc-link")
    (tmp_path / "tricky").mkdir()
    (tmp_path / "tricky:dir").symlink_to(tmp_path / "tricky")
    assert "bind syntax injection" in refused(tmp_path / "tricky:dir")
    sneaky = tmp_path / "x,readonly=false"
    sneaky.mkdir()
    (tmp_path / "plain-link").symlink_to(sneaky)
    assert "resolves to" in refused(tmp_path / "plain-link")

    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    assert "regular files and directories" in refused(fifo)

    with pytest.raises(NotFoundError):
        validate_mount_source(str(tmp_path / "missing"), raf_home=raf_home, home=home)
    with pytest.raises(InvalidInputError):
        validate_mount_source("relative/path", raf_home=raf_home, home=home, require_absolute=True)
    many = tmp_path / "many"
    many.mkdir()
    for index in range(5):
        (many / f"f{index}").write_text("x", encoding="utf-8")
    with pytest.raises(ResourceLimitExceeded):
        validate_mount_source(str(many), raf_home=raf_home, home=home, scan_limit=3)


def test_directories_with_unix_sockets_are_refused() -> None:
    root = Path(tempfile.mkdtemp(prefix="rlab-", dir="/tmp"))  # short path: AF_UNIX limits paths to ~107 bytes
    try:
        (root / "samples").mkdir()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(str(root / "samples" / "agent"))
            with pytest.raises(SecurityViolation, match="unix socket"):
                validate_mount_source(str(root / "samples"), raf_home=root / "rafhome", home=None)
        finally:
            listener.close()
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_mount_acceptance(tmp_path: Path, samples: Path) -> None:
    raf_home = tmp_path / "rafhome"
    resolved = samples.resolve()
    assert validate_mount_source(str(samples), raf_home=raf_home, home=None) == resolved
    (tmp_path / "samples-link").symlink_to(samples)
    assert validate_mount_source(str(tmp_path / "samples-link"), raf_home=raf_home, home=None) == resolved
    single = samples / "a.txt"
    assert validate_mount_source(str(single), raf_home=raf_home, home=None) == single.resolve()


def test_cli_mounts_are_read_only_under_lab_input(cli: Any, fake: FakeBackend, samples: Path, tmp_path: Path) -> None:
    data = cli("lab", "create", "demo", "--mount", str(samples), "--mount", str(samples / "a.txt"), "--json").json()
    assert data["schema"] == "raf.lab/v1"
    assert data["mounts"] == [
        {"source": str(samples.resolve()), "target": "/lab/input/samples", "read_only": True},
        {"source": str((samples / "a.txt").resolve()), "target": "/lab/input/a.txt", "read_only": True},
    ]
    assert cli("lab", "start", "demo").exit_code == 0
    argv = fake.created[0]
    assert ("--mount", f"type=bind,source={samples.resolve()},target=/lab/input/samples,readonly") in set(
        pairwise(argv)
    )
    assert_never_unsafe(argv)

    other = tmp_path / "elsewhere" / "samples"
    other.mkdir(parents=True)
    clash = cli("lab", "create", "clash", "--mount", str(samples), "--mount", str(other))
    assert clash.exit_code == 4 and "would both appear at /lab/input/samples" in clash.stderr
    refused = cli("lab", "create", "bad", "--mount", "/etc")
    assert refused.exit_code == 5 and "protected location" in refused.stderr and "Traceback" not in refused.stderr
    assert cli("lab", "create", "gone", "--mount", str(tmp_path / "nope")).exit_code == 3


def test_mount_sources_are_checked_again_on_start(cli: Any, fake: FakeBackend, samples: Path, tmp_path: Path) -> None:
    assert cli("lab", "create", "demo", "--mount", str(samples)).exit_code == 0
    shutil.rmtree(samples)
    decoy = tmp_path / "decoy"
    decoy.mkdir()
    samples.symlink_to(decoy)
    result = cli("lab", "start", "demo")
    assert result.exit_code == 5 and "changed since lab 'demo' was created" in result.stderr
    assert fake.created == []


def test_mount_sources_are_checked_again_on_restart(cli: Any, fake: FakeBackend, samples: Path, tmp_path: Path) -> None:
    assert cli("lab", "create", "demo", "--mount", str(samples)).exit_code == 0
    assert cli("lab", "start", "demo").exit_code == 0
    assert cli("lab", "stop", "demo").exit_code == 0
    shutil.rmtree(samples)
    samples.symlink_to("/etc")  # the runtime would bind the new target on the next start
    result = cli("lab", "start", "demo")
    assert result.exit_code == 5 and "protected location" in result.stderr
    assert [call[0] for call in fake.calls].count("start") == 1


# --------------------------------------------------------------------------- lifecycle (CLI)


def test_cli_lifecycle(cli: Any, ctx: RafContext, fake: FakeBackend, samples: Path) -> None:
    created = cli("lab", "create", "demo", "--mount", str(samples), "-d", "parser tests")
    assert created.exit_code == 0 and "Created lab 'demo'" in created.stdout
    assert "raf lab start demo" in created.stdout
    assert fake.created == []  # create only records the definition

    status = cli("lab", "status", "--json").json()
    assert status["schema"] == "raf.lab.status/v1"
    assert (status["backend"], status["available"], status["version"]) == ("fake", True, "fake-1.0")
    assert status["labs"][0]["state"] == "defined" and status["labs"][0]["live"] is True

    started = cli("lab", "start", "@lab", "--json").json()
    assert (started["state"], started["changed"], started["created"]) == ("running", True, True)
    assert started["network"] == "none" and started["user"] == "1000:1000"
    assert len(fake.created) == 1
    assert_never_unsafe(fake.created[0])
    again = cli("lab", "start", "demo")
    assert again.exit_code == 0 and "already running" in again.stdout
    assert len(fake.created) == 1

    detail = cli("lab", "status", "demo")
    assert detail.exit_code == 0 and "running" in detail.stdout and "--cap-drop ALL" in detail.stdout

    ran = cli("lab", "exec", "demo", "--", "cat", "-n", "/lab/input/samples/a.txt")
    assert ran.exit_code == 0 and ran.stdout == "hello from the lab\n"
    cid = started["container_id"]
    assert ("exec", cid, "cat", "-n", "/lab/input/samples/a.txt") in fake.calls
    flags_kept = cli("lab", "exec", "demo", "--", "grep", "-q", "--json", "x")  # nothing after -- is a raf flag
    assert ("exec", cid, "grep", "-q", "--json", "x") in fake.calls and flags_kept.stdout == "hello from the lab\n"
    assert cli("lab", "exec", "demo", "ls").exit_code == 0 and ("exec", cid, "ls") in fake.calls
    as_json = cli("lab", "exec", "demo", "--json", "--", "id").json()
    assert as_json["schema"] == "raf.lab.exec/v1" and as_json["command"] == ["id"] and as_json["exit_code"] == 0

    stopped = cli("lab", "stop", "demo", "--json").json()
    assert stopped["state"] == "exited" and stopped["changed"] is True
    not_running = cli("lab", "exec", "demo", "--", "id")
    assert not_running.exit_code == 4 and "not running" in not_running.stderr

    refused = cli("lab", "destroy", "demo")
    assert refused.exit_code == 4 and "--yes" in refused.stderr
    assert cid in fake.containers
    destroyed = cli("lab", "destroy", "demo", "--yes", "--json").json()
    assert destroyed["schema"] == "raf.lab.destroy/v1" and destroyed["container_removed"] is True
    assert fake.containers == {}
    assert cli("lab", "list", "--json").json()["items"] == []
    assert cli("lab", "status", "demo").exit_code == 3

    ops = [entry.operation for entry in lab_audit(ctx)]
    assert ops == [
        "lab.create",
        "lab.start",
        "lab.start",
        "lab.exec",
        "lab.exec",
        "lab.exec",
        "lab.exec",
        "lab.stop",
        "lab.destroy",
    ]
    exec_entry = next(e for e in lab_audit(ctx) if e.operation == "lab.exec")
    assert exec_entry.details["command"] == ["cat", "-n", "/lab/input/samples/a.txt"]
    assert exec_entry.affected == ["lab:demo"] and ctx.audit.verify()["valid"]


def test_outbound_access_requires_explicit_opt_in(cli: Any, ctx: RafContext, fake: FakeBackend) -> None:
    isolated = cli("lab", "create", "quiet", "--json").json()
    assert isolated["network"] == "none" and isolated["allow_outbound"] is False
    assert "warning" not in lab_audit(ctx)[0].details

    opened = cli("lab", "create", "online", "--allow-outbound", "--json")
    assert opened.exit_code == 0 and "outbound network access enabled" in opened.stderr
    assert opened.json()["network"] == "bridge" and opened.json()["allow_outbound"] is True
    assert "outbound" in lab_audit(ctx)[-1].details["warning"]

    assert cli("lab", "start", "quiet").exit_code == 0
    assert cli("lab", "start", "online").exit_code == 0
    quiet_argv, online_argv = fake.created
    assert ("--network", "none") in set(pairwise(quiet_argv))
    assert ("--network", "bridge") in set(pairwise(online_argv))
    start_entry = lab_audit(ctx)[-1]
    assert start_entry.operation == "lab.start" and "outbound" in start_entry.details["warning"]


def test_root_is_explicit_and_keeps_capabilities_dropped(cli: Any, ctx: RafContext, fake: FakeBackend) -> None:
    result = cli("lab", "create", "rooted", "--root")
    assert result.exit_code == 0 and "runs as root" in result.stderr
    assert "root" in lab_audit(ctx)[-1].details["warning"]
    assert cli("lab", "start", "rooted").exit_code == 0
    pairs = set(pairwise(fake.created[0]))
    assert ("--user", "0:0") in pairs and ("--cap-drop", "ALL") in pairs
    assert ("--security-opt", "no-new-privileges") in pairs


def test_invalid_names_images_and_limits_are_rejected_by_the_cli(cli: Any, fake: FakeBackend) -> None:
    for args in (
        ("Bad_Name",),
        ("ok-lab", "--image", "alpine;rm -rf /"),
        ("ok-lab", "--memory", "64g"),
        ("ok-lab", "--cpus", "99"),
        ("ok-lab", "--backend", "lxc"),
        ("ok-lab", "--description", "two\nlines"),
    ):
        result = cli("lab", "create", *args)
        assert result.exit_code == 4, args
        assert "Traceback" not in result.stderr
    assert cli("lab", "list", "--json").json()["items"] == []
    assert cli("lab", "create", "dup").exit_code == 0
    duplicate = cli("lab", "create", "dup")
    assert duplicate.exit_code == 4 and "already exists" in duplicate.stderr


def test_settings_drive_defaults(cli: Any, fake: FakeBackend) -> None:
    default = cli("lab", "create", "plain", "--json").json()
    assert (default["image"], default["memory"], default["cpus"], default["pids_limit"]) == (
        "alpine:3.20",
        "512m",
        "1",
        256,
    )
    assert default["backend"] == "auto"
    for key, value in (("lab.memory", "1G"), ("lab.default_image", "debian:stable-slim"), ("lab.backend", "docker")):
        assert cli("config", "set", key, value).exit_code == 0
    configured = cli("lab", "create", "tuned", "--json").json()
    assert (configured["image"], configured["memory"], configured["backend"]) == ("debian:stable-slim", "1g", "docker")
    assert cli("config", "set", "lab.memory", "lots").exit_code == 0
    broken = cli("lab", "create", "broken")
    assert broken.exit_code == 4 and "lab.memory" in broken.stderr


def test_exec_output_is_escaped_bounded_and_exit_codes_propagate(cli: Any, fake: FakeBackend) -> None:
    assert cli("lab", "create", "demo").exit_code == 0
    assert cli("lab", "start", "demo").exit_code == 0
    fake.exec_result = CommandResult(3, "\x1b]0;pwned\x07ok\n", "\x1b[2Jwarn\n")
    escaped = cli("lab", "exec", "demo", "--", "cat", "evil")
    assert escaped.exit_code == 3 and "exited with status 3" in escaped.stderr
    assert "\x1b" not in escaped.stdout and "\\x1b]0;pwned\\x07ok" in escaped.stdout
    assert "\x1b" not in escaped.stderr and "\\x1b[2Jwarn" in escaped.stderr
    raw = cli("lab", "exec", "--raw", "demo", "--", "cat", "evil")
    assert raw.exit_code == 3 and "\x1b]0;pwned\x07ok" in raw.stdout
    as_json = cli("lab", "exec", "demo", "--json", "--", "cat", "evil")
    error = as_json.json()["error"]  # exactly one JSON document, the failure with the full result
    assert as_json.exit_code == 3 and error["code"] == "raf.lab.command_failed"
    assert error["details"]["exit_code"] == 3 and error["details"]["stdout"] == "\x1b]0;pwned\x07ok\n"

    fake.exec_result = CommandResult(137, "partial", "", stdout_truncated=True, timed_out=True)
    slow = cli("lab", "exec", "demo", "--timeout", "2", "--", "sleep", "100")
    assert slow.exit_code == 124 and "did not finish within 2 s" in slow.stderr and "cut at" in slow.stderr
    assert "raf lab stop demo" in slow.stderr

    runs = len([call for call in fake.calls if call[0] == "exec"])
    assert cli("lab", "exec", "demo", "--").exit_code == 2  # no command
    assert cli("lab", "exec", "demo", "ls", "-la").exit_code == 2  # dash arguments need '--'
    assert cli("lab", "exec", "demo", "--timeout", "0", "--", "id").exit_code == 2
    assert cli("lab", "exec", "demo", "--max-output-kb", "999999", "--", "id").exit_code == 2
    assert len([call for call in fake.calls if call[0] == "exec"]) == runs


def test_shell_needs_a_terminal(cli: Any, fake: FakeBackend, monkeypatch: pytest.MonkeyPatch) -> None:
    assert cli("lab", "create", "demo").exit_code == 0
    assert cli("lab", "start", "demo").exit_code == 0
    piped = cli("lab", "shell", "demo")
    assert piped.exit_code == 4 and "interactive terminal" in piped.stderr
    assert cli("lab", "shell", "demo", "--json").exit_code == 4
    assert not any(call[0] == "shell" for call in fake.calls)
    monkeypatch.setattr(lab_cli, "_interactive_terminal", lambda: True)
    assert cli("lab", "shell", "demo").exit_code == 0
    assert [call for call in fake.calls if call[0] == "shell"] == [("shell", next(iter(fake.containers)))]


def test_stop_and_destroy_without_container(cli: Any, fake: FakeBackend) -> None:
    assert cli("lab", "create", "idle").exit_code == 0
    stopped = cli("lab", "stop", "idle")
    assert stopped.exit_code == 0 and "nothing to stop" in stopped.stdout
    assert cli("lab", "destroy", "idle", "--yes").exit_code == 0
    assert not any(call[0] in {"stop", "remove"} for call in fake.calls)
    assert cli("lab", "destroy", "idle", "--yes").exit_code == 3


def test_foreign_or_drifted_containers_are_never_touched(cli: Any, fake: FakeBackend) -> None:
    assert cli("lab", "create", "demo").exit_code == 0
    foreign = fake.add("raf-lab-default-demo", {"raf.lab": "demo", "raf.workspace": "default", "raf.lab.id": "f" * 32})
    started = cli("lab", "start", "demo")
    assert started.exit_code == 4 and "was not created for lab 'demo'" in started.stderr
    assert cli("lab", "status", "--json").json()["labs"][0]["state"] == "conflict"
    destroyed = cli("lab", "destroy", "demo", "--yes")
    assert destroyed.exit_code == 0 and "left untouched" in destroyed.stderr
    assert foreign in fake.containers
    assert not any(call[0] in {"start", "stop", "remove"} for call in fake.calls)

    del fake.containers[foreign]
    assert cli("lab", "create", "drift").exit_code == 0
    assert cli("lab", "start", "drift").exit_code == 0
    assert cli("lab", "stop", "drift").exit_code == 0
    container = next(iter(fake.containers.values()))
    container["privileged"] = True
    drifted = cli("lab", "start", "drift")
    assert drifted.exit_code == 4 and "no longer matches" in drifted.stderr and container["state"] == "exited"


def test_tampered_definitions_are_refused(cli: Any, ctx: RafContext, fake: FakeBackend) -> None:
    assert cli("lab", "create", "demo").exit_code == 0
    raw = ctx.store.kv.get("lab", "demo")
    raw["network"] = "host"
    ctx.store.kv.set("lab", "demo", raw)
    started = cli("lab", "start", "demo")
    assert started.exit_code == 5 and "invalid" in started.stderr and "Traceback" not in started.stderr
    assert fake.created == []
    listing = cli("lab", "list", "--json").json()
    assert listing["items"] == [] and listing["invalid"] == ["demo"]
    assert cli("lab", "destroy", "demo", "--yes").exit_code == 5
    assert cli("lab", "destroy", "demo", "--yes", "--forget").exit_code == 0
    assert ctx.store.kv.get("lab", "demo") is None


# --------------------------------------------------------------------------- unavailable backend


def test_unavailable_backend_gives_clean_errors(cli: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    runner = ScriptedRunner({"info": CommandResult(1, "\n", DAEMON_DOWN + "\n")})
    monkeypatch.setattr(lab_backend, "_FACTORY", [lambda choice: DockerBackend(executable="docker", runner=runner)])

    status = cli("lab", "status")
    assert status.exit_code == 0 and "unavailable" in status.stdout and "failed to connect" in status.stdout
    data = cli("lab", "status", "--json").json()
    assert (data["backend"], data["available"], data["version"]) == ("docker", False, None)
    assert data["reason"] == DAEMON_DOWN

    assert cli("lab", "create", "demo").exit_code == 0  # definitions need no backend
    labs = cli("lab", "status", "demo", "--json").json()["labs"]
    assert labs[0]["state"] == "defined" and labs[0]["live"] is False

    for args in (("start", "demo"), ("stop", "demo"), ("exec", "demo", "--", "id")):
        result = cli("lab", *args)
        assert result.exit_code == 6, args
        assert "Container backend 'docker' is not available." in result.stderr
        assert "failed to connect to the docker API" in result.stderr and HINT in result.stderr
        assert "Traceback" not in result.stderr + result.stdout
    error = cli("lab", "start", "demo", "--json").json()["error"]
    assert error["code"] == "raf.dependency_unavailable" and error["reason"] == DAEMON_DOWN and HINT in error["hint"]

    assert cli("lab", "destroy", "demo", "--yes").exit_code == 0  # no container was ever created
    assert {tuple(call[1:2]) for call in runner.calls} == {("info",)}


def test_destroy_keeps_track_of_containers_while_the_backend_is_down(cli: Any, fake: FakeBackend) -> None:
    assert cli("lab", "create", "demo").exit_code == 0
    assert cli("lab", "start", "demo").exit_code == 0
    fake.available, fake.reason = False, DAEMON_DOWN
    refused = cli("lab", "destroy", "demo", "--yes")
    assert refused.exit_code == 6 and "--forget" in refused.stderr
    forgotten = cli("lab", "destroy", "demo", "--yes", "--forget", "--json").json()
    assert forgotten["container_removed"] is False and "left in place" in forgotten["note"]
    assert len(fake.containers) == 1


# --------------------------------------------------------------------------- real backends, scripted CLI


def test_docker_backend_command_shapes() -> None:
    cid = "c" * 64
    document = [
        {
            "Id": cid,
            "Name": "/raf-lab-default-demo",
            "State": {"Status": "running", "Running": True, "ExitCode": 0, "StartedAt": "2026-10-07T10:00:00Z"},
            "Config": {"Labels": {"raf.lab": "demo"}, "Image": "alpine:3.20"},
            "HostConfig": {"NetworkMode": "none", "Privileged": False},
        }
    ]
    runner = ScriptedRunner(
        {
            "info": CommandResult(0, "29.8.2\n", ""),
            "create": CommandResult(0, cid + "\n", "Unable to find image 'alpine:3.20' locally\n"),
            "inspect": CommandResult(0, json.dumps(document), ""),
            "exec": CommandResult(0, "out", ""),
        }
    )
    sessions: list[list[str]] = []

    def interactive(argv: Sequence[str]) -> int:
        sessions.append(list(argv))
        return 0

    backend = DockerBackend(executable="docker", runner=runner, interactive=interactive)
    assert backend.availability() == Availability(True, None, "29.8.2")
    assert runner.calls[0] == ["docker", "info", "--format", "{{.ServerVersion}}"]
    spec = make_spec()
    assert backend.create(spec) == cid
    assert runner.calls[-1] == build_create_argv(spec, executable="docker")
    state = backend.inspect("raf-lab-default-demo")
    assert state is not None and state.running and state.name == "raf-lab-default-demo"
    assert (state.state, state.network, state.labels) == ("running", "none", {"raf.lab": "demo"})
    backend.start(cid)
    backend.stop(cid)
    backend.remove(cid)
    assert runner.calls[-3:] == [
        ["docker", "start", cid],
        ["docker", "stop", "-t", "10", cid],
        ["docker", "rm", "-f", "-v", cid],
    ]
    assert backend.exec(cid, ["ls", "-la"], timeout=5, max_output=100).stdout == "out"
    assert runner.calls[-1] == ["docker", "exec", cid, "ls", "-la"]
    assert backend.shell(cid) == 0 and sessions == [["docker", "exec", "-it", cid, "/bin/sh"]]


def test_backend_errors_are_classified() -> None:
    missing = DockerBackend(
        executable="docker", runner=ScriptedRunner({"inspect": CommandResult(1, "", "Error: No such container: x")})
    )
    assert missing.inspect("x") is None
    broken = DockerBackend(
        executable="docker",
        runner=ScriptedRunner(
            {
                "create": CommandResult(125, "", "Error response from daemon: manifest unknown\n"),
                "inspect": CommandResult(0, "not json", ""),
                "start": CommandResult(1, "", DAEMON_DOWN),
            }
        ),
    )
    with pytest.raises(LabBackendError) as created:
        broken.create(make_spec())
    assert created.value.reason == "Error response from daemon: manifest unknown"
    with pytest.raises(LabBackendError):
        broken.inspect("x")
    with pytest.raises(DependencyUnavailableError):
        broken.start("x")
    assert broken.availability().available is False  # remembered after the connection error
    hung = DockerBackend(
        executable="docker", runner=ScriptedRunner({"info": CommandResult(-1, "", "", timed_out=True)})
    )
    assert "did not answer within 5 s" in (hung.availability().reason or "")

    podman = PodmanBackend(
        executable="podman", runner=(runner := ScriptedRunner({"info": CommandResult(0, "5.2.1\n", "")}))
    )
    assert podman.availability() == Availability(True, None, "5.2.1")
    assert runner.calls == [["podman", "info", "--format", "{{.Version.Version}}"]]


def test_auto_detection(monkeypatch: pytest.MonkeyPatch) -> None:
    def scripted(docker_ok: bool, podman_ok: bool) -> Runner:
        def run(argv: Sequence[str], *, timeout: float, max_output: int = 0) -> CommandResult:
            ok = docker_ok if argv[0].endswith("docker") else podman_ok
            return CommandResult(0, "1.0\n", "") if ok else CommandResult(1, "", "daemon down")

        return run

    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(lab_backend, "run_command", scripted(False, True))
    assert make_backend("auto").name == "podman"
    monkeypatch.setattr(lab_backend, "run_command", scripted(True, True))
    assert make_backend("auto").name == "docker"
    monkeypatch.setattr(lab_backend, "run_command", scripted(False, False))
    fallback = make_backend("auto")
    assert fallback.name == "docker" and fallback.availability() == Availability(False, "daemon down", None)
    assert make_backend("podman").name == "podman"
    with pytest.raises(InvalidInputError):
        make_backend("lxc")
    monkeypatch.setattr(shutil, "which", lambda name: None)
    absent = make_backend("auto")
    assert absent.availability() == Availability(False, "the docker CLI was not found on PATH", None)


def test_run_command_bounds_output_and_time() -> None:
    big = run_command(
        [sys.executable, "-c", "import sys; sys.stdout.write('x' * 300000); sys.stderr.write('done')"],
        timeout=30,
        max_output=1000,
    )
    assert big.exit_code == 0 and big.stdout == "x" * 1000 and big.stdout_truncated
    assert big.stderr == "done" and not big.stderr_truncated
    slow = run_command([sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.5)
    assert slow.timed_out and slow.duration_s < 10
    assert run_command([sys.executable, "-c", "import sys; sys.exit(3)"], timeout=10).exit_code == 3
    assert run_command(["/nonexistent/raf-lab-test-binary"], timeout=5).exit_code == 127


def test_terminal_safe_escapes_control_sequences() -> None:
    assert terminal_safe("ok\tline\n") == "ok\tline\n"
    assert terminal_safe("a\r\nb") == "a\nb"
    assert terminal_safe("\x1b[31mred\x07") == "\\x1b[31mred\\x07"
    assert terminal_safe("x\rhidden") == "x\\x0dhidden"
    assert terminal_safe(chr(0x202E) + "evil" + chr(0x9B)) == "\\u202eevil\\x9b"


def test_service_accepts_an_injected_backend(ctx: RafContext) -> None:
    backend = FakeBackend()
    service = LabService(ctx, backend=backend)
    service.create("injected")
    result = service.start("injected")
    assert result.created and result.container is not None and result.container.running
    assert service.backend_status() == {"backend": "fake", "available": True, "reason": None, "version": "fake-1.0"}
    output = service.exec("injected", ["uname", "-a"])
    assert output.stdout == "hello from the lab\n"
    assert service.destroy("injected")["container_removed"] is True


# --------------------------------------------------------------------------- API


@pytest.fixture
def client(raf_home: Path, fake: FakeBackend) -> Iterator[Any]:
    with TestClient(create_app(env={"RAF_HOME": str(raf_home)})) as c:
        yield c


def test_api_lifecycle(client: Any, fake: FakeBackend, samples: Path) -> None:
    status = client.get("/api/v1/lab/status").json()
    assert status == {"backend": "fake", "available": True, "reason": None, "version": "fake-1.0"}

    created = client.post("/api/v1/lab/labs", json={"name": "api-lab", "mounts": [str(samples)], "description": "x"})
    assert created.status_code == 201
    body = created.json()
    assert body["network"] == "none" and body["state"] == "defined"
    assert body["mounts"] == [{"source": str(samples.resolve()), "target": "/lab/input/samples", "read_only": True}]
    assert ("--cap-drop", "ALL") in set(pairwise(body["container_args"]))
    assert client.post("/api/v1/lab/labs", json={"name": "api-lab"}).status_code == 409

    listing = client.get("/api/v1/lab/labs").json()
    assert [item["name"] for item in listing["items"]] == ["api-lab"] and listing["total"] == 1
    assert listing["items"][0]["live"] is True

    started = client.post("/api/v1/lab/labs/api-lab/start")
    assert started.status_code == 200 and started.json()["state"] == "running" and started.json()["created"] is True
    assert_never_unsafe(fake.created[0])
    assert client.get("/api/v1/lab/labs/api-lab").json()["state"] == "running"
    assert client.post("/api/v1/lab/labs/api-lab/stop").json()["state"] == "exited"

    for path in ("/api/v1/lab/labs/api-lab/exec", "/api/v1/lab/labs/api-lab/shell"):
        assert client.post(path, json={"command": ["id"]}).status_code in (404, 405)
    spec = client.get("/api/v1/openapi.json").json()
    lab_paths = [p for p in spec["paths"] if p.startswith("/api/v1/lab")]
    assert lab_paths and not any("exec" in p or "shell" in p for p in lab_paths)
    assert not any(call[0] in {"exec", "shell"} for call in fake.calls)

    deleted = client.delete("/api/v1/lab/labs/api-lab")
    assert deleted.status_code == 200 and deleted.json()["container_removed"] is True
    missing = client.get("/api/v1/lab/labs/api-lab")
    assert missing.status_code == 404 and missing.json()["error"]["code"] == "raf.not_found"


def test_api_validates_like_the_cli(client: Any) -> None:
    def create(body: dict[str, Any]) -> Any:
        return client.post("/api/v1/lab/labs", json=body)

    bad_name = create({"name": "Bad Name"})
    assert bad_name.status_code == 422 and bad_name.json()["error"]["code"] == "raf.invalid_input"
    etc = create({"name": "ok-lab", "mounts": ["/etc"]})
    assert etc.status_code == 400 and etc.json()["error"]["code"] == "raf.security_violation"
    assert create({"name": "ok-lab", "mounts": ["/var/run/docker.sock"]}).status_code == 400
    assert create({"name": "ok-lab", "mounts": ["relative/path"]}).status_code == 422
    assert create({"name": "ok-lab", "allow_outbound": "yes"}).status_code == 422
    assert create({"name": "ok-lab", "root": 1}).status_code == 422
    assert create({"name": "ok-lab", "privileged": True}).status_code == 422
    assert create({"name": "ok-lab", "image": "alpine; id"}).status_code == 422
    assert create({"name": "ok-lab", "memory": "99g"}).status_code == 422
    assert client.get("/api/v1/lab/labs").json()["items"] == []
    opened = create({"name": "net-lab", "allow_outbound": True, "cpus": 0.5})
    assert opened.status_code == 201 and opened.json()["network"] == "bridge" and opened.json()["cpus"] == "0.5"
    assert client.get("/api/v1/lab/labs/Bad%20Name").status_code == 422


def test_api_reports_an_unavailable_backend(raf_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    down = FakeBackend(available=False, reason=DAEMON_DOWN)
    monkeypatch.setattr(lab_backend, "_FACTORY", [lambda choice: down])
    with TestClient(create_app(env={"RAF_HOME": str(raf_home)})) as client:
        status = client.get("/api/v1/lab/status").json()
        assert status["available"] is False and status["reason"] == DAEMON_DOWN
        assert client.post("/api/v1/lab/labs", json={"name": "x-lab"}).status_code == 201
        response = client.post("/api/v1/lab/labs/x-lab/start")
        assert response.status_code == 503
        error = response.json()["error"]
        assert (
            error["code"] == "raf.dependency_unavailable" and error["reason"] == DAEMON_DOWN and HINT in error["hint"]
        )
        item = client.get("/api/v1/lab/labs").json()["items"][0]
        assert item["state"] == "defined" and item["live"] is False
        assert client.delete("/api/v1/lab/labs/x-lab").status_code == 200


# --------------------------------------------------------------------------- product registration


def test_manifest_and_help(cli: Any) -> None:
    info = cli("product", "info", "lab", "--json").json()
    assert (info["status"], info["category"], info["commands"]) == ("BETA", "synthetic", ["lab"])
    assert info["ui"] == {"route": "/lab", "nav": "Lab"}
    assert (REPO_ROOT / info["docs"]).is_file()
    help_text = cli("lab", "--help")
    assert help_text.exit_code == 0 and "Isolated environments" in help_text.stdout
