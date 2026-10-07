"""R$F Lab against a real container runtime: every isolation guarantee, checked inside a running lab.

Opt-in: ``RAF_TEST_DOCKER=1`` and a running Docker (or Podman) daemon that has, or can pull, the lab
default image (alpine:3.20). CI runs this module in its Lab job. The default suite drives Lab with an
in-memory backend (test_lab.py) and never needs a daemon.
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from raf.products.lab.backend import container_name, make_backend

pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(os.environ.get("RAF_TEST_DOCKER") != "1", reason="RAF_TEST_DOCKER=1 is not set"),
]

PROBE = (
    'echo "uid=$(id -u) gid=$(id -g) home=$HOME pwd=$(pwd)"; '
    "awk '/^(CapEff|CapBnd|NoNewPrivs):/ {print $1 $2}' /proc/self/status; "
    "echo \"ifaces=$(tail -n +3 /proc/net/dev | cut -d: -f1 | tr -d ' ' | tr '\\n' ',')\""
)


@pytest.fixture
def runtime() -> str:
    backend = make_backend("auto")
    availability = backend.availability()
    if not availability.available:
        pytest.fail(f"RAF_TEST_DOCKER=1 but no container runtime is available: {availability.reason}")
    executable: str = getattr(backend, "executable", "docker")
    return executable


@pytest.fixture
def labs(cli: Any, runtime: str) -> Iterator[list[str]]:
    """Names of the labs a test creates; whatever is left is destroyed afterwards."""
    created: list[str] = []
    yield created
    for name in created:
        if cli("--yes", "lab", "destroy", name).exit_code != 0:
            subprocess.run([runtime, "rm", "-f", container_name("default", name)], check=False, capture_output=True)


def _lab(cli: Any, labs: list[str], *options: str) -> str:
    name = f"t-{secrets.token_hex(4)}"
    labs.append(name)
    created = cli("lab", "create", name, *options)
    assert created.exit_code == 0, created.stderr
    started = cli("lab", "start", name)
    assert started.exit_code == 0, started.stdout + started.stderr
    return name


def _sh(cli: Any, lab: str, script: str, *options: str) -> Any:
    return cli("lab", "exec", lab, *options, "--", "sh", "-c", script)


def _inspect(runtime: str, container: str) -> dict[str, Any]:
    out = subprocess.run([runtime, "inspect", container], check=True, capture_output=True, text=True, timeout=60)
    data: dict[str, Any] = json.loads(out.stdout)[0]
    return data


def _probe(cli: Any, lab: str) -> dict[str, str]:
    result = _sh(cli, lab, PROBE)
    assert result.exit_code == 0, result.stderr
    values: dict[str, str] = {}
    for token in result.stdout.split():
        key, sep, value = token.partition("=") if "=" in token else token.partition(":")
        if sep:
            values[key] = value
    return values


def test_a_running_lab_is_isolated(cli: Any, runtime: str, labs: list[str], tmp_path: Path) -> None:
    samples = tmp_path / "samples"
    samples.mkdir()
    (samples / "note.txt").write_text("hello lab\n")
    name = _lab(cli, labs, "--mount", str(samples))

    # what the runtime was told
    info = _inspect(runtime, container_name("default", name))
    host = info["HostConfig"]
    assert host["NetworkMode"] == "none" and host["Privileged"] is False
    assert host["CapDrop"] == ["ALL"] and not host.get("CapAdd")
    assert "no-new-privileges" in host["SecurityOpt"]
    assert host["ReadonlyRootfs"] is True
    assert host["PidsLimit"] == 256 and host["Memory"] == 512 * 1024**2 and host["MemorySwap"] == host["Memory"]
    assert host["NanoCpus"] == 1_000_000_000
    assert info["Config"]["User"] == "1000:1000" and info["Config"]["Labels"]["raf.lab"] == name
    binds = [m for m in info["Mounts"] if m["Type"] == "bind"]
    assert [m["Destination"] for m in binds] == ["/lab/input/samples"] and not any(m["RW"] for m in binds)
    assert not any("docker.sock" in str(m.get("Source")) for m in info["Mounts"])

    # what the lab's processes get
    probe = _probe(cli, name)
    assert (probe["uid"], probe["gid"], probe["home"], probe["pwd"]) == ("1000", "1000", "/lab/work", "/lab/work")
    assert probe["CapEff"] == probe["CapBnd"] == "0000000000000000" and probe["NoNewPrivs"] == "1"
    assert probe["ifaces"] == "lo,"  # no network interface but loopback
    assert _sh(cli, name, "wget -q -T 3 -O- http://192.0.2.1/").exit_code != 0

    # file systems: read-only root and input, writable memory-backed /lab/work and /tmp, no exec from /tmp
    for path in ("/x", "/etc/x", "/lab/input/samples/x"):
        refused = _sh(cli, name, f"touch {path}")
        assert refused.exit_code != 0 and "Read-only file system" in refused.stderr, path
    assert _sh(cli, name, "cat /lab/input/samples/note.txt").stdout == "hello lab\n"
    work = _sh(cli, name, "echo kept > w.txt && cat /lab/work/w.txt && echo t > /tmp/t && cat /tmp/t")
    assert work.exit_code == 0 and work.stdout.split() == ["kept", "t"], work.stderr
    script = "printf '#!/bin/sh\\necho ran\\n' > /tmp/s.sh && chmod +x /tmp/s.sh"
    assert _sh(cli, name, f"{script} && /tmp/s.sh").exit_code == 126  # noexec
    assert _sh(cli, name, f"{script} && sh /tmp/s.sh").stdout == "ran\n"

    # limits: run time, then processes (the sleeps keep the process table full until the lab stops,
    # so nothing else can be started in it meanwhile: not even the runtime's own exec helper)
    slow = _sh(cli, name, "sleep 30", "--timeout", "2")
    assert slow.exit_code == 124 and "did not finish within 2 s" in slow.stderr
    forks = _sh(cli, name, "for i in $(seq 1 300); do sleep 60 & done; wait", "--timeout", "30")
    assert forks.exit_code != 0 and "can't fork" in forks.stderr

    # stop ends every process and empties the memory-backed directories; destroy removes the container
    assert cli("lab", "stop", name).exit_code == 0
    assert cli("lab", "start", name).exit_code == 0
    empty = _sh(cli, name, "ls -A /lab/work /tmp")
    assert empty.exit_code == 0 and empty.stdout.split() == ["/lab/work:", "/tmp:"]
    assert cli("--yes", "lab", "destroy", name).exit_code == 0
    labs.remove(name)
    gone = subprocess.run([runtime, "inspect", container_name("default", name)], capture_output=True, timeout=60)
    assert gone.returncode != 0


def test_a_root_lab_keeps_every_restriction(cli: Any, runtime: str, labs: list[str]) -> None:
    name = _lab(cli, labs, "--root")
    probe = _probe(cli, name)
    assert (probe["uid"], probe["gid"]) == ("0", "0")
    assert probe["CapEff"] == probe["CapBnd"] == "0000000000000000" and probe["NoNewPrivs"] == "1"
    assert probe["ifaces"] == "lo,"
    assert "Read-only file system" in _sh(cli, name, "touch /root/x").stderr
    assert _sh(cli, name, "echo ok > /lab/work/w && cat /lab/work/w").stdout == "ok\n"


def test_outbound_access_is_a_bridge_network_only_when_asked(cli: Any, runtime: str, labs: list[str]) -> None:
    if subprocess.run([runtime, "network", "inspect", "bridge"], capture_output=True, timeout=60).returncode != 0:
        pytest.skip("the runtime has no bridge network")
    name = _lab(cli, labs, "--allow-outbound")
    host = _inspect(runtime, container_name("default", name))["HostConfig"]
    assert host["NetworkMode"] == "bridge" and host["CapDrop"] == ["ALL"] and host["ReadonlyRootfs"] is True
