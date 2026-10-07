"""``raf lab``: isolated container environments for security experiments."""

from __future__ import annotations

import shlex
import sys
from typing import Any

import typer
from rich.text import Text

from raf.core.errors import InvalidInputError, RafError
from raf.core.security.text import terminal_safe
from raf.products.lab.service import (
    EXEC_DEFAULT_OUTPUT_KB,
    EXEC_DEFAULT_TIMEOUT,
    EXEC_MAX_OUTPUT_KB,
    EXEC_MAX_TIMEOUT,
    OUTBOUND_WARNING,
    ROOT_WARNING,
    LabService,
    LifecycleResult,
)
from raf.sdk import cli as rt

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
    help="""Isolated environments for security experiments (Docker or Podman containers).

Examples:
  raf lab create protocol-test --mount ./samples
  raf lab start protocol-test
  raf lab shell protocol-test
  raf lab exec protocol-test -- ls -la /lab/input
  raf lab stop protocol-test
  raf lab destroy protocol-test

Secure by default: no network, all capabilities dropped, no-new-privileges, read-only root
filesystem, unprivileged user, process/memory/CPU limits, read-only mounts under /lab/input.
Outbound network access only with --allow-outbound. The host is never reconfigured.""",
)

_NAME_HELP = "Lab name (or @lab / @last for the lab used most recently)."
_STATE_STYLE = {
    "running": "bold green",
    "defined": "dim",
    "created": "cyan",
    "exited": "yellow",
    "stopped": "yellow",
    "paused": "yellow",
    "dead": "red",
    "conflict": "bold red",
}


class LabCommandFailed(RafError):
    """The command run by ``raf lab exec`` failed; R$F exits with the command's own status.

    Raised (instead of ``typer.Exit``) so the status reaches the shell through the regular
    error path, also inside the interactive ``raf`` shell.
    """

    code = "raf.lab.command_failed"

    def __init__(self, message: str, *, exit_code: int, **kwargs: Any) -> None:
        super().__init__(message, **kwargs)
        self.exit_code = exit_code


def _service() -> LabService:
    return LabService(rt.ctx())


def _interactive_terminal() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


# --------------------------------------------------------------------------- rendering


def _state_text(lab: dict[str, Any]) -> Text:
    state = str(lab["state"])
    text = Text(state, style=_STATE_STYLE.get(state, ""))
    if not lab.get("live"):
        text.append(" (last known)", style="dim")
    return text


def _network_text(lab: dict[str, Any]) -> Text:
    if lab["allow_outbound"]:
        return Text("bridge - outbound access allowed", style="yellow")
    return Text("none - isolated", style="green")


def _backend_text(status: dict[str, Any]) -> Text:
    text = Text(str(status["backend"]))
    if status["available"]:
        if status.get("version"):
            text.append(f" {status['version']}")
        text.append("  available", style="green")
    else:
        text.append("  unavailable", style="bold red")
    return text


def _resources(lab: dict[str, Any]) -> str:
    cpus = str(lab["cpus"])
    return f"{lab['memory']} memory, {cpus} CPU{'' if cpus == '1' else 's'}, {lab['pids_limit']} processes"


def _user(lab: dict[str, Any]) -> str:
    if lab["root"]:
        return f"{lab['user']} (root inside the container; capabilities dropped)"
    return f"{lab['user']} (unprivileged)"


def _definition_rows(lab: dict[str, Any]) -> list[tuple[str, Any]]:
    rows: list[tuple[str, Any]] = [("Image", lab["image"]), ("Network", _network_text(lab))]
    mounts = lab["mounts"]
    if not mounts:
        rows.append(("Mounts", "none"))
    for index, mount in enumerate(mounts):
        rows.append(("Mounts" if index == 0 else "", f"{mount['source']} → {mount['target']} (read-only)"))
    rows += [("Resources", _resources(lab)), ("User", _user(lab))]
    return rows


def render_lab(lab: dict[str, Any], *, backend: dict[str, Any] | None = None) -> None:
    rt.header(f"R$F LAB  {lab['name']}", lab.get("description") or None)
    container = lab["container"] + (f"  {lab['container_id'][:12]}" if lab.get("container_id") else "")
    rows: list[tuple[str, Any]] = [("State", _state_text(lab)), *_definition_rows(lab), ("Container", container)]
    rows.append(("Backend", _backend_text(backend) if backend else lab["backend"]))
    if backend and not backend["available"] and backend.get("reason"):
        rows.append(("Reason", backend["reason"]))
    rows.append(("Created", lab.get("created_at") or "-"))
    rt.kv_block(rows, width=12)
    if lab.get("container_args"):
        c = rt.console()
        c.print()
        c.print(Text("Container command (created on first start)", style="bold"))
        c.print(Text("  " + shlex.join(lab["container_args"]), style="dim"))
    if lab.get("note"):
        rt.note(str(lab["note"]))


def _lab_rows(labs: list[dict[str, Any]]) -> list[tuple[Any, ...]]:
    return [
        (
            lab["name"],
            _state_text(lab),
            lab["image"],
            "bridge (outbound)" if lab["allow_outbound"] else "none",
            len(lab["mounts"]),
            lab["container"],
        )
        for lab in labs
    ]


def _warn_invalid(names: list[str]) -> None:
    for name in names:
        rt.warn(f"lab '{name}' has an invalid stored definition and is ignored (raf lab destroy {name} --forget --yes)")


def _suggestions(lab: dict[str, Any]) -> list[str]:
    name = lab["name"]
    if lab["state"] == "running":
        return [f"raf lab shell {name}", f"raf lab exec {name} -- ls -la /lab", f"raf lab stop {name}"]
    return [f"raf lab start {name}", f"raf lab destroy {name}"]


def render_status(data: dict[str, Any], *, detail: bool) -> None:
    labs: list[dict[str, Any]] = data["labs"]
    if detail and labs:
        render_lab(labs[0], backend=data)
    else:
        rt.header("R$F LAB")
        rows: list[tuple[str, Any]] = [("Backend", _backend_text(data))]
        if not data["available"] and data.get("reason"):
            rows.append(("Reason", data["reason"]))
        rt.kv_block(rows, width=12)
        c = rt.console()
        c.print()
        if labs:
            rt.table(["LAB", "STATE", "IMAGE", "NETWORK", "MOUNTS", "CONTAINER"], _lab_rows(labs))
        else:
            c.print("No labs in this workspace yet.")
        _warn_invalid(list(data.get("invalid", [])))
    if not data["available"]:
        rt.note("Install Docker or Podman and make sure the daemon is running; labs can be created meanwhile.")
    rt.next_steps(_suggestions(labs[0]) if labs else ["raf lab create <name>"])


# --------------------------------------------------------------------------- commands


@app.command("create", help="Define a lab: validated and recorded, no container yet ('start' creates it).")
def create_cmd(
    name: str = typer.Argument(..., help="Lab name: 2-41 lowercase letters, digits or '-'."),
    image: str | None = typer.Option(
        None, "--image", help="Container image (default alpine:3.20 or the lab.default_image setting)."
    ),
    mounts: list[str] | None = typer.Option(
        None, "--mount", help="Existing host file or directory, mounted read-only at /lab/input/<name> (repeatable)."
    ),
    allow_outbound: bool = typer.Option(
        False, "--allow-outbound", help="Allow outbound network access (bridge network). Off by default."
    ),
    memory: str | None = typer.Option(None, "--memory", help="Memory limit, 32m to 16g (default lab.memory: 512m)."),
    cpus: str | None = typer.Option(None, "--cpus", help="CPU limit, 0.1 to 16 (default lab.cpus: 1)."),
    root: bool = typer.Option(False, "--root", help="Run as root inside the container (capabilities stay dropped)."),
    description: str = typer.Option("", "--description", "-d", help="One-line note about the experiment."),
    backend: str | None = typer.Option(None, "--backend", help="auto (default), docker or podman."),
) -> None:
    service = _service()
    lab = service.create(
        name,
        image=image,
        mounts=mounts or [],
        allow_outbound=allow_outbound,
        memory=memory,
        cpus=cpus,
        root=root,
        description=description,
        backend=backend,
    )
    if lab.allow_outbound:
        rt.warn(OUTBOUND_WARNING)
    if lab.root:
        rt.warn(ROOT_WARNING)
    data = service.payload(lab)

    def render() -> None:
        rt.success(f"Created lab '{lab.name}' (not started; the container is created by 'raf lab start').")
        rt.console().print()
        rt.kv_block([*_definition_rows(data), ("Container", data["container"])], width=12)
        rt.next_steps([f"raf lab start {lab.name}", f"raf lab status {lab.name}"])

    rt.output("raf.lab/v1", data, render)


@app.command("list", help="Labs of this workspace with their last recorded state (no backend needed).")
def list_cmd() -> None:
    service = _service()
    labs = [service.payload(lab) for lab in service.labs()]
    invalid = service.invalid_definitions()
    data: dict[str, Any] = {"items": labs, "total": len(labs)}
    if invalid:
        data["invalid"] = invalid

    def render() -> None:
        rt.header("R$F LABS", f"workspace {service.workspace}")
        if labs:
            rt.table(["LAB", "STATE", "IMAGE", "NETWORK", "MOUNTS", "CONTAINER"], _lab_rows(labs))
            rt.note("States are the last recorded ones; 'raf lab status' asks the backend.")
        else:
            rt.console().print("No labs in this workspace yet.")
        _warn_invalid(invalid)
        rt.next_steps(["raf lab status"] if labs else ["raf lab create <name>"])

    rt.output("raf.lab.list/v1", data, render)


@app.command("status", help="Backend availability and the live state of every lab (or one lab in detail).")
def status_cmd(
    name: str | None = typer.Argument(None, help=_NAME_HELP),
    backend: str | None = typer.Option(None, "--backend", help="Check this backend: auto, docker or podman."),
) -> None:
    service = _service()
    lab_name = service.resolve_name(name) if name else None
    data = service.status(lab_name, backend=backend)
    rt.output("raf.lab.status/v1", data, lambda: render_status(data, detail=lab_name is not None))


def _lifecycle_payload(service: LabService, result: LifecycleResult) -> dict[str, Any]:
    data = service.payload(result.lab, live=True, note=result.note)
    data["changed"] = result.changed
    data["created"] = result.created
    return data


@app.command("start", help="Create the lab's container if needed (secure defaults) and start it.")
def start_cmd(name: str = typer.Argument(..., help=_NAME_HELP)) -> None:
    service = _service()
    result = service.start(service.resolve_name(name))
    lab = result.lab
    if lab.allow_outbound:
        rt.warn(OUTBOUND_WARNING)
    data = _lifecycle_payload(service, result)

    def render() -> None:
        container = data["container"] + (f" ({str(data['container_id'])[:12]})" if data.get("container_id") else "")
        if result.changed:
            rt.success(f"Started lab '{lab.name}': container {container} is {data['state']}.")
        else:
            rt.console().print(f"Lab '{lab.name}' is already running (container {container}).")
        if result.note and result.changed:
            rt.warn(result.note)
        rt.next_steps(_suggestions(data))

    rt.output("raf.lab/v1", data, render)


@app.command("stop", help="Stop the lab's container (it is kept; /lab/work and /tmp are emptied).")
def stop_cmd(name: str = typer.Argument(..., help=_NAME_HELP)) -> None:
    service = _service()
    result = service.stop(service.resolve_name(name))
    lab = result.lab
    data = _lifecycle_payload(service, result)

    def render() -> None:
        if result.changed:
            rt.success(f"Stopped lab '{lab.name}' ({data['state']}).")
        else:
            rt.console().print(f"Lab '{lab.name}': {result.note or 'nothing to stop'}.")
        rt.next_steps([f"raf lab start {lab.name}", f"raf lab destroy {lab.name}"])

    rt.output("raf.lab/v1", data, render)


@app.command("destroy", help="Remove the lab's container and its definition (asks for confirmation).")
def destroy_cmd(
    name: str = typer.Argument(..., help=_NAME_HELP),
    forget: bool = typer.Option(
        False,
        "--forget",
        help="Delete the definition even when the backend is unavailable (a container is then left in place).",
    ),
) -> None:
    service = _service()
    lab_name = service.resolve_name(name)
    if not service.exists(lab_name):
        service.get(lab_name)  # raises the standard "does not exist" error
    container = service.container_name(lab_name)
    rt.confirm(
        f"Destroy lab '{lab_name}'?",
        [
            f"Removes container {container} if it exists (anything in /lab/work and /tmp is lost).",
            "Deletes the lab definition from this workspace. Mounted host paths are not modified.",
        ],
    )
    result = service.destroy(lab_name, forget=forget)

    def render() -> None:
        suffix = "container removed" if result["container_removed"] else "no container removed"
        rt.success(f"Destroyed lab '{lab_name}' ({suffix}).")
        if result.get("note"):
            rt.warn(str(result["note"]))

    rt.output("raf.lab.destroy/v1", result, render)


@app.command("shell", help="Interactive /bin/sh inside a running lab (needs a terminal).")
def shell_cmd(name: str = typer.Argument(..., help=_NAME_HELP)) -> None:
    if rt.STATE.json:
        raise InvalidInputError(
            "raf lab shell is interactive and has no JSON output.", hint="Use: raf lab exec NAME --json -- CMD"
        )
    if not _interactive_terminal():
        raise InvalidInputError(
            "raf lab shell needs an interactive terminal.",
            hint="In scripts and pipelines use: raf lab exec NAME -- CMD [ARGS...]",
        )
    service = _service()
    lab_name = service.resolve_name(name)
    rt.note(f"Entering lab '{lab_name}' (exit the shell to return).")
    code = service.shell(lab_name)
    if code not in (0, 130):
        rt.note(f"The shell session ended with status {code}.")


@app.command(
    "exec",
    help="Run one command in a running lab: no shell, no terminal, output captured with limits. "
    "Put the command after '--' (raf lab exec NAME [OPTIONS] -- CMD [ARGS...]); nothing after '--' is read "
    "by R$F. Exits with the command's status (124 on timeout).",
)
def exec_cmd(
    name: str = typer.Argument(..., help=_NAME_HELP),
    command: list[str] = typer.Argument(..., help="Command and arguments (an argument vector, not a shell line)."),
    timeout: int = typer.Option(
        EXEC_DEFAULT_TIMEOUT, "--timeout", min=1, max=EXEC_MAX_TIMEOUT, help="Seconds before the command is abandoned."
    ),
    max_output_kb: int = typer.Option(
        EXEC_DEFAULT_OUTPUT_KB, "--max-output-kb", min=1, max=EXEC_MAX_OUTPUT_KB, help="Output kept per stream (KB)."
    ),
    raw: bool = typer.Option(False, "--raw", help="Print output as is (control characters are escaped by default)."),
) -> None:
    argv = list(command)  # Click consumed the '--' separator; everything after it arrives verbatim
    service = _service()
    lab_name = service.resolve_name(name)
    result = service.exec(lab_name, argv, timeout=timeout, max_output_kb=max_output_kb)
    data = {
        "lab": lab_name,
        "command": argv,
        "exit_code": result.exit_code,
        "timed_out": result.timed_out,
        "duration_s": result.duration_s,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "stdout_truncated": result.stdout_truncated,
        "stderr_truncated": result.stderr_truncated,
    }

    def render() -> None:
        sys.stdout.write(result.stdout if raw else terminal_safe(result.stdout))
        sys.stdout.flush()
        sys.stderr.write(result.stderr if raw else terminal_safe(result.stderr))
        sys.stderr.flush()

    failed = result.timed_out or result.exit_code != 0
    if not (failed and rt.STATE.json):  # with --json a failure is reported once, as the error document
        rt.output("raf.lab.exec/v1", data, render)
    if result.stdout_truncated or result.stderr_truncated:
        rt.warn(f"output was cut at {max_output_kb} KB per stream (--max-output-kb)")
    details = data if rt.STATE.json else None
    if result.timed_out:
        raise LabCommandFailed(
            f"The command did not finish within {timeout} s and was abandoned.",
            exit_code=124,
            hint=f"It may still run inside the lab until 'raf lab stop {lab_name}'.",
            details=details,
        )
    if result.exit_code:
        raise LabCommandFailed(
            f"The command exited with status {result.exit_code}.", exit_code=result.exit_code, details=details
        )
