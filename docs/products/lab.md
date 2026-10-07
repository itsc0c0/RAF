# R$F Lab

R$F Lab creates isolated environments for security experiments: inspect samples safely, generate
synthetic traffic, test parsers against hostile input, reproduce configurations and validate R$F
scenarios. A lab is a container with no network, no capabilities, a read-only root filesystem, an
unprivileged user and resource limits. Host files enter a lab only as read-only mounts.

Status: **BETA** · category: synthetic environments · command: `raf lab` · API: `/api/v1/lab`

Lab needs Docker or Podman. Its tests cover the container arguments, every validation rule, the
lifecycle and the CLI and API through an in-memory backend, and the Docker/Podman backends through
a scripted command runner. `tests/products/test_lab_docker.py` runs labs on a real Docker daemon
(the Lab CI job, or locally with `RAF_TEST_DOCKER=1`) and checks every guarantee from inside the
running container: the runtime's configuration (no network, all capabilities dropped,
no-new-privileges, read-only root, limits, user, read-only binds, no socket), what a process sees
(uid, empty capability sets, `NoNewPrivs`, only the loopback interface), the file systems (read-only
root and input, writable `/lab/work` and `/tmp`, no execution from `/tmp`), the process and time
limits, emptying on stop, removal on destroy, a `--root` lab and `--allow-outbound`. Podman is
supported but has not been validated the same way. Lab never changes the host's configuration: it
does not install a runtime, start a daemon, add firewall rules or touch the network setup.

## Commands

```text
raf lab create NAME [--image IMAGE] [--mount PATH]... [--allow-outbound] [--memory 512m] [--cpus 1]
                    [--root] [--description TEXT] [--backend auto|docker|podman]
raf lab start NAME
raf lab status [NAME] [--backend auto|docker|podman]
raf lab list
raf lab shell NAME
raf lab exec NAME [--timeout S] [--max-output-kb N] [--raw] -- CMD [ARGS...]
raf lab stop NAME
raf lab destroy NAME [--forget]
```

`NAME` is 2-41 characters: lowercase letters, digits and `-`, starting with a letter or digit.
Lifecycle commands also accept `@lab` (or `@last`) for the lab used most recently in the workspace.
All commands accept the global flags (`--json`, `--quiet`, `--workspace`, `--yes` ...). JSON
documents carry a schema id: `raf.lab/v1` (create, start, stop), `raf.lab.status/v1`,
`raf.lab.list/v1`, `raf.lab.destroy/v1`, `raf.lab.exec/v1`.

```text
$ raf lab create protocol-test --mount ./samples
$ raf lab start protocol-test
$ raf lab exec protocol-test -- ls -la /lab/input/samples
$ raf lab shell protocol-test
$ raf lab stop protocol-test
$ raf lab destroy protocol-test
```

### Lifecycle

| Command | What happens |
|---|---|
| `create` | Validates everything and stores the definition in the workspace (key-value namespace `lab`). No container is created and no backend is needed. |
| `start` | Checks the backend and the mounts again, creates the container on first start (the image is pulled by the daemon if missing), then starts it. Starting a running lab changes nothing. |
| `status` | Backend availability plus each lab's live state from the backend: `defined` when no container exists, otherwise the runtime's state (`created`, `running`, `exited`, `paused` ...). `conflict` means a container with the lab's name exists but was not created for this lab. With `NAME`: every detail, including the exact container command. When the backend is unavailable, the last recorded state is shown and marked as such. |
| `list` | Definitions with their last recorded state; never contacts the backend. |
| `shell` | `docker exec -it <container> /bin/sh` attached to your terminal. Needs a terminal (use `exec` in scripts) and has no time limit: it ends when you leave the shell or the lab stops. |
| `exec` | Runs one command, see below. |
| `stop` | Stops the container (10 s grace period, then SIGKILL). The container is kept; `/lab/work` and `/tmp` are emptied. |
| `destroy` | Asks for confirmation (`--yes` in scripts), removes the container (`rm -f -v`) and deletes the definition. Mounted host paths are never modified. |

Containers are named `raf-lab-<workspace>-<name>` and labeled `raf.lab=<name>`,
`raf.workspace=<workspace>` and `raf.lab.id=<random id of the definition>`. Lab only starts, stops
or removes a container whose three labels match the definition, so it never touches a container it
did not create for that lab (for example a name collision between workspaces or R$F homes). Before
starting an existing container Lab also checks that it is not privileged and still uses the
network of the definition.

Definitions are re-validated whenever they are read. A definition that was edited in the database
into something unsafe (for example `network: host`) is refused, listed under `invalid`, and can only
be removed: `raf lab destroy NAME --forget --yes`.

## Security defaults

Every lab container is created by one function (`build_create_argv` in
`src/raf/products/lab/backend.py`) with these arguments, here for the definition
`raf lab create protocol-test` in workspace `default`:

```text
docker create --name raf-lab-default-protocol-test
  --label raf.lab=protocol-test --label raf.workspace=default --label raf.lab.id=<id>
  --network none
  --cap-drop ALL
  --security-opt no-new-privileges
  --read-only
  --tmpfs /tmp:rw,noexec,nosuid,size=64m
  --tmpfs /lab/work:rw,nosuid,size=256m,mode=1777
  --pids-limit 256 --memory 512m --memory-swap 512m --cpus 1
  --user 1000:1000
  --workdir /lab/work --env HOME=/lab/work
  [--mount type=bind,source=<resolved host path>,target=/lab/input/<name>,readonly ...]
  --entrypoint /bin/sh alpine:3.20 -c 'trap "exit 0" TERM INT; sleep 2147483647 & wait'
```

| Flag | Why |
|---|---|
| `--network none` | No network interface except loopback. Changed only by `--allow-outbound`. |
| `--cap-drop ALL` | No Linux capabilities, also with `--root`. |
| `--security-opt no-new-privileges` | setuid/setgid binaries and file capabilities cannot raise privileges. |
| `--read-only` | The image filesystem cannot be modified. |
| `--tmpfs /tmp:rw,noexec,nosuid,size=64m` | Scratch space; nothing executes from it. |
| `--tmpfs /lab/work:rw,nosuid,size=256m,mode=1777` | The working directory (and `HOME`), writable by the lab's user (`mode=1777`: the directory is not part of the image, and without a mode the runtime makes the mount point root-owned 0755). Container runtimes usually also add `nodev` and, unless `exec` is requested, `noexec` to tmpfs mounts (Docker does), so run scripts through an interpreter (`sh script.sh`, `python3 script.py`) rather than executing files directly. |
| `--pids-limit`, `--memory`, `--memory-swap`, `--cpus` | Fork bombs and runaway parsers stay contained. Swap is not used beyond the memory limit. |
| `--user 1000:1000` | Unprivileged user. `raf lab create --root` uses `--user 0:0` instead; capabilities stay dropped and no-new-privileges stays on. |
| `--entrypoint /bin/sh ... sleep` | A fixed idle process (no input is ever placed in it) keeps the lab running for `shell`/`exec` and exits promptly when the lab is stopped, so no init binary is needed. Images therefore need `/bin/sh` and `sleep` (alpine, debian, ubuntu, python ... images do; distroless images do not). |

Never used, whatever the input: `--privileged`, `--cap-add`, `--network host` (or any network other
than `none`/`bridge`), host PID/IPC/UTS/user namespaces, `--device`, `--volume`, `--volumes-from`,
and any mount of a container runtime socket. The specification object re-checks these invariants
before an argument list is built, so not even a tampered definition can produce such a container.
Seccomp, AppArmor and SELinux are left at the runtime's default profiles.

Resource limits come from the options or the settings `lab.memory` (512m), `lab.cpus` (1) and
`lab.pids_limit` (256), and are bounded: memory 32m-16g, CPUs 0.1-16 (the runtime may refuse more
CPUs than the host has), processes 16-4096. The values are stored with the definition, so a lab
keeps its configuration when settings change later.

Images are validated with a strict pattern - `[registry[:port]/]path[:tag][@sha256:<64 hex>]`,
lowercase repository paths, no spaces or shell syntax, at most 255 characters. The default is
`alpine:3.20`; `--image` or the setting `lab.default_image` choose another.

## Mounts

`--mount PATH` (repeatable, at most 8) bind-mounts an existing file or directory **read-only** at
`/lab/input/<basename>`. Mounts are for bringing samples, captures and configurations into a lab;
results leave a lab through `raf lab exec` output.

Lab resolves the path (symlinks included) and refuses:

* missing paths, and anything that is not a regular file or directory (sockets, devices, FIFOs);
* paths containing `,` or `:` (bind syntax injection), quotes, backslashes or control characters -
  checked before and after resolving symlinks;
* anything named `docker.sock` or `podman.sock`, existing or not, and links to such files;
* `/`, `/tmp`, `/var/tmp` and your home directory itself (too broad; their subdirectories are fine);
* `/etc`, `/proc`, `/sys`, `/dev`, `/boot`, `/run`, `/var/run`, `/var/lib/docker`,
  `/var/lib/containers`, the R$F home directory, and the credential directories `~/.ssh`,
  `~/.gnupg`, `~/.aws`, `~/.azure`, `~/.kube`, `~/.docker`, `~/.config/gcloud`,
  `~/.local/share/containers` - including everything below them **and every directory that
  contains one of them** (so `/var` or `/home` are refused too);
* directories that contain a unix socket or a device file anywhere below them (a read-only bind
  mount does not prevent connecting to a socket, which would be a channel to a host service), and
  directories that cannot be read completely or hold more than 100,000 entries.

Two mounts with the same basename are refused (they would share a target). The runtime binds the
mount sources again every time a container starts, so Lab checks them again before every start:
if a path was removed or replaced (for example by a symlink to another place) since `create`,
`start` refuses. Symlinks inside a mounted directory resolve inside the container, never on the
host.

Paths are resolved by the R$F process. With a remote Docker daemon (`DOCKER_HOST` or a remote
context) the daemon would resolve them on its own host - use Lab with a local daemon.

## Outbound network

Labs have no network by default. `raf lab create NAME --allow-outbound` gives the lab the runtime's
default bridge network (`--network bridge`): it can then reach the host's networks and the
internet, without any egress filtering. The choice is fixed per lab, printed as a warning, and
recorded in the audit log (`warning` detail of `lab.create` and of every `lab.start`). Lab never
creates networks, publishes ports or changes host firewall rules.

## exec and shell

`raf lab exec NAME [OPTIONS] -- CMD [ARGS...]` runs one command as an argument vector (no shell, no
terminal, no stdin) via `docker exec <container> CMD ARGS...`. Everything after `--` reaches the
command verbatim, including words such as `--json` or `-q`; without `--` a dash argument is
rejected as an unknown option. Output is captured with a limit per stream (`--max-output-kb`,
default 1024, at most 16384) and the command is abandoned after `--timeout` seconds (default 60, at
most 3600). An abandoned command may keep running inside the lab until the lab is stopped.

Output is shown as it was captured, except that control characters, terminal escape sequences and
bidirectional overrides are escaped (`\x1b`), so a hostile sample cannot rewrite your terminal;
`--raw` prints it unchanged. R$F exits with the command's status: on a non-zero status R$F prints
the output and then `R$F: The command exited with status N.`; a timeout exits with 124. With
`--json` a successful run prints a `raf.lab.exec/v1` document (`command`, `exit_code`, `stdout`,
`stderr`, truncation flags, `duration_s`); a failed run prints one `raf.error/v1` document with code
`raf.lab.command_failed` whose `details` hold the same fields.

`raf lab shell NAME` opens `/bin/sh` in the lab as the lab's user, in `/lab/work`.

## Backends

`--backend` (on `create` and `status`) chooses `docker`, `podman` or `auto` (default). `auto` uses
Docker when `docker info --format '{{.ServerVersion}}'` answers within 5 seconds, else Podman when
`podman info --format '{{.Version.Version}}'` answers, else reports why the first installed CLI is
unavailable. After the first start the definition records the backend that holds the container,
and later commands use it.

When no backend is available, commands that need one fail with exit code 6 (HTTP 503):

```text
R$F: Container backend 'docker' is not available.

Reason:
  failed to connect to the docker API at unix:///var/run/docker.sock; check if the path is correct
  and if the daemon is running: dial unix /var/run/docker.sock: connect: no such file or directory

Install Docker or Podman and make sure the daemon is running; 'raf lab status' shows the backend.
```

`create`, `list` and `status` keep working. `destroy` also works for labs that never had a
container; for others it refuses (it would lose track of the container) unless `--forget` is given,
which deletes the definition and leaves the container in place.

Every container CLI call runs without a shell and with a timeout: availability 5 s, inspect 15 s,
create 300 s (includes pulling the image), start 60 s, stop 40 s, remove 60 s. Errors reported by
the runtime (for example an unknown image) fail with code `raf.lab.backend` (exit code 1, HTTP 502)
and the runtime's message as the reason.

## API

| Method | Path | Result |
|---|---|---|
| GET | `/lab/status?backend=` | `{backend, available, reason, version}` |
| GET | `/lab/labs` | `{items: [Lab], total}` - live state when the backend is available (`live: true`), else the last recorded state |
| POST | `/lab/labs` `{name, image?, mounts?, allow_outbound?, memory?, cpus?, root?, description?, backend?}` | 201, the Lab with `container_args` |
| GET | `/lab/labs/{name}` | the Lab in detail (`container_args`: the exact container command) |
| POST | `/lab/labs/{name}/start`, `/lab/labs/{name}/stop` | the Lab plus `changed`, `created` |
| DELETE | `/lab/labs/{name}?forget=false` | `{name, destroyed, container, container_removed, note?}` |

A Lab document has `name`, `state`, `live`, `image`, `network`, `allow_outbound`,
`mounts: [{source, target, read_only}]`, `memory`, `cpus`, `pids_limit`, `user`, `root`, `backend`,
`container`, `container_id`, `description`, `created_at`, `updated_at`, `state_at` and, when
relevant, `note`. The create body rejects unknown fields, `allow_outbound` and `root` must be JSON
booleans, and mount paths are validated by the same function as on the command line; they must be
absolute because they are resolved on the server. Refused mounts return 400
(`raf.security_violation`), invalid input 422, unknown labs 404, conflicts 409, an unavailable
backend 503.

There is deliberately **no shell or exec route**. Running commands in a lab over HTTP would make
the API a remote command execution service: `raf serve` can be exposed beyond loopback with a
token, and any browser on the machine can reach a loopback API. Commands run in a lab only through
the local CLI.

## Audit

`lab.create`, `lab.start`, `lab.stop`, `lab.destroy`, `lab.exec` (the command, bounded to 32
arguments of 200 characters, exit code, timeout and truncation) and `lab.shell` are recorded in the
workspace audit log (`raf audit`) with the affected `lab:<name>`. Outbound access and `--root`
add a `warning` detail.

## Configuration

| Key | Default | Notes |
|---|---|---|
| `lab.backend` | `auto` | `auto` (a running Docker, else a running Podman), `docker` or `podman`; `--backend` overrides it per lab. |
| `lab.default_image` | `alpine:3.20` | Image for labs created without `--image` (global or workspace config, `RAF_LAB_DEFAULT_IMAGE`); validated like `--image`. |
| `lab.memory` | `512m` | Default memory limit for new labs. |
| `lab.cpus` | `1.0` | Default CPU limit for new labs. |
| `lab.pids_limit` | `256` | Process limit for new labs (16-4096). |

## Limitations

* Requires Docker or Podman with a running daemon or service. CI validates Docker; Podman (and
  rootless runtimes) have not been run against the isolation checks yet.
* Linux and macOS hosts. Paths containing `,`, `:`, quotes or backslashes cannot be mounted, which
  also rules out Windows paths.
* Inside the container the lab runs as uid/gid 1000 (or 0 with `--root`). Mounted files must be
  readable by that user; with rootless or user-namespaced runtimes the IDs are mapped, so
  world-readable files are the safe choice.
* `/lab/work` and `/tmp` are memory-backed and emptied when the lab stops; there is no writable
  host mount. Copy results out through `raf lab exec` output.
* Mount checks are made at `create` and before every start; changes to a mounted directory while
  the lab runs (for example a socket created in it afterwards) are not detected.
* `--allow-outbound` is all-or-nothing: no egress filtering, no DNS policy, no port publishing.
* `exec` has no stdin and no terminal; an abandoned command may keep running until `stop`.
* Images must provide `/bin/sh` and `sleep`.
