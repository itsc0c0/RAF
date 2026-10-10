# Installing R$F

The simplest way to install R$F on Linux is a release bundle: one archive per architecture
(`x86_64`, `aarch64`) that holds everything R$F needs and an installer. The installer works offline:
no Python, Node.js or Rust on the machine, nothing downloaded.

## From a release bundle

Download the bundle for your machine from the
[releases page](https://github.com/itsc0c0/RAF/releases) (`uname -m` tells which one), unpack it and
run `install.sh`:

```sh
curl -LO https://github.com/itsc0c0/RAF/releases/download/v0.2.0/raf-0.2.0-linux-x86_64.tar.gz
tar -xzf raf-0.2.0-linux-x86_64.tar.gz
cd raf-0.2.0-linux-x86_64
sudo ./install.sh
```

The `.zip` archive holds the same bundle (`unzip ... && sudo sh install.sh`).

| | |
|---|---|
| Installed into | `/opt/raf` (`--prefix DIR` for another directory) |
| Commands | `raf` and `raf-os`, linked into `/usr/local/bin` (`--bin-dir DIR`, or `--no-link`) |
| Without root | `./install.sh --user`: `~/.local/opt/raf`, links in `~/.local/bin` |
| Your data | `~/.raf` of whoever runs `raf` (or `$RAF_HOME`); never touched by the installer |
| Upgrade | run the newer bundle's `install.sh`; if anything fails, the previous installation is restored |
| Uninstall | `sudo /opt/raf/uninstall.sh` (asks first; `--yes` does not); your data stays |

Then:

```sh
raf demo load     # the demo workspace (fictional Raven Industries)
raf analyze       # every analysis on it
raf serve         # web workbench on http://127.0.0.1:8765 (loopback only)
raf tui           # R$F OS, the full-screen terminal panel
```

### What the bundle holds

```text
raf-0.2.0-linux-x86_64/
  install.sh, uninstall.sh   the installer (POSIX sh) and the uninstaller it copies to /opt/raf
  README.txt, LICENSE, VERSION
  BUNDLE                     version, architecture, Python version, minimum glibc, source commit
  SHA256SUMS                 SHA-256 of every file; install.sh checks them before anything else
  runtime/                   a CPython 3.12 runtime (python-build-standalone), used only by R$F
  wheels/                    R$F (with the built web workbench) and every dependency as wheels, the
                             versions and hashes of uv.lock, PostgreSQL and keyring support included
  bin/raf-os                 R$F OS, a static (musl) binary
  share/                     docs/, fixtures/ (the demo data and samples), examples/ (a systemd unit)
```

The installation, `/opt/raf`:

```text
python/      the runtime          venv/     R$F and its dependencies (a virtual environment)
bin/raf      -> venv/bin/raf      bin/raf-os -> venv/bin/raf-os (raf tui finds it there)
share/       docs, fixtures, examples          uninstall.sh, .raf-install (what was installed)
```

### What the installer does, and does not do

1. Checks the machine (Linux, the bundle's architecture, glibc 2.17 or newer, not musl) and the
   bundle's SHA-256 sums.
2. Refuses to write into a directory that is not an R$F installation (`--force` keeps it aside
   instead), or to replace `raf`/`raf-os` links that point elsewhere.
3. Moves an earlier installation aside, unpacks the runtime, creates the virtual environment and
   installs the wheels with pip, offline (`--no-index`, its own settings only: `PIP_*` variables
   and pip configuration files are ignored).
4. Checks that `raf` and `raf-os` start (with a scratch `RAF_HOME`, so no `~/.raf` is created as
   root), creates the links, records what it installed, and removes the earlier installation.

It starts no service and changes no system file. `share/examples/raf-serve.service` is a systemd
unit for `raf serve` with a hardened service user, to install yourself if you want the workbench
running; it listens on 127.0.0.1 only.

### Requirements

Linux on x86_64 or aarch64 with glibc 2.17 or newer (the release notes and each bundle's
`BUNDLE` name its minimum: the oldest glibc every dependency has wheels for): Debian, Ubuntu,
RHEL/Rocky/Alma 8+, Fedora, SUSE, Arch and their derivatives. Alpine (musl) is not supported by the bundle: use a glibc base
image in containers, or install from source. Tools: `sh`, `tar`, `gzip`, `sed`, `sha256sum`.
Optional: Docker or Podman for Lab, a PostgreSQL server for `RAF_STORAGE_URL`, an OS keyring.

Every release bundle is installed and used (demo, analyses, policy checks, terminal panel, web
workbench, upgrade, uninstall, user installation) on Debian 12, Ubuntu 24.04, AlmaLinux 8 and
Fedora 42 containers without network access before it is published (`scripts/check-release`).

## From source

Python 3.12+; Node.js 20.19+ to build the web workbench; Rust 1.88+ to build R$F OS:

```sh
git clone https://github.com/itsc0c0/RAF raf && cd raf
./scripts/bootstrap            # .venv + raf CLI (+ web build with npm, + R$F OS with cargo)
source .venv/bin/activate
```

Or a wheel with the built workbench: `(cd web && npm ci && npm run build) && ./scripts/check-wheel`,
then `pipx install dist/raf-0.2.0-py3-none-any.whl`.

## Building a release bundle

```sh
python3 scripts/build-release                     # dist/release/raf-<version>-linux-<arch>.{tar.gz,zip,sha256}
scripts/check-release dist/release/raf-*.tar.gz   # install and use it in clean containers (Docker)
```

`build-release` needs uv, npm, cargo with the `<arch>-unknown-linux-musl` target
(`rustup target add x86_64-unknown-linux-musl`) and network access; it builds for the machine it
runs on. The `Release` workflow (`.github/workflows/release.yml`) builds both architectures on
GitHub's runners, runs `check-release` on four distributions each, and publishes the archives and
their `SHA256SUMS` as a GitHub release when a `vX.Y.Z` tag matching `RAF_VERSION` is pushed (or when
it is started from the Actions tab with the tag).
