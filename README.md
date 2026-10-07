# R$F

**Every security capability. One command away.**

R$F (pronounced "RAF") is a defensive security workstation. It imports security data (logs, event
streams, packet captures, inventories, policies, SBOMs, evidence), normalizes everything into one
shared security object model, and lets twenty products work on that model together: a graph of
identities, hosts, services and credentials; unified timelines; causal traces; deterministic incident
replay; snapshots and diffs; blast radius, IAM, policy and exposure analysis with explainable risk
scores; what-if digital twins; synthetic ranges and telemetry; packet, secret, dependency and evidence
analysis; and Oracle, which answers questions about the workspace with citations to the data.

Everything runs locally: a CLI (`raf`), a full-screen terminal control panel (R$F OS, `raf tui`), an
HTTP API and a web workbench, over a SQLite workspace.

> **Defensive use only.** R$F analyzes data you are authorized to hold and models environments you
> are authorized to assess. It does not scan arbitrary Internet targets, exploit systems, deploy
> payloads or harvest credentials. Offensive behavior exists only as synthetic, clearly labeled data
> (Range, Forge) or as benign actions inside isolated, local labs (Lab). See
> [docs/security-model.md](docs/security-model.md).

Version 0.1.0 (initial development; see [product status](#products) and
[docs/implementation-status.md](docs/implementation-status.md)).

## Screenshots

R$F OS (`raf tui`) on the demo dataset, TRACE page: how incident INC-001 went from an outside
address to production. A text capture of the terminal; in color, observed edges are bright green,
modeled ones dim.

```text
 R$F OS  v0.1.0 │ workspace default │ ● ONLINE 195ms │ api 127.0.0.1:44447              2026-10-07 15:09:54 UTC
  HOME   TIMELINE   TRACE   IAM   BLAST   EXPOSURE   POLICY   GHOST   GRAPH   ORACLE   FINDINGS   EVIDENCE  ────
┌ ◢ PAGES ─────────────┐┌ ◈ TRACE ─────────────────────────────────────────────────────────────────────── 1/61 ┐
│ 1  HOME              ││ incident or object ❯ INC-001                                                  / edit │
│ 2  TIMELINE          ││▌R$F TRACE — INC-001                                                                 ┃│
│▶3  TRACE             ││ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ┃│
│ 4  IAM               ││ entry → production                                                                  ┃│
│ 5  BLAST             ││                                                                                     ┃│
│ 6  EXPOSURE          ││›                203.0.113.45 [ip]                                                   ┃│
│ 7  POLICY            ││                      │                                                              ┃│
│ 8  GHOST             ││                      │ network observation   ● observed 22:52:11.000 auth.login     ┃│
│ 9  GRAPH             ││                      ▼                                                              ┃│
│ 0  ORACLE            ││›                   VPN-01 [host]                                                    ┃│
│    FINDINGS          ││                      │                                                              ┃│
│    EVIDENCE          ││                      │ authenticated as      ● observed 22:52:11.000 auth.login     ┃│
└──────────────────────┘│                      ▼                                                              ┃│
┌ FOCUS ───────────────┐│›                    bob [user]                                                      ││
│ ⚑ INC-001            ││›                     │                                                              ││
│ ◉ bob                ││›                     │ logged into           ● observed 22:58:03.000 auth.login     ││
│ ◎ production         ││›                     ▼                                                              ││
│ ❯ INC-001            ││›                   DEV-01 [host]                                                    ││
└──────────────────────┘│›                     │                                                              ││
┌ WORLD ───────────────┐│›                     │ contains              ● observed 23:01:47.000 file.read      ││
│ objects          426 ││›                     ▼                                                              ││
│ relationships    849 ││›                    .env [file]                                                     ││
│ events           562 ││›                     │                                                              ││
│ open findings     42 ││›                     │ contains secret       ◌ modeled                              ││
│ incidents          1 ││›                     ▼                                                              ││
└──────────────────────┘│›      DEPLOY_TOKEN in /opt/deploy/.env [secret]                                     ││
┌ SIGNAL ──────────────┐│›                     │                                                              ││
│ ✔ trace        195ms ││›                     │ authenticates as      ● observed 23:04:41.000 auth.login     ││
│ ✔ home         311ms ││›                     ▼                                                              ││
└──────────────────────┘└──────────────────────────────────────────────────────────────────────────────────────┘
 ←→ pages  ↑↓ line  ⏎ inspect  / param  r reload  v graph  m rain  ? help  q quit                          3/12
```

`raf demo load` followed by `raf serve` shows the web workbench with the same data; every command
below works on the demo dataset.

## Installation

Requirements: Python 3.12+. Optional: Node.js 20.19+ to build the web workbench, Rust (stable,
1.88+) to build R$F OS, Docker or Podman for Lab, the `keyring` extra for OS keyring secrets.

```bash
git clone <repository-url> raf && cd raf
./scripts/bootstrap            # .venv + raf CLI (+ web build with npm, + R$F OS with cargo)
source .venv/bin/activate
```

Manual installation: `uv sync` (uses `uv.lock`), or `python3.12 -m venv .venv && .venv/bin/pip
install -e . --group dev` (pip 25.1 or newer); then `cd web && npm ci && npm run build` for the
workbench, and `cargo build --release --manifest-path tui/Cargo.toml` for R$F OS.

## Quick start

```bash
raf demo load                  # fictional Raven Industries: inventory, a working day, incident INC-001, evidence
raf graph alice                # what alice is connected to
raf blast alice                # what an attacker controlling alice could reach, and why
raf timeline alice             # everything alice did
raf replay INC-001             # the incident, reconstructed step by step
raf oracle ask "Explain the most important security path in INC-001"
raf tui                        # R$F OS: the full-screen terminal control panel (keyboard and mouse)
raf serve                      # API + web workbench on http://127.0.0.1:8765
```

`raf analyze <file or directory>` is the general entry point for your own data: it detects what the
input is (packet capture, JSON/JSONL/CSV/syslog/access logs, policy documents, SBOMs, repositories,
R$F bundles), runs the matching products, shows every step, and records the result as `analysis-N`
for `raf lens|graph|timeline analysis-N`. See [docs/analyze.md](docs/analyze.md).

Every command supports `--json` (documents carry a `schema` id), `--quiet`, `--no-color`,
`--debug`, `--yes` and `--workspace NAME`; `raf` without arguments opens an interactive shell.
`@last` refers to the last object, incident or analysis you looked at.

## Example workflow

The signature workflow, run end to end by `tests/integration/test_end_to_end.py`:

```bash
raf workspace create demo && raf workspace use demo
raf range create raven --seed 42          # a synthetic organization (deterministic)
raf range start raven                     # simulated routine activity
raf graph user alice
raf forge scenario suspicious-access --seed 99   # modeled, harmless scenario events
raf analyze ./fixtures/raven-events.jsonl
raf timeline user alice
raf trace alice
raf blast alice
raf snapshot create before
raf ghost clone current hardened          # a what-if model (no real system is touched)
raf ghost modify hardened --remove-access alice:production
raf snapshot create after --source ghost:hardened
raf diff before after                     # what changed, ranked by importance, with reasons
raf evidence case create INC-001
raf evidence import ./fixtures/evidence --case INC-001   # hashed, read-only, chain of custody
raf replay INC-001
raf oracle ask "Explain the most important security path in INC-001"
```

Oracle's answer for INC-001 (builtin reasoner, abridged): bob → DEV-01 → `/opt/deploy/.env` →
`DEPLOY_TOKEN` → svc-deploy → deployers → prod-deployer → ci-cd → production, with three of the
eight steps confirmed by the incident's own events (bob's login to DEV-01, the read of `.env`,
svc-deploy's login to CI-01), the other principals that control DEV-01, related findings, and a
suggested Ghost experiment that removes the credential exposure. Every statement cites R$F IDs.

## R$F OS

`raf tui` opens R$F OS, a full-screen terminal control panel for Linux terminals: twelve pages (home,
timeline, trace, IAM, blast, exposure, policy, ghost, graph, oracle, findings, evidence) switched with
the arrow keys or the mouse, an inspector for any object, event or finding, and a boot sequence with
digital rain. The panel (`tui/`, Rust + Ratatui) draws screens that the R$F API computes from the same
services as the CLI; `raf tui` serves them on a random loopback port with a one-time token, and
nothing is changed in the workspace. `raf tui --dump PAGE` prints a page as plain text. See
[docs/tui.md](docs/tui.md).

## Products

| Product | Command | Status | What it does |
|---|---|---|---|
| Graph | `raf graph` | BETA | Security relationship graph: neighborhoods, paths, temporal views, export |
| Timeline | `raf timeline` | BETA | Unified event timelines with filters, grouping and JSON/CSV/R$F export |
| Trace | `raf trace` | BETA | Causal chains around an object: observed links vs. labeled correlations |
| Replay | `raf replay` | BETA | Deterministic incident reconstruction (state at T, windows, playback) |
| Diff | `raf diff` | BETA | Compare snapshots, the current state and Ghost models, with explained importance |
| Blast | `raf blast` | BETA | Blast radius of a hypothetical compromise with explainable paths and risk |
| IAM | `raf iam` | BETA | Effective access, privilege paths, risky identities |
| Policy | `raf policy` | BETA | Normalize and analyze firewall and access policies; evaluate flows |
| Exposure | `raf exposure` | BETA | Explainable exposure of every asset (criticality, reachability, vulnerabilities, control paths) |
| Ghost | `raf ghost` | BETA | Security digital twins: what-if models, simulated exposure, comparisons |
| Range | `raf range` | BETA | Synthetic organizations with deterministic seeds and simulated activity |
| Forge | `raf forge` | BETA | Synthetic telemetry and modeled scenarios |
| Lab | `raf lab` | EXPERIMENTAL | Isolated Docker/Podman labs (no network, no capabilities, read-only by default) |
| Protocol | `raf protocol` | BETA | Packet captures: explained fields, flows, DNS/HTTP/TLS metadata |
| Vault | `raf vault` | BETA | Exposed credentials in files (always redacted, fingerprinted, allowlistable) |
| Dependency | `raf dependency` | BETA | Dependency inventory, SBOM import/export, offline OSV advisory checks |
| Evidence | `raf evidence` | BETA | DFIR cases: SHA-256 hashed read-only evidence, chain of custody, verification |
| Surface | `raf surface` | BETA | Authorized external attack surface from imported inventories (no scanning) |
| Lens | `raf lens` | BETA | Security data workbench: filter, group and pivot any scope |
| Oracle | `raf oracle` | BETA | Grounded answers with validated citations (deterministic builtin reasoner or a model) |

`raf products` shows the live registry (status, availability, enable/disable). Statuses are
deliberately conservative: nothing is STABLE in 0.x. Lab is EXPERIMENTAL because it has not been run
against a live container daemon in CI. Per-product documentation: [docs/products/](docs/products/).

## Architecture

```
            raf (CLI)        HTTP API /api/v1        web workbench (React)
                 \                 |                     /
                  raf.apps  ── one application layer ──
                         raf.analysis (analyze, demo, ingest)
                                   |
        raf.products: graph timeline trace replay diff blast iam policy exposure ghost
                      range forge lab protocol vault dependency evidence surface lens oracle
                                   |
                        raf.sdk (CLI/API runtime for products)
                                   |
   raf.core: object model · storage (SQLite, migrations) · ingestion (parsers, normalizers,
             provenance) · graph propagation · risk model · findings · snapshots · jobs ·
             workspaces · config & secrets · audit log · plugins · bundles
```

* One **shared security object model**: deterministic IDs (`host:dev-01`, `user:alice`,
  `rel:…`, `event:…`, `finding:<product>:<rule>:<hash>`), temporal validity, confidence and
  provenance on everything. Products never keep private copies of the world.
* **Products are independent**: each is a package with a manifest; a product may only use another
  product it declares in `depends_on`, which `tests/unit/test_architecture.py` enforces together
  with the layering above. Products can be disabled; the rest keeps working.
* **Explainable by construction**: every risk score is a list of signed factors with evidence
  (`raf-risk/1.0`, [docs/risk-model.md](docs/risk-model.md)); every path hop states why it is
  traversable; every finding explains itself.
* **Imported data is untrusted**: safe parsers, size limits, no shell interpolation, escaped output
  in the terminal and the browser, and Oracle treats imported text strictly as data.

Details: [docs/architecture.md](docs/architecture.md).

## Development

```bash
.venv/bin/pytest -q                          # unit, product, API, CLI and end-to-end tests
.venv/bin/ruff check src tests scripts && .venv/bin/ruff format --check src tests scripts
.venv/bin/mypy                               # strict
cd web && npm run typecheck && npm run lint && npm run test && npm run build
cd tui && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test && cargo build --release
```

CI (`.github/workflows/ci.yml`) runs all of the above. Tests never need network access or external
infrastructure. Fixtures are generated deterministically by `scripts/generate_fixtures.py`; a test
fails when they are out of date. More: [docs/development.md](docs/development.md).

## Documentation

| Topic | Document |
|---|---|
| Architecture and design decisions | [docs/architecture.md](docs/architecture.md) |
| Security model (safety boundaries, untrusted data, secrets, API) | [docs/security-model.md](docs/security-model.md) |
| Threat model | [docs/threat-model.md](docs/threat-model.md) |
| Object model | [docs/object-model.md](docs/object-model.md) |
| Risk model | [docs/risk-model.md](docs/risk-model.md) |
| CLI reference | [docs/cli.md](docs/cli.md) |
| HTTP API | [docs/api.md](docs/api.md) |
| R$F OS terminal panel (`raf tui`) | [docs/tui.md](docs/tui.md) |
| `raf analyze` | [docs/analyze.md](docs/analyze.md) |
| Web workbench | [docs/web-ui.md](docs/web-ui.md) |
| Products | [docs/products/](docs/products/) |
| Plugins | [docs/plugin-development.md](docs/plugin-development.md) |
| Development | [docs/development.md](docs/development.md) |
| What works today, what is next | [docs/implementation-status.md](docs/implementation-status.md), [docs/next-steps.md](docs/next-steps.md) |

## License

Apache-2.0.
