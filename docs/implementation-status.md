# Implementation status (0.1.0)

What works today, what is partial, and what is missing. "Implemented" here means: core logic,
input validation, meaningful output, error handling, tests, CLI/API (and UI where it exists)
integration, and documentation that describes the actual behavior.

## Status meanings

| Status | Meaning in R$F |
|---|---|
| STABLE | feature-complete, interfaces frozen for the 1.x line. **Nothing is STABLE in 0.x.** |
| BETA | implemented end to end (logic, validation, CLI, API, tests, docs); interfaces may still change |
| ALPHA | usable core with significant gaps |
| EXPERIMENTAL | implemented but not validated in its real operating environment |
| DISABLED | turned off by the operator (`raf product disable`) |

## Platform

| Area | State | Notes |
|---|---|---|
| Object model, deterministic IDs, provenance | done | objects, relationships (validity intervals), events, findings, incidents, provenance rows |
| Workspaces, configuration, secrets | done | layered config; secrets only env/keyring; per-workspace SQLite |
| Storage | done | SQLite (WAL) with Alembic migrations (schema equality is tested). PostgreSQL (`postgres` extra, `storage.url`): CI migrates a fresh database, checks it against the declared schema and runs a 32-command demo workflow on SQLite and PostgreSQL with identical results and content hashes (`tests/integration/test_postgres.py`); the rest of the suite runs on SQLite |
| Ingestion | done | JSON, JSONL, CSV/TSV, syslog, access logs, text logs, directories, filesystem metadata, archives; native, ECS, CloudTrail and tabular normalizers; product parsers (pcap, policy documents); quarantine of rejected records |
| `raf analyze` | done | detection + pipelines for pcap, events, directories, policies, repositories, manifests, SBOMs, bundles; `analysis-N` records and scoping |
| Jobs, audit log, bundles, backups | done | hash-chained audit; bundle verify/import; workspace export/restore |
| Findings lifecycle | done | idempotent IDs, status history, reopen, resolve-absent, triage via CLI/API/UI |
| Risk model | done | `raf-risk/1.0` explainable factors (Blast, Exposure, Ghost, Oracle) |
| CLI | done | global flags, `--json` schemas, structured errors and exit codes, interactive shell, `@last` |
| HTTP API | done | `/api/v1` for every product; loopback default, token for remote binding, host guard, CSP, body limit |
| Web workbench | done | a view for every product with an API: overview, investigate (Lens/Trace), graph, replay, timeline, analyses, snapshots & diff, exposure (IAM, Blast, Policy incl. document check and revision compare), surface, ghost, ranges (Range/Forge), lab, protocol (incl. earlier uploads), evidence, findings (incl. Vault secrets and dependencies), oracle, products, settings; bearer-token support; unit tests and a Playwright end-to-end suite. Known limitations are listed in [web-ui.md](web-ui.md) |
| R$F OS terminal panel (`raf tui`) | done | Rust + Ratatui `raf-os` (`tui/`): 12 pages, keyboard and mouse, inspector, plain-text `--dump`; served by read-only `/api/v1/tui` routes over loopback with a one-time token; see [tui.md](tui.md). Built with Cargo (no prebuilt binaries yet); tested on Linux |
| Plugins | done | manifests, install/trust (hash pinned)/verify/uninstall; see [plugin-development.md](plugin-development.md) |
| Architecture rules | done | layering and declared product dependencies enforced by `tests/unit/test_architecture.py` |
| Packaging | done | Linux release bundles for x86_64 and aarch64 (Python runtime, every dependency as a wheel, web workbench, static R$F OS binary, docs, fixtures) with an offline installer into `/opt/raf` (upgrade with rollback, `--user`, uninstaller), checked on Debian, Ubuntu, AlmaLinux and Fedora without network before every release (`scripts/build-release`, `scripts/check-release`, [install.md](install.md)); from source: `scripts/bootstrap`, `uv sync`, a wheel with the workbench (`scripts/check-wheel`). Not on PyPI; no macOS or Windows bundles |
| CI | done | `.github/workflows/ci.yml` (Python lint/types/tests/smoke, web lint/types/tests/build, the web workbench end to end in Chromium, PostgreSQL migrations and SQLite/PostgreSQL equivalence, Lab on a real Docker daemon, R$F OS fmt/clippy/tests/build and an end-to-end `raf tui --dump` of every page) |

## Products

| Product | Status | Works | Partial / not yet |
|---|---|---|---|
| Graph | BETA | neighborhoods, paths, temporal `--at` views, incident/analysis scopes, GraphML/JSON export, stats | layout is the client's job (web); very large graphs are truncated with notice |
| Timeline | BETA | unified events, filter language, grouping, histograms, cursor pagination, CSV/JSON/bundle export | — |
| Trace | BETA | causal chains: observed links vs labeled correlations with confidence | correlation windows are heuristics (configurable) |
| Replay | BETA | deterministic incident reconstruction, state at T, checkpoints, state hashes | — |
| Diff | BETA | snapshots, current state and Ghost models; categories, importance with reasons | — |
| Blast | BETA | control/reach/trust propagation, vulnerability upgrades, explainable paths and risk | port-level policy is not part of propagation (see `raf policy can`) |
| IAM | BETA | effective access, privilege paths, dormant/MFA/excessive/inherited/credential-exposure findings | no cloud-provider permission evaluation beyond imported statements |
| Policy | BETA | firewall and access policy normalization (raf-policy/1, IAM JSON, CSV exports, iptables-save, nftables text and JSON, with chains inlined), anomaly analysis, flow decisions, revision diffs | vendor firewall configurations are not parsed; netfilter conditions beyond addresses, protocols, destination ports, ICMP types and connection states (interfaces, marks, rate limits ...) are imported as disabled rules; `ip` tables are applied to IPv6 flows too |
| Exposure | BETA | per-asset explainable exposure, workspace metrics, findings | — |
| Ghost | BETA | what-if models with 12 operations, undo, simulate, compare, min-cost cut suggestions, snapshot source | zone-level network modeling |
| Range | BETA | presets (raven, acme, small-office, enterprise), seeded organizations, simulated activity periods, clean purge | no live services; periods are generated synchronously |
| Forge | BETA | 7 telemetry generators, 3 modeled scenarios, deterministic seeds, optional ingestion | — |
| Lab | BETA | definitions, secure container arguments, lifecycle, exec/shell via CLI, audit; tested with fakes, and on a real Docker daemon in CI with every isolation guarantee checked inside running labs | Podman not validated against a live service |
| Protocol | BETA | pcap/pcapng reader, explained fields, flows (Community ID), DNS/HTTP/TLS metadata, ingestion | no live capture, TCP reassembly or decryption (by design) |
| Vault | BETA | rule-based secret detection with entropy, redaction, keyed fingerprints, allowlists, findings | — |
| Dependency | BETA | manifests and lockfiles (Python, JavaScript, …), SBOM import/export, offline OSV matching with confidence | advisories must be imported (no online feed) |
| Evidence | BETA | cases, SHA-256 read-only storage, hash-chained custody, verification, incident linking, export | no disk/memory image parsing; custody is not externally signed |
| Surface | BETA | authorized-scope inventory import (DNS, certificates, services, cloud storage), ownership, findings | see [products/surface.md](products/surface.md) for limits; no scanning by design |
| Lens | BETA | any scope: events, groups, histograms, involved objects, findings, pivots | ranking considers the top 2,000 objects |
| Oracle | BETA | deterministic grounded reasoner, OpenAI-compatible provider with validated citations, injection defenses | keyword-based intent detection; model provider tested with mocks only |

## Verified workflows

* The signature workflow (README "Example workflow") runs end to end in
  `tests/integration/test_end_to_end.py` and in CI.
* `raf demo load` followed by `raf graph alice`, `raf blast alice`, `raf timeline alice`,
  `raf replay INC-001`, `raf oracle ask …` (CI smoke test).

## Known gaps

See [next-steps.md](next-steps.md).
