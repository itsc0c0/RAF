# Next steps

Known gaps and the planned order of work after 0.1.0. Each item names what remains to be done.

## Toward a first public release

1. **Packaging.** The wheel carries the built web workbench and is checked in a clean environment in
   CI (`scripts/check-wheel`); next: publish it with signed release artifacts, and ship R$F OS
   (`raf-os`) binaries per platform.
2. **Lab validation.** CI runs the isolation checks of `tests/products/test_lab_docker.py` on a real
   Docker daemon; next: the same checks on rootless Podman.
3. **PostgreSQL in CI.** CI checks the migrations and runs a demo workflow on SQLite and
   PostgreSQL with identical results; next, run the whole suite against PostgreSQL (fixtures that
   clone a template database instead of copying a SQLite file).
4. **Web workbench coverage.** The browser end-to-end suite (`web/e2e`) covers the signature
   workflow, triage and the token prompt; extend it to the other write flows (Ghost operations,
   Surface and Protocol uploads, snapshots, Lab).
5. **Performance budgets.** Benchmarks for million-event imports, timeline queries and propagation on
   large graphs, with regression thresholds in CI (`slow` marker). Measured today on a workspace
   with 150,000 events, 51,000 objects and 200,000 relationships (mostly process activity), command
   wall time including about 0.8 s of start-up: Blast, Trace, Oracle and every R$F OS page take
   about a second or less; `raf snapshot create` and `raf ghost create` 3 s, `raf diff SNAPSHOT
   current` 2.5 s, `raf diff` between two snapshots 3 s, `raf ghost modify` 1.7-1.9 s,
   `raf ghost compare` 3 s, `raf snapshot delete` 2.6 s. Still slow there: the first snapshot of a
   workspace created before content hashes were stored computes them once (13 s), and
   `raf ghost modify --remove-relationship` builds the model's full state (12 s).

## Product depth

* **Policy:** parsers for vendor firewall configurations in addition to iptables-save, nftables and
  the CSV export path; interface-to-zone mappings so interface-based netfilter rules can be modeled
  instead of imported disabled.
* **IAM:** cloud-provider permission evaluation (conditions, permission boundaries) from imported
  policy documents.
* **Dependency:** advisory feeds beyond imported OSV files (still offline-first), lockfile formats for
  more ecosystems.
* **Evidence:** externally signed custody (operator key), disk and memory image metadata parsers.
* **Surface:** public-suffix awareness, domain expiry rule, RDAP import.
* **Protocol:** more application protocols (SMB, Kerberos metadata, QUIC SNI) — always offline.
* **Detections:** user-defined rules (an import format with the same evidence and explanation
  model, Sigma as a source), per-rule thresholds in the configuration, and an evaluation set of
  labeled logs per rule; Oracle answers that cite detection findings.
* **Multi-source logs:** multi-line documents (XML exports, pretty-printed JSON arrays) decoded
  field by field instead of folded into one message; more vendor formats (Palo Alto, FortiGate,
  Check Point, Exchange message tracking).
* **Oracle:** better intent detection (still deterministic), multi-turn follow-ups that reuse the
  retrieved facts, evaluation set with expected citations.
* **Graph/Blast:** port-aware propagation that consumes the Policy model directly.

## Platform

* **R$F OS:** test and package `raf-os` for macOS and Windows terminals; ship prebuilt binaries
  with releases (today it is built from `tui/` with Cargo); optional connection to a remote
  `raf serve` with a token.

* Multi-user API (roles, per-user audit identity) for shared deployments.
* Encryption at rest for workspaces (today: rely on disk encryption).
* Plugin distribution with signatures (today: hash-pinned local trust).
* Incremental exposure/IAM re-analysis instead of workspace-wide recomputation after imports.

## How to pick up work

Read [implementation-status.md](implementation-status.md) for the current truth,
[architecture.md](architecture.md) for the structure, and [development.md](development.md) for the
workflow. Keep documentation and statuses truthful: a feature is implemented only when it is tested,
integrated and documented.
