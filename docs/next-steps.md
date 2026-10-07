# Next steps

Known gaps and the planned order of work after 0.1.0. Nothing here is implemented yet.

## Toward a first public release

1. **Packaging.** Publish a wheel that includes the built web workbench (`raf serve` then needs no
   Node.js), and document `pipx install`. Signed release artifacts.
2. **Lab validation.** Run Lab against real Docker and rootless Podman in CI (a `docker`-marked test
   job), then decide whether it can leave EXPERIMENTAL.
3. **PostgreSQL in CI.** The storage layer supports PostgreSQL; add a CI job that runs the suite
   against it before calling it supported.
4. **Web workbench coverage.** Every product with an API should have a view (see the page list in
   [web-ui.md](web-ui.md)); add browser end-to-end tests of the signature workflow.
5. **Performance budgets.** Benchmarks for million-event imports, timeline queries and propagation on
   large graphs, with regression thresholds in CI (`slow` marker).

## Product depth

* **Policy:** parsers for common firewall configuration formats (in addition to the CSV export path).
* **IAM:** cloud-provider permission evaluation (conditions, permission boundaries) from imported
  policy documents.
* **Dependency:** advisory feeds beyond imported OSV files (still offline-first), lockfile formats for
  more ecosystems.
* **Evidence:** externally signed custody (operator key), disk and memory image metadata parsers.
* **Surface:** public-suffix awareness, domain expiry rule, RDAP import.
* **Protocol:** more application protocols (SMB, Kerberos metadata, QUIC SNI) — always offline.
* **Oracle:** better intent detection (still deterministic), multi-turn follow-ups that reuse the
  retrieved facts, evaluation set with expected citations.
* **Graph/Blast:** port-aware propagation that consumes the Policy model directly.

## Platform

* Multi-user API (roles, per-user audit identity) for shared deployments.
* Encryption at rest for workspaces (today: rely on disk encryption).
* Plugin distribution with signatures (today: hash-pinned local trust).
* Incremental exposure/IAM re-analysis instead of workspace-wide recomputation after imports.

## How to pick up work

Read [implementation-status.md](implementation-status.md) for the current truth,
[architecture.md](architecture.md) for the structure, and [development.md](development.md) for the
workflow. Keep documentation and statuses truthful: a feature is implemented only when it is tested,
integrated and documented.
