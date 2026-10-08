# R$F security model

This document states what R$F will and will not do, how it treats the data it handles, and which
mechanisms enforce that. The adversary view (what could go wrong and how it is mitigated) is in
[threat-model.md](threat-model.md).

## 1. Purpose and safety boundary

R$F is a **defensive** platform: investigation, exposure analysis, evidence handling, and modeling of
environments the operator is authorized to assess.

R$F does **not** implement, and must not be extended to implement:

* exploitation of real systems, credential theft, persistence, destructive payloads or malware
  deployment;
* scanning or probing of arbitrary Internet targets (there is no scanner in R$F);
* anything whose primary purpose is unauthorized compromise.

Where offensive behavior is useful for training or testing, it exists only in safe forms:

| Product | What it does instead |
|---|---|
| Range, Forge | **Synthetic** organizations and telemetry: deterministic, seeded, marked `synthetic=true`, using reserved `.example` domains and RFC 5737 documentation addresses. Scenarios (suspicious access, credential risk, lateral movement) are modeled event sequences with mundane, harmless commands; the "exfiltration" in INC-001 is a modeled upload to `files.exfil-test.example`. Destroying a range removes exactly what it wrote (job provenance). |
| Lab | Containers the operator starts locally to run their own, benign experiments. Isolated by default (see §6). R$F never runs commands in a lab by itself and the API cannot. |
| Ghost | What-if models over a frozen copy of the graph. Operations such as `remove-access` change the model only; no real system is touched. |
| Surface | Attack surface from **imported** inventories (DNS, certificates, cloud listings, scope files) within an explicit authorized scope; no network probing. |
| Protocol | Saved capture files only: no live capture, no TCP reassembly, no decryption. |
| Oracle | Explains; has no tools; never changes data (see §5). |

## 2. Imported data is untrusted

Every input (files, uploads, bundles, captures, manifests, SBOMs, advisories, policy documents,
evidence, API request bodies) may be malformed or hostile.

* **Bounded parsing.** Size limits per file (`ingest.max_file_mb`), per record
  (`ingest.max_record_kb`), per non-streaming JSON document (`ingest.max_json_document_mb`);
  archive limits on members, total size and compression ratio (`ingest.max_archive_*`); product
  limits (capture packets and bytes, Vault file size, Dependency manifests, Surface documents, Lab
  output). Streaming parsers are used where formats allow it.
* **Safe parsers only.** Standard JSON/CSV parsers; YAML through `safe_load` or a SafeLoader subclass
  that also rejects aliases (no object construction, no alias bombs); captures through a bounded
  binary reader; no `eval`, no pickle.
* **No shell.** No input is ever interpolated into a shell command. The only subprocesses are Lab's
  calls to the Docker/Podman CLI, made with argument vectors (`shell=False`), timeouts and bounded
  output.
* **Filesystem safety.** Symlinks are not followed by Vault, Dependency, Evidence or directory
  imports; bundle members are validated against absolute paths, traversal, drive letters,
  symlinks and duplicates before anything is written.
* **Never silently discarded.** A malformed record is rejected individually with a reason and
  quarantined (`raf import report <job>`); the rest of the input is imported.
* **Escaped output.** The terminal renders data through `terminal_safe()` (control characters,
  escape sequences and bidirectional overrides are shown escaped) and never interprets Rich markup
  from data. The web workbench renders everything as text (ESLint forbids raw HTML sinks), shows raw
  records labeled as untrusted, and routes only to known in-app paths.

## 3. Secrets

* **Vault never prints a full secret.** Findings show a redacted form (`sk-****91a2`) and a keyed
  fingerprint (HMAC-SHA-256 with a per-workspace key in `secrets/`) so the same secret can be
  recognized across files and scans without being stored. The API returns the same redacted data.
* **Configuration secrets** (`oracle.api_key`, `api.token`) are read only from environment
  variables or the OS keyring (`raf secret set`). A secret found in a config file is ignored with a
  warning. `raf config list`, `raf secret status`, `raf oracle status` and the API report only
  whether a secret is set.
* **Logs** pass messages through the shared redaction patterns (private keys, bearer tokens,
  `password=`/`token=`-style assignments, cloud and SaaS token formats, credentials in URLs).
* **Imported log values.** Credential-like fields of imported records (`password`, `token`,
  `secret`, `api_key`, `Authorization`, `cookie` ...) are stored redacted, and secrets in messages,
  query strings and SQL statements are masked. An access key ID a cloud call was signed with becomes
  a `secret` object whose name is redacted (`AKIA****MPLE`) and whose key is a SHA-256 fingerprint,
  so detections and the graph can follow one credential without showing it. The raw excerpt of a line
  is evidence and is kept as received, bounded (`ingest.store_raw false` keeps none);
  see [logs](logs.md#redaction).
* **Model providers** receive retrieved R$F facts; Oracle's status warns when that data would leave
  the host or travel over plain HTTP.
* No secrets are kept in the repository; fixtures contain only synthetic, non-functional values.

## 4. Evidence integrity

* Every evidence item is hashed (SHA-256) on import and stored content-addressed and read-only; the
  original timestamps are kept. The original is never modified.
* Each item has a hash-chained **chain of custody** (acquired, parsed, linked, note, verified, exported);
  `raf evidence verify` recomputes content hashes and chain links and exits with status 5 on any
  mismatch.
* Derived artifacts reference their source (`DERIVED_FROM`); events parsed from evidence keep the
  evidence ID in their raw reference.

## 5. AI (Oracle)

* The platform is fully usable with AI disabled (`oracle.provider disabled`); the default provider
  is a deterministic reasoner without a model or network access.
* Model prompts separate a fixed **system policy**, the **retrieved R$F data** (JSON records between
  per-request nonce markers; marker-like text in data is neutralized) and the **user question**.
  Imported text that looks like instructions is flagged and stays data.
* Every ID a model cites is checked against the retrieved data; others are reported as
  `invalid_references`, marked in the answer and excluded from citations.
* Oracle has no tools and no write path: answers are never stored as objects, relationships or
  findings (AI output never silently becomes authoritative data). Questions are audited.
* Details and tests: [products/oracle.md](products/oracle.md), `tests/products/test_oracle.py`.

## 6. Lab isolation

Lab containers are created by one reviewed function with: no network (`--network none`) unless
`--allow-outbound` is given explicitly (with a warning and an audit record), all capabilities
dropped, `no-new-privileges`, read-only root filesystem, size-limited tmpfs for `/tmp` and
`/lab/work`, an unprivileged user unless `--root`, PID/memory/CPU limits, and read-only bind mounts
under `/lab/input`. Mount sources are refused when they are or contain system locations, the R$F
home, credential directories, the container runtime socket, any unix socket or device file; they are
re-checked before every start. Lab never modifies a container whose labels do not match its
definition and never reconfigures the host. The API manages definitions and lifecycle only; commands
run in a lab only through the local CLI. Details: [products/lab.md](products/lab.md).

## 7. API and web workbench

* `raf serve` binds to loopback by default. Binding to another address requires a bearer token
  (`RAF_API_TOKEN` or the keyring; one is generated and shown once if missing), compared in
  constant time.
* A host-header guard rejects unexpected `Host` values (DNS rebinding); responses carry a strict
  Content-Security-Policy and related security headers; request bodies are limited
  (`api.max_upload_mb`, HTTP 413).
* Data enters the API as uploads (analyze, protocol, evidence), never as server paths, so an API
  client cannot make R$F read arbitrary files. The exception is Lab's mount list, which uses the
  same validation as the CLI and requires absolute paths.
* Errors are structured (`{"error": {code, message, reason, hint}}`); internal errors are logged
  and returned without stack traces.

## 8. Accountability and data lifecycle

* Every state-changing operation (imports, analyses, findings triage, snapshots, ghost/range/lab
  lifecycle, evidence actions, configuration and secret changes, Oracle questions) is recorded in a
  **hash-chained audit log** with the actor, interface and command; `raf audit verify` detects
  edited, inserted or deleted entries.
* Destructive local operations (deleting workspaces, ghost models, ranges, labs) require explicit
  confirmation or `--yes`. Deletion removes only R$F data; range destruction removes only what the
  range wrote (by job provenance); Lab never deletes mounted host files.
* Workspace backups (`raf workspace export`) are integrity-checked bundles; restores validate the
  archive before writing anything.

## 9. Extensions

Plugins run with the privileges of the R$F process. They are loaded only after an operator trusts
them; trust pins a hash of the plugin directory, and a changed plugin is reported unavailable until
it is trusted again. Plugin modules are compiled from their source files, so bytecode that the hash
does not cover never runs. The permissions a plugin declares are shown for review when it is
installed and trusted; R$F does not enforce them and, for in-process Python code, could not. A
plugin that fails to load is reported unavailable instead of breaking the CLI or the API. Treat
plugins like any other code you install. See [plugin-development.md](plugin-development.md).

## 10. Authorization statement

Use R$F only on data, systems and environments you own or are explicitly authorized to analyze.
Synthetic datasets shipped with R$F (Raven Industries, Range presets, Forge scenarios) are fictional.
