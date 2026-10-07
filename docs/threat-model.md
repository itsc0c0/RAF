# R$F threat model

Scope: R$F 0.1 running on an analyst's workstation (CLI, local API, web workbench) or on a shared
host with `raf serve` bound to a network address. The mechanisms referenced here are described in
[security-model.md](security-model.md).

## Assets

| Asset | Why it matters |
|---|---|
| Workspace data (objects, events, findings, cases) | sensitive investigation results; integrity drives decisions |
| Evidence originals and chain of custody | legal and forensic value; must be provably unmodified |
| Secrets the platform handles (API token, model API key, Vault fingerprint key) | access to the API, a paid model, correlation of secrets |
| Secrets found in analyzed data | the operator's exposed credentials; must not leak further |
| The analyst's host | R$F parses hostile data and can start containers |
| Analysis conclusions | an attacker who controls the data may try to steer conclusions |

## Trust boundaries

1. **Imported data → parsers** (files, uploads, bundles, captures, SBOMs, advisories, evidence).
   The data may have been crafted by the adversary under investigation.
2. **HTTP clients → API** (the local browser, other local processes, remote clients when bound to
   a network address).
3. **R$F → container runtime** (Lab) and **container → host**.
4. **R$F → model provider** (Oracle with an OpenAI-compatible server).
5. **Plugins → R$F process.**
6. **Displayed output → analyst** (terminal and browser rendering data from 1).

## Threats and mitigations

| # | Threat | Boundary | Mitigation | Residual risk |
|---|---|---|---|---|
| T1 | Resource exhaustion through huge files, records, JSON documents, zip bombs, deep nesting | 1 | per-file/record/document limits, archive member/size/ratio limits, streaming parsers, bounded product readers (captures, Vault, Dependency, Surface) | large-but-valid inputs within limits still take time; limits are configurable |
| T2 | Code execution through parsers (YAML object construction, pickle, eval) | 1 | `safe_load` / SafeLoader without aliases, JSON/CSV standard parsers, no eval or pickle | bugs in third-party parsers |
| T3 | Path traversal or symlink tricks in bundles, directory imports, evidence | 1 | member path validation (absolute, `..`, drive letters, symlinks, duplicates), symlinks not followed, hashes verified before writing | none known |
| T4 | Command injection | 1, 3 | no shell anywhere; Lab uses argument vectors with validated image names, lab names, resource values and mount paths | none known |
| T5 | Terminal escape / bidi injection that hides or forges output | 6 | `terminal_safe()` on table and key-value output, Lab output escaped by default; Rich markup in data is not interpreted | free-form text printed outside the shared helpers must use them too |
| T6 | XSS / HTML injection in the workbench | 6 | everything rendered as React text, raw-HTML sinks forbidden by lint rules, strict CSP, links from data never followed | none known |
| T7 | Prompt injection through imported text ("ignore previous instructions…") | 1, 4 | builtin reasoner never interprets text; model prompts separate policy/data/question with nonce markers; instruction-like text flagged; citations validated; no tools; answers never stored as data | a model can still be persuaded to word a wrong conclusion; validated citations and the notice keep it checkable |
| T8 | Poisoned data steering conclusions (fake events, misleading names) | 1 | provenance on every fact (source, SHA-256, record, parser, job), confidence levels, findings explain their evidence, synthetic data labeled | R$F cannot tell true from false input; analysts must weigh sources |
| T9 | Tampering with evidence or audit history | local attacker | content-addressed read-only evidence, hash-chained custody and audit log, `raf evidence verify`, `raf audit verify` | an attacker with write access to the workspace can delete everything; detection, not prevention |
| T10 | Secret leakage (logs, output, API, model provider, repository) | 2, 4 | Vault redaction + keyed fingerprints, secrets only from env/keyring, redaction filter on logs, API reports "set/not set", transport warnings for model providers, synthetic fixtures | secrets inside raw event excerpts are stored as imported (bounded excerpts, `ingest.store_raw`) |
| T11 | Unauthorized API access, DNS rebinding, CSRF-like requests from a browser | 2 | loopback default, bearer token required for remote binding (constant-time compare), host-header guard, CSP, JSON/multipart APIs, request size limit | any local process on a loopback-bound instance can call the API |
| T12 | API used to read server files | 2 | uploads only; no route takes server paths (Lab mounts are validated and refuse sensitive locations) | Lab mounts of non-sensitive directories by an authorized API client |
| T13 | Container escape or host exposure via Lab | 3 | no network by default, all capabilities dropped, no-new-privileges, read-only root, unprivileged user, resource limits, read-only mounts, refusal of sockets/devices/system and credential paths, ownership labels, no API exec route | kernel or runtime vulnerabilities; `--allow-outbound` and `--root` widen exposure (warned and audited) |
| T14 | Malicious or modified plugin | 5 | plugins load only after explicit trust; trust pins a hash of the plugin's files, checked whenever plugin code is loaded and when products are listed (a changed plugin is unavailable); plugin modules are compiled from source, never from cached bytecode, so a planted `.pyc` cannot run; symbolic links and special files are refused; plugins cannot take over built-in commands, parsers or API paths; one that fails to load is reported unavailable instead of breaking the CLI or the API | a trusted plugin has full process privileges: its declared permissions are shown for review, not enforced; a module the plugin imports later is read from disk at that moment |
| T15 | Misuse of R$F against third parties | — | no scanner, no exploitation or payload capability; offensive behavior only synthetic or in isolated labs | operators remain responsible for authorization |

## Assumptions

* The host OS, Python runtime and container runtime are trusted and patched.
* The operator controls `RAF_HOME`; other local users cannot write to it.
* Model providers are chosen by the operator, who accepts that retrieved facts are sent to them.

## Out of scope (0.1)

Multi-user access control inside one workspace, encryption at rest (rely on disk encryption),
remote/hosted deployments, and signed plugin distribution.
