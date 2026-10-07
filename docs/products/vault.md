# R$F Vault

Defensive secret hygiene: find credentials that were committed to files and
repositories, record them in the shared security model without ever keeping
their values, and track them until they are removed or explicitly accepted.

Status: **BETA**. Category: specialized analysis. Product id: `vault`.

## Commands

```bash
raf vault scan PATH [--allowlist FILE] [--host NAME] [--no-store] [--show-suppressed]
raf vault findings [--status OPEN|ACKNOWLEDGED|RESOLVED|SUPPRESSED|FALSE_POSITIVE|all] [--severity S] [--limit N]
raf vault secrets [--all] [--limit N]          # stored secret objects (redacted)
raf vault rules                                # detectors, severity and documented precision
raf vault allowlist add [FINGERPRINT] --reason TEXT [--rule RULE] [--path GLOB]
raf vault allowlist list
```

Every command supports `--json` (schemas `raf.vault.scan/v1`, `raf.vault.findings/v1`,
`raf.vault.secrets/v1`, `raf.vault.rules/v1`, `raf.vault.allowlist/v1`, `raf.vault.allowlist.add/v1`).

```bash
$ raf vault scan ./raven-shop
R$F VAULT SCAN  /home/analyst/raven-shop
Host      local
Files     41 scanned, 3 skipped (binary 2, symlink 1)
Secrets   4 in 3 file(s), 4 distinct, 1 suppressed
Severity  CRITICAL 1 · HIGH 2 · MEDIUM 1
Stored    4 new, 0 updated, 0 resolved  (job-7)

SEV       CONFIDENCE     RULE                 LOCATION           VALUE        FINGERPRINT
CRITICAL  HIGH (0.95)    private-key          keys/deploy.pem:1  MII****Qw==  5d0e9c1a3b7f2e44
HIGH      HIGH (0.95)    github-token         src/app.py:1       ghp****a1a1  082b5f6f5102512f
...
```

* `PATH` is a file or a directory. The scan runs as a job (`raf jobs`) and is audited
  (`vault.scan`, counts only).
* `--host NAME` records where the files live: File objects are keyed `<host>|<path>` and a
  `HOST CONTAINS FILE` relationship links them to the host (for example the inventory host
  `DEV-01`). The default host is `local` (no host object is created).
* `--no-store` reports only; nothing is written except the job and audit records (which
  hold counts only).
* `--allowlist FILE` adds an allowlist file to the workspace allowlist for this scan.
* `--show-suppressed` lists allowlisted and inline-suppressed results; otherwise they are
  only counted.

## Detection rules

Severity is the impact if the match is a live credential; confidence is how often the
pattern is a real secret (the detector's precision). They are independent.

| Rule | Detects | Severity | Base confidence |
|---|---|---|---|
| `private-key` | PEM block `-----BEGIN … PRIVATE KEY-----` with key material (multi-line or `\n`-escaped JSON); markers without material are ignored | CRITICAL (HIGH when encrypted) | 0.95 high |
| `aws-access-key-id` | `AKIA`/`ASIA` + 16 uppercase letters/digits | HIGH | 0.90 high |
| `aws-secret-access-key` | 40-char base64 (mixed case, digits) on a line mentioning an AWS secret key | CRITICAL | 0.70 medium |
| `github-token` | `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_` + 36+, `github_pat_…` | HIGH | 0.95 high |
| `gitlab-token` | `glpat-` + 20+ | HIGH | 0.95 high |
| `slack-token` | `xoxb-`/`xoxa-`/`xoxp-`/`xoxr-`/`xoxs-` | HIGH | 0.90 high |
| `stripe-key` | `sk_live_` / `rk_live_` (test keys are not reported) | HIGH | 0.95 high |
| `google-api-key` | `AIza` + 35 | HIGH | 0.90 high |
| `jwt` | three base64url segments whose header decodes to a JWT header | HIGH | 0.60 medium |
| `openai-style` | `sk-` / `sk-proj-` + 20+ mixed-case alphanumerics (+30 with the OpenAI key marker) | HIGH | 0.60 medium |
| `url-credentials` | `scheme://user:password@host` | HIGH | 0.80 high (−20 for localhost / `.example` / `.test` hosts) |
| `password-assignment` | `password`/`passwd`/`pwd`/`secret`/`token`/`api_key` (and `client_secret`, `SECRET_KEY`, `apiKey`, …) assigned a literal | MEDIUM | 0.55 medium |
| `high-entropy` | base64/hex string ≥ 20 chars with Shannon entropy ≥ `vault.entropy_threshold`, only on lines with a secret keyword | LOW | 0.30 low |

Details:

* **Placeholders are ignored**: `changeme`, `${VAR}`, `$VAR`, `{{ var }}`, `%(var)s`, `<password>`,
  `[password]`, masks such as `xxxx` / `****`, `your_…_here`, YAML aliases and tags (`*x`, `!vault`),
  secret-manager references (`vault:`, `op://`, `arn:aws:…`, `ENC[…]`), `none`/`null`/`true`,
  values equal to the key name, pure numbers, paths and URLs, and documentation keys containing
  `EXAMPLE`.
* **password-assignment** accepts any value in config-like files (`.env*`, YAML, JSON, TOML, INI,
  properties, XML, HCL/Terraform, Dockerfile, `.npmrc`, `.netrc`, …) and only string literals in
  source code (`password = "…"`, `connect(password="…")`, `SECRET_KEY: str = "…"`), never
  expressions. The key must *end* with a credential word, so `token_type`, `password_hint` or
  `tokenizer` do not match.
* **high-entropy**: for pure hex strings the threshold is scaled by 4/6 (a hex alphabet carries at
  most 4 bits per character, base64 6). Tokens must mix letters and digits (base64: both cases);
  path-like tokens are ignored.
* When matches overlap the most specific rule wins (`GITHUB_TOKEN=ghp_…` is a `github-token`, not a
  `password-assignment`).
* **Confidence is explained**: each result and finding carries `explanation` factors whose points
  add up to the confidence (×100): the rule's base precision, rule-specific evidence (keyword on the
  line, entropy margin, OpenAI marker, local host) and a −15 penalty for paths that look like tests,
  fixtures, examples or docs.

## Allowlists and suppression

* **Inline**: a line containing `raf:allow` or `raf-vault:ignore` suppresses matches that start on
  that line.
* **Workspace allowlist**: `<workspace>/vault-allowlist.yaml`, written by `raf vault allowlist add`.
* **Extra file**: `--allowlist FILE` (YAML via `yaml.safe_load`, or JSON).

```yaml
allow:
  - fingerprint: 082b5f6f5102512f      # 12-64 hex characters, prefix match
    reason: revoked test token
  - rule: high-entropy
    path: "tests/fixtures/*"           # fnmatch glob on the path relative to the scan root (or absolute)
    reason: generated fixtures
```

All conditions present in an entry must match; a reason is required. Allowlists are **never read
from the scanned tree**: scanned content is untrusted and must not be able to hide its own secrets.

Suppressed results are counted, listed with `--show-suppressed`, and are not stored. An open finding
whose secret becomes allowlisted moves to **SUPPRESSED** (status history note `vault: …`); if the
allowlist entry is removed, the next scan reopens it. Analyst decisions (`raf finding
false-positive|ack`) are never overridden.

## Fingerprints and redaction

* Values are displayed only through `redact_secret()` (`ghp****a1a1`); passwords and URL passwords
  reveal less (`R****B1`), short values are fully masked, private keys are redacted from their key
  material.
* The fingerprint is `HMAC-SHA256(key, value)` (first 32 hex characters) with a random per-workspace
  key in `<workspace>/secrets/vault.key` (created exclusively with mode 0600, directory 0700). It
  identifies the same secret across files and scans (dedup, allowlists) but cannot be used to
  confirm a guessed secret without the key. Fingerprints are workspace specific: copy the key file
  to share allowlists between workspaces.

## Data model

| Kind | ID / key | Content |
|---|---|---|
| File object | `file:<host>\|<absolute path>` | name = basename; `metadata.path`, `host`, `relative_path`, `scan_root`; tag `vault` |
| Secret object | `secret:<host>\|<absolute path>\|<line>\|<rule>` | `metadata.rule`, `kind`, `redacted`, `fingerprint`, `path`, `relative_path`, `line`, `end_line`, `host`, `severity`, `status` (`present`/`removed`) — **never the value** |
| Relationship | `FILE CONTAINS_SECRET SECRET` | `metadata.line`, `rule`; confidence = result confidence |
| Relationship | `HOST CONTAINS FILE` | only with an explicit `--host` |
| Finding | `finding:vault:<rule>:<digest(host\|path\|rule\|fingerprint)>` | one per file, rule and fingerprint (repeated occurrences are grouped; `metadata.lines`); severity, confidence, explanation, evidence (secret and file objects), recommendation |
| Provenance | every object, relationship and finding | source `vault:<host>:<root>`, parser `vault/1.0`, record `<path>:<line>`, job id |

Re-scanning a target (same host, file or directory):

* findings whose secret is gone become **RESOLVED** (`resolve_absent`, scoped to the scanned target:
  scanning another directory never resolves them); findings of files that could not be read this
  time are kept;
* removed secrets get `valid_to` and their `CONTAINS_SECRET` relationship is ended (history is kept;
  a secret that reappears is reactivated);
* a secret that moved to another line keeps its finding (the fingerprint is part of the finding id);
* a scan truncated by the file limit ends and resolves nothing (files it did not reach are unknown).

## API

| Method | Path | Description |
|---|---|---|
| GET | `/vault/findings?status=OPEN\|…\|all&severity=&limit=&offset=` | `{items: [Finding], total, limit, offset}` |
| GET | `/vault/secrets?include_removed=&limit=&offset=` | `{items: [{id, name, rule, kind, severity, redacted, fingerprint, host, path, relative_path, line, confidence, first_seen, last_seen, removed}], total}` |
| GET | `/vault/rules` | detection rules |

**Scanning is CLI-only by design.** A scan reads files on the machine that runs R$F; exposing it over
HTTP would let any API client make the server read arbitrary local paths. The API is read-only and
returns only redacted values and fingerprints.

## Safety notes

* Scanned content is untrusted. Symlinks are never followed (files or directories; a symlinked scan
  root is refused). Files are opened with `O_NOFOLLOW | O_NONBLOCK` and re-checked with `fstat`, so
  FIFOs, devices and swapped-in links are skipped without blocking.
* Skipped: `.git`, `.hg`, `.svn`, `node_modules`, `.venv`, `__pycache__`, tool caches, any
  virtualenv (`pyvenv.cfg`), files larger than `vault.max_file_kb` (default 2048 KiB) and binary
  files (a NUL byte in the first 8 KiB). At most 100,000 files are examined per scan
  (`truncated: true` otherwise). Skipped files are reported with a reason.
* Secret values never reach stdout/stderr, JSON output, the database (objects, findings, provenance,
  jobs, audit), the log file or any other file: only the rule, redacted form and keyed fingerprint
  are kept. Job results and audit details hold counts only. The test suite checks every table and
  every file under `RAF_HOME` for leaks.

## Configuration

| Key | Default | Meaning |
|---|---|---|
| `vault.max_file_kb` | 2048 | Largest file scanned |
| `vault.entropy_threshold` | 4.2 | Shannon entropy (bits/char) for `high-entropy` (hex: × 4/6) |

## Limits

* Detection is line based: secrets split across lines (other than PEM blocks) or encoded (base64 of
  a credential) are not found; UTF-16 files look binary and are skipped.
* Only the working tree is scanned, not version-control history; rotate anything found, because
  removing it from the file does not remove it from history.
* Matches are not validated against providers (R$F works offline), so a token may already be revoked
  or a JWT may be expired or public (anon keys): confidence reflects pattern precision only.
* `password-assignment` and `high-entropy` are heuristics with medium/low precision; weak numeric
  passwords are not reported.
