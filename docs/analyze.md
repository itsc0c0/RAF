# raf analyze

`raf analyze <input>` looks at a file or directory, works out what it is, runs the matching
analysis pipeline across the R$F products, and records the result as `analysis-N`. Every module
that ran (or was skipped, and why) is listed; nothing is hidden.

```text
$ raf analyze ./fixtures/raven-events.jsonl

R$F ANALYZE  raven-events.jsonl
────────────────────────────────────────
Detected: JSON Lines: jsonl parser (score 0.95)

Running:
  ✓ Ingest (JSON Lines)     774 of 774 records accepted (jsonl/1.0 + raf-native/1.0)  0.28 s
  ✓ Timeline                531 events indexed, 2026-10-06T06:00:00Z → 2026-10-07T01:06:00Z
  ✓ Graph                   357 objects and 696 relationships created; 0 objects and 0 relationships updated
  ✓ Incidents               events linked to INC-001
  ✓ Detections              6 detection(s) (5 high, 1 medium) over 531 events; 2 explained (approved changes,
                            tickets, scheduled jobs); correlated detections match INC-001
  ✓ IAM analysis            29 principal(s) in the input; workspace re-analyzed: 9 IAM finding(s), 9 involving them
  ✓ Exposure correlation    31 asset(s) involved (6 critical, 8 high, 3 low, 8 medium); 14 exposure finding(s)
  ✓ Findings                29 new finding(s) (4 medium, 19 high, 6 critical)
  → analysis-1

Objects             357
Relationships       696
Events              531
Detections            6
Findings             29
Incidents      INC-001

Detections:
  HIGH      6 failed sign-ins for bob in 45 s from 203.0.113.45, then a success from 203.0.113.45
  HIGH      Suspected credential attack → suspicious sign-in (203.0.113.45): 2 correlated detections, matching INC-001
  HIGH      Suspected exfiltration → security alert (APP-01): 2 correlated detections, matching INC-001
  HIGH      Large transfer between 10.30.0.5 and 198.51.100.23 (files.exfil-test.example): 48.3 MB over 443/tcp
            (988x the largest routine flow)
  HIGH      Alert from raven-ids: Unusual outbound data volume from APP-01 to a first-seen domain
  MEDIUM    Sign-in from a new public address: bob from 203.0.113.45 to VPN-01 (no MFA seen)

Explained (no finding):
  Transfer of 182.4 MB from 10.30.0.10 to 203.0.113.200: follows the scheduled job 'pg_dump raven' (svc-backup,
  started by /usr/sbin/cron) that wrote raven-20261006.dump (182.0 MB) on DB-01: consistent with a scheduled
  backup or export
  Database export on DB-01: pg_dump raven: run by svc-backup from a scheduler (/usr/sbin/cron): a scheduled job

Explore:
  raf lens analysis-1
  raf graph analysis-1
  raf timeline analysis-1
  raf replay INC-001
  raf oracle ask "Explain the most important security path in INC-001"
```

## Usage

```text
raf analyze <file | directory | analysis-N> [--format PARSER] [--incident NAME] [--source-name NAME]
                                            [--synthetic] [--no-correlate]
raf analyses [--limit N]
raf detect [SCOPE] [--dry-run]
```

`raf analyze analysis-3` shows a recorded analysis again; `raf analyses` lists them. After an
analysis, `@last` refers to it: `raf graph @last`, `raf lens @last`.

## Detection

Content first, then names; deterministic.

| Input | Detected as | How |
|---|---|---|
| libpcap / pcapng capture | `pcap` | magic number |
| `.raf` bundle | `bundle` | ZIP archive with an R$F `manifest.json` |
| `package.json`, `requirements*.txt`, lockfiles, … | `manifest` | Dependency manifest names |
| CycloneDX / SPDX JSON | `sbom` | `"bomFormat": "CycloneDX"` or `"spdxVersion"` |
| JSON Lines, JSON, CSV, syslog, web access logs, mixed multi-source logs ([formats](logs.md)), text logs | `events` | the ingestion parser with the best sniff score; for mixed logs the detection names the sources seen in the first lines |
| `raf-policy/1`, IAM JSON, firewall CSV exports | `policy` | the Policy parser's sniff score |
| `raf-surface/1` inventories (JSON, JSONL, YAML, CSV with surface `kind`s) | `surface` | the Surface parser's sniff score |
| directory with dependency manifests or `.git` | `repository` | bounded walk (5,000 entries, depth 4) |
| any other directory | `directory` | every data file is imported with its own parser |

`--format` forces a parser for data files. Unknown inputs fail before anything is written, with the
list of parsers.

## Pipelines

| Type | Steps |
|---|---|
| `pcap` | **Protocol** (decode: flows, DNS, HTTP, TLS) → Timeline → Graph → Detections → IAM analysis* → Exposure correlation* → Findings |
| `events`, `directory` | Ingest → Timeline → Graph → Incidents (when linked) → Detections → IAM analysis* → Exposure correlation* → Findings |
| `policy` | Ingest → Timeline → Graph → Policy analysis → Findings |
| `surface` | Ingest → Timeline → Graph → Surface analysis (only within the authorized scope; an analyze never changes the scope) → IAM analysis* → Exposure correlation* → Findings |
| `repository` | Dependency scan (+ advisory matching) → Vault secret scan → Graph → Findings |
| `manifest` | Dependency scan → Graph → Findings |
| `sbom` | Dependency SBOM import (+ advisory matching) → Graph → Findings |
| `bundle` | Bundle verification (every member SHA-256) → Bundle import → Timeline → Graph → Findings |

**Detections** run the [Timeline detection rules](products/timeline.md#detections) over the events of
the analysis: the step reports the findings by severity, the activity it explained (approved
changes, tickets, scheduled jobs) and the suspected incident it created (`CASE-...`) or the existing
incident its correlated detections match; the summary lists the detections and what was ruled out.
`raf detect analysis-N` runs them again, `raf detect` over the whole workspace.

\* Correlation re-runs the workspace-wide analyses so findings stay consistent with the new data:
**IAM analysis** runs when the input brought users, identities, groups or roles; **Exposure
correlation** re-scores exposure (`raf-risk/1.0`) when the input touched assets (including hosts
that own an analyzed IP address) and reports the levels of the involved assets. Skip both with
`--no-correlate`. A step whose product is disabled (`raf products disable vault`) is reported as
skipped; the rest of the pipeline continues.

**Status.** `completed` when every executed step succeeded, `partial` when a later step failed
(the data that was imported stays), `failed` when the first, essential step failed (for example a
bundle that does not verify: nothing is imported). A failed analysis exits with status 1 and is
still recorded.

## Analysis records and scope

Each run is stored in the workspace (`analyses` table) with the input path, its SHA-256, the
detected type, every step with its numbers, the statistics, the suggestions and the jobs it
created. `raf lens|graph|timeline analysis-N` scope to exactly that data through job provenance.

Imports are idempotent: analyzing data that is already in the workspace creates no duplicates.
Data imported earlier with another parser (a mixed log imported as plain text before) is re-read
with the current one: the Timeline step says how many events were re-read, and the analysis covers
the job that first imported them. The summary counts the events and objects of the analysis scope,
not only the new ones.
The analysis then also covers the jobs that first imported it: a job that imported only this input
joins the scope; a job that imported it together with other sources (for example an evidence case)
joins it for a single file, with the scope narrowed to that file's source name. Example: analyzing
`raven-inc001.pcap` in the demo workspace (where the capture arrived as INC-001 evidence) reports
"9 already present" and `raf lens analysis-N` shows exactly those 9 events.

## API

| Method | Path | Description |
|---|---|---|
| POST | `/api/v1/analyze` (multipart `file`, optional form fields `incident`, `correlate`, `synthetic`) | analyze an uploaded file → the analysis (`synthetic` is `raf analyze --synthetic`) |
| GET | `/api/v1/analyses?limit=` | `{items, total}` |
| GET | `/api/v1/analyses/{id}` | one analysis with `job_ids` |

The API accepts uploads only (never a server path), limited by `api.max_upload_mb`. An upload is
stored read-only in the workspace (`uploads/analyze/<sha256>`), and its sanitized original name is
used as the provenance source and shown as `input`; server paths are never returned.

## Limitations

* Directories and repositories can be analyzed from the CLI only (the API takes single files).
* Detection of plain-text formats relies on parser sniffing; use `--format` when a file is
  ambiguous.
* Correlation is workspace-wide: IAM and exposure findings may change for objects outside the
  input; the steps say so in their numbers ("… involving them").
