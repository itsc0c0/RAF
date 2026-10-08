# R$F Timeline

R$F Timeline puts every normalized event of a scope - an object, an incident, an analysis, a job or
the whole workspace - on one time axis, whatever source it came from (JSONL exports, syslog, EDR
events, proxy logs, packet captures, [mixed multi-source logs](../logs.md)). It answers: what
happened, in which order, by whom, against what, from which source record - and it exports exactly
that selection. Its [detections](#detections) turn the events into findings and correlated
incidents.

Status: **BETA** · category: investigation · commands: `raf timeline`, `raf detect` · API: `/api/v1/timeline`
· web: Timeline · depends on: core only (event store and filter language in `raf.core`)

## Usage

```text
raf timeline [SCOPE] [--from T] [--to T] [--type TYPE]... [--category CAT]... [--severity LEVEL]
                     [--filter EXPR] [--group-by FIELD] [--limit N] [--reverse] [--cursor CURSOR]
raf timeline [SCOPE] [same filters] --export FILE [--format csv|json|jsonl|raf]
```

| Scope | Example | Events |
|---|---|---|
| nothing, `workspace`, `all`, `@workspace` | `raf timeline workspace` | every event |
| an object (ID, name, alias, or `TYPE NAME`) | `raf timeline user alice`, `raf timeline 10.30.0.5` | events in which the object is involved in any role (actor, target, host, `src_ip`, `answer`, ...) |
| an incident | `raf timeline INC-001` | events linked to the incident |
| an analysis or a job | `raf timeline analysis-1`, `raf timeline job-1` | events those jobs imported |
| a context reference | `raf timeline @last`, `@incident`, `@analysis` | what it refers to |

The scope syntax is the one of Graph, Lens and Replay ([cli.md](../cli.md#references)).

## Selecting events

| Option | Meaning |
|---|---|
| `--from T`, `--to T` | inclusive time bounds (see below) |
| `--type TYPE` | repeatable, combined with OR; `auth.login` is exact, `auth.*` or a bare `auth` matches `auth` and every `auth.<action>` |
| `--category CAT` | repeatable, combined with OR (`auth`, `process`, `file`, `network`, `dns`, `http`, `tls`, `iam`, ...) |
| `--severity LEVEL` | minimum severity: INFO < LOW < MEDIUM < HIGH < CRITICAL (`warning` = MEDIUM, `error` = HIGH, ...) |
| `--filter EXPR` | the R$F filter language, e.g. `'type:auth.* outcome:failure actor:bob "vpn"'` ([reference](../cli.md#filter-language), `raf help query`) |

Options and filter terms only narrow the scope: every term must hold. `type:` and `category:` terms
intersect with `--type` / `--category` (a contradiction selects nothing), the stricter of a time
term (`after:`, `before:`, `time>=…`) and `--from` / `--to` wins, `job:` and `incident:` terms
intersect with the scope, and an `object:` term on an object scope selects the events that involve
both objects (`raf timeline user alice --filter object:DEV-01`). Combinations the event store cannot
express are rejected with an explanation (exit 4) rather than widened: two different incidents, or
two `source:` texts of which neither contains the other. See the
[filter language](../cli.md#filter-language).

**Time values** (`--from`, `--to`): ISO 8601 (`2026-10-06T23:00:00Z`, offsets and a space separator
are accepted), epoch seconds (or milliseconds, microseconds, nanoseconds), RFC 2822, `now`, a time of
day `HH:MM[:SS]` placed on the date of the scope's first event (choosing the occurrence inside the
scope's window when it spans midnight), and offsets such as `+15m`, `-2h`, `+1d` from the scope's
first event. For INC-001 (first event 22:47:00), `--from +15m --to +20m` selects 23:02-23:07.
Filter terms `after:` and `before:` take full timestamps only.

```text
$ raf timeline user alice --filter 'type=auth.*'

R$F TIMELINE  alice  (user:alice)
────────────────────────────────────────
Events        5
Window        2026-10-06 08:14:08 → 2026-10-06 18:22:30
Filters       type=auth.*
By category   auth 5
Activity      █    █        █              █                 █

TIME                 SEV   TYPE         ACTOR  OUTCOME  TARGET  DETAIL
2026-10-06 08:14:08  INFO  auth.login   alice  success  WS-01
2026-10-06 09:17:59  INFO  auth.login   alice  success  DEV-01
2026-10-06 11:23:55  INFO  auth.login   alice  success  DEV-01
2026-10-06 14:28:14  INFO  auth.login   alice  success  DEV-01
2026-10-06 18:22:30  INFO  auth.logout  alice           WS-01

Next:
  raf trace user:alice
  raf graph user:alice
  raf timeline user alice --export timeline.csv
```

## Order and pagination

Events are ordered by (timestamp, event ID), oldest first; `--reverse` lists newest first. A page
holds `--limit` events (default 50, 1-10,000). When more events match, the result carries
`next_cursor`, an opaque keyset cursor (base64url of the last event's timestamp and ID); passing it
with `--cursor` and the same scope, filters and direction returns the next page. `total` always
counts every matching event. An invalid cursor is rejected (exit 4).

```text
raf timeline INC-001 --limit 20 --json        # ... "next_cursor": "MjAyNi0xMC0wNlQyMjo1..."
raf timeline INC-001 --limit 20 --cursor MjAyNi0xMC0wNlQyMjo1...
```

## Grouping and activity histogram

`--group-by FIELD` (default `category`) counts the matching events (all of them, not only the page)
by `category`, `event_type`, `actor`, `target`, `severity`, `source` or `outcome`, most frequent
first; the 30 largest groups are returned and the terminal shows 8. Actor and target groups are keyed
by object ID (`user:bob 16`).

The histogram counts the matching events in equal-width buckets between the first and the last
matching event (bucket width at least one second). The CLI uses 48 buckets and draws them as the
`Activity` sparkline (hidden with `--quiet`); the API's `buckets` parameter sets the number (default
60). The returned list can hold one more bucket than requested, the last one containing the final
timestamp.

## Export

`--export FILE` writes **every** matching event (`--limit`, `--cursor` and `--reverse` do not apply)
in (timestamp, ID) order, creating parent directories and replacing an existing file. The command
prints the event count and the SHA-256 of the written file and records a `timeline.export` audit
entry.

```text
$ raf timeline INC-001 --export inc.csv
Exported 44 events to inc.csv (csv, sha256 9f33755f3ef052a3...)
```

| `--format` | Content |
|---|---|
| `csv` (default) | header `timestamp, event_id, event_type, category, action, outcome, actor, actor_name, target, target_name, severity, confidence, source, parser, record, raw_reference, message`; every text cell (all columns except `timestamp`, `severity` and `confidence`) that starts with `=`, `+`, `-`, `@`, tab or CR is prefixed with `'` so spreadsheets do not evaluate it |
| `json` | one JSON array of event documents |
| `jsonl` | one event document per line |
| `raf` | an R$F bundle (`raf-bundle/1.0` ZIP) with the events, the objects involved in them, the relationships they reference and, for an incident scope, the incident object; check it with `raf bundle verify`, load it elsewhere with `raf bundle import` |

The `raf` format contains no findings or provenance records; use `raf workspace export` for a full
backup.

## Output

`raf timeline --json` emits `raf.timeline/v1`:

```json
{
  "schema": "raf.timeline/v1",
  "scope": {"kind": "incident", "id": "incident:inc-001", "label": "INC-001", "job_ids": []},
  "filters": [],
  "total": 44, "first": "2026-10-06T22:47:00Z", "last": "2026-10-06T23:27:00Z",
  "items": [{"id": "event:e49aa7bd2897ad0805cbc31d", "timestamp": "2026-10-06T22:47:00Z",
             "event_type": "auth.failure", "category": "auth", "action": "failure", "outcome": "failure",
             "actor": "user:bob", "target": "host:vpn-01",
             "objects": [{"object_id": "user:bob", "role": "actor"},
                         {"object_id": "ip:203.0.113.45", "role": "src_ip"}, "..."],
             "source": "raven-events.jsonl", "parser": "raven-demo/1.0", "record": "record 753",
             "raw_reference": "raven-events.jsonl#record 753", "severity": "LOW", "confidence": 0.8,
             "attributes": {"src_ip": "203.0.113.45", "method": "password"}, "relationships": [],
             "message": null, "synthetic": true, "job_id": "job-1", "incidents": ["incident:inc-001"],
             "raw": null, "ingested_at": "..."}],
  "names": {"host:vpn-01": "VPN-01", "user:bob": "bob"},
  "next_cursor": "MjAyNi0xMC0wNlQyMjo0NzowOVp8ZXZlbnQ6...",
  "group_by": "category", "groups": [{"key": "auth", "count": 17}, "..."],
  "histogram": [{"start": "2026-10-06T22:47:00Z", "count": 6}, "..."]
}
```

`filters` lists the recognized filter terms (free text appears quoted). `names` maps the actor,
target and host IDs of the returned page to object names. The event fields are described in the
[object model](../object-model.md#events). An export prints `raf.timeline.export/v1`:
`{path, format, events, sha256}` (plus `bundle_version` for `raf`).

The terminal table shows time, severity, type, actor and target names, outcome and the first 60
characters of the message; imported text is escaped before it is printed.

## API

| Method | Path | Result |
|---|---|---|
| GET | `/timeline?ref=&start=&end=&type=&category=&severity=&q=&filter=&group_by=&cursor=&limit=&descending=&buckets=` | the `raf.timeline/v1` fields (without `schema`); `limit` 1-2000 (default 200), `buckets` 1-500 (default 60) |
| GET | `/timeline/export?ref=&format=&start=&end=&type=&severity=&filter=` | file download `timeline-<scope>.<format>` (`text/csv`, `application/json`, `application/x-ndjson`, `application/zip`); recorded in the audit log. `format` is case-insensitive; any other value is a 422 before anything is written. The file is written to a temporary file that is removed after the download, or at once when the export fails |

`ref` omitted or `workspace` selects the whole workspace. `filter` takes the filter language; `q` is
plain text searched in messages, event types, actor and target IDs and raw records (an unquoted word
of the filter language does the same). `start` and `end` must be full timestamps. `type` and
`category` are repeatable. `group_by` always applies (an empty value is rejected). The export route
has no `category` or `q` parameter: use `category:` terms in `filter`.

## Detections

`raf detect [SCOPE] [--dry-run]` runs R$F's detection rules over the events of a scope (by default the
whole workspace); `raf analyze` runs them over the events of every input it imports (the
**Detections** step). Rules read normalized events, so they work the same on JSON Lines, syslog, a
packet capture or a [mixed multi-source log](../logs.md). Each finding cites its events, the objects
involved, the baseline it compared against and its MITRE ATT&CK technique; findings are stored with
product `timeline` and stable IDs, so a re-run updates them and resolves the ones it no longer
produces (only those whose evidence lies in the examined events).

```text
$ raf detect analysis-1

R$F DETECT  analysis-1
────────────────────────────────────────
Events      2,560
Detections  9
Explained   2
Incidents   CASE-125236

Detections:
  CRITICAL  Suspected exposed credentials → credential misuse → data collection → persistence attempt →
            exfiltration (198.51.100.77): 5 correlated detections
  CRITICAL  Bulk read from bucket raven-backups by svc-ci from 198.51.100.77: 8 object(s), 320.7 MB (db/2026-10-05/)
  HIGH      Cloud identity svc-ci used from public address 198.51.100.77: 12 API call(s) (GetObject x8,
            GetCallerIdentity, ListBuckets, ListObjectsV2, AttachUserPolicy), 1 denied
  HIGH      Sensitive artifact served publicly: support-bundle.zip downloaded by 198.51.100.77; it contains deploy.env
  HIGH      Large transfer between 198.51.100.77 and 52.95.150.20: 320.7 MB over 443/tcp (1,074x the largest routine flow)
  MEDIUM    Persistence attempt: svc-ci called AttachUserPolicy for itself from 198.51.100.77 - denied (AccessDenied)
  MEDIUM    Alert from Raven EdgeWAF: SQL injection attempt blocked
  LOW       Web reconnaissance from 203.0.113.66: 6 probes of sensitive paths (/.env, /wp-login.php, ...) in 10 s; all refused
  LOW       Sign-in from a new public address: carol from 192.0.2.44 to raven-sso (MFA completed)

Explained (no finding):
  3 destructive operation(s) by system:serviceaccount:ops:deploy-bot (delete pods x3): covered by approved change
  CHG-1017 (rolling_restart on payments, window 21:20-21:50Z)
  Large export of q3-summary.csv (151.2 MB) by finance.batch: carries its own reference ticket FIN-301 (...)
```

### Rules

| Rule | Detects | Severity | ATT&CK |
|---|---|---|---|
| `web-recon` | one client requesting 5+ well-known sensitive paths (`/wp-admin`, `/.git/`, `/.env`, `/actuator`, ...) within 15 minutes, or a burst of 30+ client errors (70%+ of its requests, 10+ paths) | LOW when every probe was refused, MEDIUM when one was answered | T1595.003 |
| `exposed-artifact` | an archive, dump or diagnostics bundle served without authentication, through a public link or to a public address; web and application records of the same download are joined by request ID | HIGH when its manifest lists credential files (`.env`, keys, `credentials` ...), else MEDIUM | T1552.001 |
| `cloud-credential-public` | calls signed by a cloud identity from a public address, when the scope's cloud calls come from internal networks (80%+), the identity is also used internally (the description names the same key used from both networks), a long-term key (`AKIA...`) signed them, the identity is a service identity, or the address appears in other detections | HIGH (MEDIUM for a person's identity with no other signal) | T1078.004 |
| `bulk-storage-read` | 5+ objects or 100 MB+ read from one bucket by one identity and address (CloudTrail and S3 access logs joined by request ID; sizes from the access logs) from a public address or by a flagged identity | CRITICAL from a public address with 100 MB+ or a sensitive bucket name, HIGH otherwise | T1530 |
| `cloud-persistence` | credential, user and permission changes (`CreateAccessKey`, `AttachUserPolicy`, `CreateUser` ...) from a public address, by a flagged or service identity, or denied | MEDIUM when denied (an attempt), HIGH, CRITICAL from a public address by a flagged identity | T1098.001 |
| `large-transfer` | a flow of 10 MB+ and 20× the 90th percentile of the scope's flows; the description names the domain the destination was resolved from and the storage read it matches | HIGH with a public endpoint, else MEDIUM | T1048 |
| `brute-force` | 5+ failures for an account in 10 minutes, 3× its own median rate, from one public address (or 10+ from anywhere) | HIGH when a sign-in followed within 30 minutes, else MEDIUM | T1110.001 |
| `password-spray` | 10+ failures from one address across 3+ accounts in 10 minutes | HIGH with a success, else MEDIUM | T1110.003 |
| `mfa-fatigue` | 5+ MFA challenges for an account in 10 minutes | MEDIUM | T1621 |
| `new-external-signin` | a sign-in from a public address never seen for the user, whose other sign-ins (3+) are internal | LOW with MFA in the same session, MEDIUM without | T1078 |
| `service-account-new-source` | a service account (`svc-`, `-bot`, `deploy` ...) with 3+ sign-ins from stable sources authenticating from a new one (the host holding the address is named) | HIGH | T1078, T1021 |
| `credential-access` | reads of credential files (`.env`, private keys, cloud credentials, `.pgpass` ...) and commands searching for them | HIGH for reads, MEDIUM for searches | T1552.001 |
| `suspicious-command` | reverse shells, download-and-execute, credential dumping, defense evasion, data uploads (`curl -T`), database exports (`COPY ... TO`, `pg_dump`), control bypasses (`--skip-review`), encoded PowerShell, persistence | HIGH or MEDIUM by kind | T1059 |
| `risky-sql` | statements exporting or reading files, running commands, changing privileges or destroying data | HIGH or MEDIUM | T1005 |
| `destructive-change` | deletion of workloads, secrets, roles or namespaces (Kubernetes) and `Delete*`/`Terminate*` cloud calls not covered by an approved change | MEDIUM | T1489 |
| `log-tampering` | `StopLogging`, `DeleteTrail`, `DeleteFlowLogs` ..., Windows 1102/104 | HIGH (MEDIUM when denied) | T1562.008 |
| `dns-tunneling` | 30+ distinct long names under one domain from one client | MEDIUM | T1071.004 |
| `large-export` | an application export or download of 100 MB+ without a ticket | MEDIUM | T1567 |
| `security-alert` | alerts of MEDIUM or higher raised by tools in the data (IDS, WAF, EDR, SIEM; CEF/LEEF, Suricata, Zeek notices), relayed with their own severity | the tool's | - |
| `attack-chain` | detections that share an entity (address, identity, credential, bucket, artifact, host) within two hours, one of them HIGH or worse | the worst member; one level higher with 4+ members | - |

Addresses count as internal in RFC 1918, carrier-grade NAT, loopback, link-local and IPv6
unique-local ranges and in `detect.internal_networks`; documentation ranges (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24) count as public, as they stand for Internet addresses in examples.

### Explained activity

Some activity looks like an attack and is not; R$F says why instead of raising a finding:

* a destructive operation inside the window of an **approved change record** (`change.record`
  events: ticket, status, window) for the same service or actor;
* an export that carries its own **ticket** (`FIN-301`);
* a database export, upload or large transfer by a **scheduled job** (a process started by cron,
  systemd or the Windows scheduler) - a transfer only when the job wrote a file of the same size
  (within 5%) on the same host before it.

They are listed under `Explained (no finding)` with the record that explains them, in the analysis
and in the narrative of a nearby incident.

### Correlated incidents

Detections that share an entity within two hours form a chain. A chain with a HIGH or worse member
becomes a **suspected incident** named `CASE-<hash>` (status `suspected`, source `raf detections`)
whose description is the time-ordered narrative of its steps and of the activity ruled out around
it; its events are linked, so `raf timeline CASE-...`, `raf replay CASE-...`, `raf graph CASE-...` and
`raf oracle ask` work on it. When most of a chain's events already belong to an incident of the
workspace (`INC-001` in the demo), the chain is reported as matching it and no new incident is made:
an existing incident is cited, never rewritten. Each chain is also an `attack-chain` finding citing
its member findings.

```text
CASE-125236  Suspected exposed credentials → credential misuse → data collection → persistence attempt → exfiltration
  2026-10-06 21:40:05  [HIGH] Credential Access: Sensitive artifact served publicly: support-bundle.zip ...
  2026-10-06 21:41:02  [HIGH] Initial Access: Cloud identity svc-ci used from public address 198.51.100.77 ...
  2026-10-06 21:41:14  [CRITICAL] Collection: Bulk read from bucket raven-backups by svc-ci ...
  2026-10-06 21:42:39  [MEDIUM] Persistence: Persistence attempt: svc-ci called AttachUserPolicy ...
  2026-10-06 21:42:56  [HIGH] Exfiltration: Large transfer between 198.51.100.77 and 52.95.150.20 ...
  Ruled out (no finding):
    3 destructive operation(s) by system:serviceaccount:ops:deploy-bot ...: covered by approved change CHG-1017 ...
```

In the demo workspace (`raf demo load` runs the detections), the rules reconstruct INC-001 from its
evidence: the VPN brute force ending in a sign-in without MFA, the `.env` read on DEV-01, `svc-deploy`
signing in to CI-01 from DEV-01, the `--skip-review` deployment, the `COPY ... TO` export and
`curl -T` upload on APP-01, the 48 MB transfer to `files.exfil-test.example` and the IDS alert; the
nightly backup (cron `pg_dump`, then 182 MB to the backup storage) is explained.

### Output and API

`raf detect --json` emits `raf.detections/v1`: `{scope, generated_at, events_examined, findings,
explained: [{rule, title, reason, events, at}], incidents: [{id, name, title, severity, confidence,
findings, events, start, end, narrative, existing}], by_severity, by_rule, created, updated,
resolved}`. `--dry-run` reports without storing findings or incidents.

| Method | Path | Result |
|---|---|---|
| POST | `/timeline/detect` with `{"ref": "analysis-3" \| "INC-001" \| null, "dry_run": false}` | the report above (without `schema`); recorded in the audit log unless `dry_run` |

## Configuration

| Key | Default | Meaning |
|---|---|---|
| `detect.internal_networks` | empty | extra internal networks for the detections, comma-separated CIDRs |

What an event carries is decided at import time (`ingest.store_raw`, `ingest.raw_max_bytes`,
`ingest.default_timezone`; see `raf config keys`).

## Limitations

* `after:` / `before:` filter terms do not accept `HH:MM` or relative values; `--from` / `--to` do.
* A `raf` export holds the selected events in memory while the bundle is written.
* Detections compare against the baseline of the examined scope (one file, one analysis or the
  workspace): a short scope gives a thin baseline, which is why several rules also require a public
  address, a service identity or a concentrated source. Thresholds are fixed, documented above.
* Detections keep bounded state (100,000 keys and 5,000 items per key and collection); beyond that
  the rules see a sample.
