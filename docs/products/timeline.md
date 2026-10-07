# R$F Timeline

R$F Timeline puts every normalized event of a scope - an object, an incident, an analysis, a job or
the whole workspace - on one time axis, whatever source it came from (JSONL exports, syslog, EDR
events, proxy logs, packet captures). It answers: what happened, in which order, by whom, against
what, from which source record - and it exports exactly that selection.

Status: **BETA** · category: investigation · command: `raf timeline` · API: `/api/v1/timeline`
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

## Configuration

Timeline has no configuration keys of its own. What an event carries is decided at import time
(`ingest.store_raw`, `ingest.raw_max_bytes`, `ingest.default_timezone`; see `raf config keys`).

## Limitations

* `after:` / `before:` filter terms do not accept `HH:MM` or relative values; `--from` / `--to` do.
* A `raf` export holds the selected events in memory while the bundle is written.
