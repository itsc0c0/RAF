# R$F Trace

R$F Trace answers two questions about one object: **how did it become involved** (backward: who
logged in, which process spawned it, which file read preceded a credential being used) and **what
did it do** (forward: logins, processes, connections, file operations). Every link is either
*observed* - stated by a single event - or *correlated* - consistent in time and structure across
events - and correlated links are labeled as such and never presented as proven causation. An
incident or an event can be traced too: from the incident's most significant event, or from the
event itself.

Status: **BETA** · category: investigation · command: `raf trace` · API: `GET /api/v1/trace/{ref}`
· web: Investigate (`?trace=`) · depends on: core only (event store)

## Usage

```text
raf trace REF [--direction both|back|forward] [--depth N]
```

* `REF` - an object reference: ID, name, alias or context reference (`alice`, `host:dev-01`,
  `198.51.100.23`, `@last`); an incident (`INC-001`, `@incident`); or an event ID (`event:...`).
  Processes, files, users, identities, hosts, IP addresses, domains and URLs have rules; other types
  only appear as causes or effects. Findings and snapshots are refused (exit 4).
* `--direction` - `both` (default), `back` (also `backward`) or `forward` (also `fwd`).
* `--depth` - how many links away from the subject to follow, 1-6 (default 3).

Trace reads events. It uses three relationship types besides them: `HAS_ADDRESS` (which host owns
an IP address), and `CONTAINS_SECRET` / `AUTHENTICATES_AS` (which file holds a credential of an
identity) for the credential-exposure correlation.

## Points in time

Every object is traced from a point in time, and Trace reads the events of that object that are
**nearest to it**: for causes, the 500 latest events at or before the point; for effects, the 400
earliest events at or after it. The subject has no point in time (unless it is an incident or an
event, see below), so its causes come from its 500 latest events and its effects from its 400 latest
events. Every later object is traced from the time of the link that reached it: causes of causes are
never later than their effect, effects of effects never earlier.

## Incidents and events

Events do not reference an incident as an object, so an incident is traced from its **most
significant event**: the linked event with the highest severity, and among those the latest (then
the highest event ID). An event ID is traced from that event. The event's target (else its actor,
else the first object it names) is the object traced, from the event's time, and the first link of
the trace connects it to the subject: backward `object → subject`, forward `subject → object`, with
the event type as relation (`ALERT`, `NETWORK_CONNECTION`, ...), the event's confidence and
provenance, kind `observed`. This link counts as one of the `--depth` links. A note names the event
used, and the result's `anchor` holds it (`event_id`, `event_type`, `timestamp`, `severity`,
`object`).

For INC-001 the most significant event is the HIGH alert *Unusual outbound data volume from APP-01
to a first-seen domain* at 23:20:00, so INC-001 is traced through APP-01 from 23:20:00. An incident
without linked events, or an event that names no object, gives a note and no links.

## Backward links (causes)

For an object X, Trace applies these rules to the events it reads (see
[Points in time](#points-in-time)):

| X is | Event | Cause and relation | Confidence |
|---|---|---|---|
| process | `process.start` with X as target | the `parent` process: `SPAWNED`; a user or identity actor: `STARTED` | event's |
| file | `file.<op>` with X as target | the `process` (else the actor): `READ`, `CREATE`, `MODIFY`, `DELETE` | event's |
| user, identity | any `auth.*` with X as actor, not failed, with a `src_ip` | the host that has that address (`HAS_ADDRESS`), else the IP: `AUTHENTICATED_FROM` | event's × 0.95 |
| user, identity | `iam.*` with X as target, except `*.remove`, `*.revoke`, `*.disable` | the actor: `CHANGED_ACCESS` | event's |
| host | `auth.login` / `auth.privilege` with X as target, not failed | the actor: `LOGGED_INTO` / `ELEVATED_ON` | event's |
| IP, host | `network.*` with X as target, not failed | the actor: `CONNECTED_TO` | event's |
| domain | `dns.query` with X as target | the actor: `QUERIED` | event's |
| IP | `dns.query` with X as an `answer` | the queried domain: `RESOLVED_TO` | event's |
| URL | `http.request` with X as target | the actor: `REQUESTED` | event's |

The events are examined newest first, and at most 75 rule links are collected per object.

**Correlations** (kind `correlated`, at most 25 per object):

| Relation | X | Rule | Confidence |
|---|---|---|---|
| `CREDENTIAL_EXPOSURE` | user, identity | a file holds a secret (`CONTAINS_SECRET`) that authenticates as X (`AUTHENTICATES_AS`); the file was read (`file.read`, the 20 latest reads before the point in time) and X's next successful `auth.login` followed within `trace.correlation_window_minutes`. The cause is the reading process (else the actor). | min(0.65, read × 0.7) |
| `SESSION_CONTEXT` | user, identity | X authenticated (`auth.login`, not failed) from an address of host H; another principal had logged into H within the 2 hours before and had not logged out of H in between. X's five latest logins before the point in time are examined. | 0.4 |
| `RESOLUTION_BEFORE_CONNECTION` | IP | a `network.*` event targets X and the same actor resolved a domain to X (`dns.query`) within the correlation window before it. The 25 latest such connections are examined. The cause is the domain. | 0.7 |

## Forward links (effects)

For an object X, Trace applies these rules to the events it reads (all observed):

| Condition | Effect and relation |
|---|---|
| X is the actor, the event has a target and did not fail | the target: `LOGGED_INTO` (`auth.login`), `STARTED` (`process.start`), `QUERIED` (`dns.query`), `REQUESTED` (`http.request`), `CONNECTED_TO` (`network.connection`), otherwise the event type in upper case (`FILE_READ`, `NETWORK_FLOW`, `TLS_HANDSHAKE`, ...) |
| X is the `parent` of a `process.start` | the started process: `SPAWNED` |
| X is the `process` of a `file.*` event | the file: `READ`, `CREATE`, `MODIFY`, `DELETE` |
| X is the `host` of a `process.start` | the process: `RAN` |

At most 75 effect links are collected per object, in the order the events are read.

## Corroboration and confidence

An observed link carries the confidence of its event (`AUTHENTICATED_FROM` × 0.95). Links that
state the same fact - same cause, effect, relation and timestamp - are merged into the first one:
each other **source** (event `source`) counts once, is listed in `corroborated_by` and raises the
confidence to 1 − (1 − a)(1 − b), capped at **0.95** for observed and **0.6** for correlated links.
More records from a source already counted (or the same event found twice) add nothing. In the demo,
bob's `LOGGED_INTO` DEV-01 at 22:58:03 is stated by both `auth.log` and `raven-events.jsonl` and
reaches 0.95. The terminal shows the level next to the value (HIGH ≥ 0.8, MEDIUM ≥ 0.5, LOW below).

## Traversal

Objects are processed breadth-first up to `--depth`. Each object keeps at most the five most recent
links per relation (after merging) backward and at most 75 links forward. An (object, time) state is
explored once; at most 300 states are explored and 400 links collected per direction. Every link
records `step` (its position) and `parent_step` (the link through which its object was reached;
`null` for the subject's own links, and for the first link of a trace from an event), which is how
trees are drawn.

## The most supported causal chain

The chain explains the subject with a sequence of backward links, each into the cause of the link
after it and not later than it, that **never visits an object twice** (the subject included). Each
link has a support: its confidence divided by (1 + gap in minutes / 15), the gap being the time to
the link it explains (the link into the subject: its confidence). The chain with the highest total
support wins:

* links below 0.3 confidence are ignored, and a link whose support is below 0.1 does not extend a
  chain (a 0.8 cause more than 105 minutes before the link it would explain);
* the first link is an observed one when the subject has one;
* the search is depth-first over the three best links at each step, at most 12 links and 2,000
  tried links, so the result is deterministic.

The chain is printed earliest cause first, each link with its explanation. In the demo, svc-deploy
is explained by WS-02 → bob → DEV-01 → svc-deploy; tracing `cat [20903]` gives WS-02 → bob → cat,
because the earlier steps of bob's path (the VPN login from 203.0.113.45, then WS-02) would visit bob
again - they remain in the backward tree.

## Example

```text
$ raf trace INC-001 --direction back --depth 6

R$F TRACE  INC-001  (incident:inc-001)
────────────────────────────────────────
Causes      49
Effects     0
Observed    47
Correlated  2

Most supported causal chain
WS-02
   │ AUTHENTICATED_FROM  2026-10-06 22:58:03  (observed, 0.94)
   ▼
bob
   │ LOGGED_INTO  2026-10-06 22:58:03  (observed, 0.95)
   ▼
DEV-01
   │ AUTHENTICATED_FROM  2026-10-06 23:04:41  (observed, 0.94)
   ▼
svc-deploy
   │ LOGGED_INTO  2026-10-06 23:08:02  (observed, 0.95)
   ▼
APP-01
   │ ALERT  2026-10-06 23:20:00  (observed, 0.70)
   ▼
INC-001  incident:inc-001
  · bob authenticated to DEV-01 from 10.10.1.22 (WS-02's address)
  · bob accessed DEV-01
  · svc-deploy authenticated to CI-01 from 10.20.0.11 (DEV-01's address)
  · svc-deploy accessed APP-01
  · INC-001's most significant event: HIGH alert involving APP-01: Unusual outbound data volume from APP-01 to a first-seen domain

How it became involved (backward)
INC-001
└── ← ALERT APP-01  2026-10-06 23:20:00  [observed, MEDIUM 0.70]  raven-events.jsonl record 767
    ├── ← LOGGED_INTO svc-deploy  2026-10-06 23:08:02  [observed, HIGH 0.95]  auth.log line 5  +1 corroborating source(s)
    │   ├── ← AUTHENTICATED_FROM CI-01  2026-10-06 23:08:02  [observed, HIGH 0.94]  auth.log line 5  +1 corroborating source(s)
    │   │   ├── ← LOGGED_INTO svc-deploy  2026-10-06 23:04:41  [observed, HIGH 0.95]  raven-edr line 5  +1 corroborating source(s)
...
Note: INC-001 is traced from its most significant event (highest severity, then latest): HIGH alert at 2026-10-06T23:20:00Z involving APP-01 (event:a49a5932ab338cf5db13d932).
Note: Correlated links are consistent in time and structure but are not proven causation.

Next:
  raf replay INC-001
  raf timeline INC-001
  raf graph INC-001
  raf trace host:app-01
```

`raf trace svc-deploy --direction back` reaches the credential exposure (from `--json`):

```json
{"cause": "process:dev-01|20903|2026-10-06T23:01:47Z", "effect": "identity:svc-deploy",
 "relation": "CREDENTIAL_EXPOSURE", "kind": "correlated", "confidence": 0.56,
 "timestamp": "2026-10-06T23:01:47Z", "event_id": "event:0ab15d6dfe6ce715173370f1",
 "explanation": ".env holds a credential that authenticates as svc-deploy; it was read by cat [20903] 2m54s before svc-deploy authenticated to CI-01. Correlation, not proof.",
 "provenance": {"source": "raven-edr", "record": "line 3", "parser": "jsonl/1.0",
                "raw_reference": "evidence:ev-0003#line 3"},
 "direction": "backward", "step": 2, "parent_step": null, "corroborated_by": []}
```

## Output

The terminal prints the counts, the chain with one explanation per link, and two trees ("How it
became involved", "What it did"). Each tree line shows the relation, the other object, the time,
`[kind, level confidence]`, the source record and the number of corroborating sources; trees show at
most 10 links per object and 70 per tree (`--json` has everything). Notes are printed for the event
an incident or event is traced from, when the backward links contain correlations, and when the
subject is not stored as an object. The CLI then suggests, with IDs quoted for the shell:
`raf timeline`, `raf graph` and `raf blast` for an object; `raf replay`, `raf timeline` and
`raf graph` for an incident; `raf show` for an event; and `raf trace` of the object an incident or
event was traced through.

`--json` emits `raf.trace/v1`: `{subject, nodes, backward, forward, chain, notes, anchor}`.

| Element | Fields |
|---|---|
| `subject`, `nodes[]` | `id`, `name`, `type`, `depth` (links from the subject), `direction` (`subject`, `backward`, `forward`); an event subject is named `<event type> <time>`, type `event` |
| `backward[]`, `forward[]`, `chain[]` | `cause`, `effect`, `relation`, `kind` (`observed` / `correlated`), `confidence`, `timestamp`, `event_id`, `explanation`, `provenance` (`source`, `record`, `parser`, `raw_reference`), `direction`, `step`, `parent_step`, `corroborated_by[]` (provenance + `event_id`) |
| `anchor` | `null` for objects; for an incident or event: `event_id`, `event_type`, `timestamp`, `severity`, `object` |

## API

`GET /trace/{ref}?direction=&depth=` returns the same document without `schema`. `ref` may contain
`/`; `direction` accepts the CLI values; `depth` 1-6 (default 3). Errors: 404 unknown object, 409
ambiguous reference, 422 invalid direction or depth, or a finding or snapshot reference.

## Configuration

| Key | Default | Used for |
|---|---|---|
| `trace.correlation_window_minutes` | `720` | the maximum time between the credential read and the login (`CREDENTIAL_EXPOSURE`), and between the DNS resolution and the connection (`RESOLUTION_BEFORE_CONNECTION`). `SESSION_CONTEXT` uses a fixed 2-hour window. |

## Limitations

* Trace follows events. Relationships that no event produced (inventory grants, policies) are not
  traced; use Graph, Blast or IAM for those.
* Each object contributes at most 500 events backward and 400 forward, the ones nearest to its point
  in time; older causes of a very busy object are not seen. Narrow the question with
  `raf timeline` first, or trace an event (`raf trace event:...`) to set the point in time.
* An incident is traced from one event only; trace other events of the incident by their IDs
  (`raf timeline INC-001 --json` lists them).
* Correlations are heuristics. They need the supporting structure (addresses mapped to hosts with
  `HAS_ADDRESS`, credential files linked with `CONTAINS_SECRET` / `AUTHENTICATES_AS`) and stay
  capped at 0.6 even when corroborated.
* The chain never revisits an object, so a principal that moves through several hosts appears once
  in it; the backward tree shows the whole path.
