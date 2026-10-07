# R$F Replay

R$F Replay reconstructs what the environment looked like, moment by moment, during an incident (or
any scope): which sessions were open, which processes ran, which relationships existed, which files
were touched, which flows and alerts occurred. Every step is derived from one event and the
relationships that event produced, events are applied in a total order, and every state has a
SHA-256 hash, so the same events always give the same states and the same hashes.

Status: **BETA** · category: investigation · command: `raf replay` · API: `/api/v1/replay`
· web: Replay · depends on: core only (event and relationship stores)

## Usage

```text
raf replay SCOPE                                   sequence overview
raf replay SCOPE --at T                            state at a moment
raf replay SCOPE --from T [--to T]                 what changed within a window
raf replay SCOPE --play [--speed 0.25|0.5|1|2|5|10] compressed playback in the terminal
    options: [--no-context] [--limit N]
```

`SCOPE` is required: an incident (`INC-001`), an object (`alice`, `host DEV-01`), an analysis or a
job (`analysis-1`, `job-1`), a context reference (`@incident`, `@last`) or `workspace`. `--at`,
`--from` and `--to` accept ISO timestamps, epoch values, `now`, a time of day `HH:MM[:SS]` placed in
the replay window (choosing the occurrence inside the window when it spans midnight) and offsets
such as `+10m` from the window start.

## Window and events

* **Window.** For an incident whose metadata has both `start` and `end`, that interval (INC-001:
  22:40-23:45); otherwise the first and last event of the scope. `--from` / `--to` do not change the
  window that is built; they select the part reported by the window view.
* **Events.** The scope's events inside the window, ordered by (timestamp, event ID), at most 50,000
  (a larger window is rejected with a hint to narrow it). For an incident, events linked to it but
  outside the window are counted in `excluded_events` and reported in a note.
* **Initial context.** Unless `--no-context` is given, the relationships among the objects involved
  in the replayed events that are valid at the window start (same rule as Graph `--at`) form the
  initial state: INC-001 starts with 24 relationships among 20 objects.

## Reconstruction

The state consists of objects, relationships, open sessions, running processes, flows, file
activity, identity changes and alerts. Each event becomes one step holding only its **delta**:

| Event | Step effect | Summary |
|---|---|---|
| any | objects of the event not yet in the state are added; relationships the event produced are added | |
| `iam.role.remove`, `iam.group.remove`, `iam.permission.revoke`, `process.end`, `file.delete` | a produced relationship whose `valid_to` is at or before the event time is removed | |
| `auth.login`, not failed | session `user@host` opened `{user, host, since, source (src_ip), method}` | `bob logged into VPN-01 from 203.0.113.45` |
| `auth.logout` | the open session of that user on that host is closed | `bob logged out of DEV-01` |
| `auth.failure` | - | `failed login for bob on VPN-01 from 203.0.113.45` |
| `auth.privilege` | - | `... elevated privileges on ... (as_user)` |
| `process.start` | process added `{process, host, user, since, command_line}` | `bob started cat [20903] on DEV-01: cat /opt/deploy/.env` |
| `process.end` | process removed | `... exited` |
| `network.*`, `tls.*` | when not failed: flow `{at, source, destination, port, bytes_out, protocol}` | `APP-01 → 198.51.100.23:443 (48.2 MB out)`, `[blocked]` when failed |
| `file.*` | file activity `{at, operation, file, actor}` (the process, else the actor) | `cat [20903] read .env` |
| `iam.*` | identity change `{at, change, actor, target, detail}` (`role`, `group`, `resource`) | `dev-admin: iam.user.disable on bob` |
| `alert*` | alert `{at, event_id, severity, message, target}` | `ALERT Unusual outbound data volume ...` |
| `dns.query`, `http.request`, others | - | resolution, request, or the event message |

**State at T** applies, in order, every step whose timestamp is at or before T to the initial
state; `step_index` is the index of the last applied step (`-1` before the first). Flows are
reported when they happened within the 10 minutes before T.

**State hash.** The SHA-256 of a canonical JSON form of the state: sorted object and relationship
IDs, sessions and processes in key order, and flows, files, identity changes and alerts sorted by
content with event IDs removed. The hash therefore depends only on what the events say, not on
import order or event IDs: loading the demo into two workspaces gives the same INC-001 final hash
`ac2c424d6cb70a51...` and the same state hash at 23:04:41 (`139f26d370c7a6cd...`).

**Checkpoints.** Every `replay.checkpoint_interval` steps (500) the timeline records `{index,
state_hash}` (the workspace replay of the demo, 562 events, has one checkpoint at index 499). They
let a client verify its own reconstruction; they hold hashes, not states, and `--at` always replays
from the start of the window.

## Views

**Overview** (no option): window, number of events, objects, initial context, the final state hash,
and the sequence of step summaries with consecutive identical steps (same type, actor and target)
collapsed (`6x failed login for bob on VPN-01`), marked `[new session]` or `[relationship ended]`.
`--limit` sets the number of lines (default 80).

```text
$ raf replay INC-001

R$F REPLAY  INC-001  Suspicious production data access via the deployment pipeline
──────────────────────────────────────────────────────────────────────────────────
Window      2026-10-06T22:40:00Z → 2026-10-06T23:45:00Z (65m)
Events      44
Objects     48
Context     24 relationships valid at start
State hash  ac2c424d6cb70a51 (deterministic)

Sequence
22:47:00  LOW     6x failed login for bob on VPN-01 from 203.0.113.45
22:52:11  MEDIUM  bob logged into VPN-01 from 203.0.113.45  [new session]
22:53:40  INFO    bob logged into WS-02 from 10.40.0.2  [new session]
22:58:03  MEDIUM  bob logged into DEV-01 from 10.10.1.22  [new session]
...
23:01:47  HIGH    cat [20903] read .env
23:04:41  INFO    2x svc-deploy logged into CI-01 from 10.20.0.11  [new session]
23:06:05  HIGH    svc-deploy started deploy.sh [9120] on CI-01: deploy.sh --target prod --skip-review --extra-step db-report
...
23:16:30  HIGH    APP-01 → 198.51.100.23:443 (48.2 MB out)
23:20:00  HIGH    ALERT Unusual outbound data volume from APP-01 to a first-seen domain
23:25:12  MEDIUM  dev-admin: iam.user.disable on bob
23:27:00  INFO    dev-admin: iam.group.remove on bob  [relationship ended]
```

**State** (`--at T`): a scrubber across the window, the step number, object and relationship counts,
the state hash, then active sessions, running processes, flows of the last 10 minutes, file activity
(last 10), identity changes and alerts (15 lines per section).

```text
$ raf replay INC-001 --at 23:04:41
22:40:00 ──────────────●───────────────────────── 23:45:00
                       ▲
                    23:04:41

Step           19 / 44
Objects        29
Relationships  45
State hash     139f26d370c7a6cd

Active sessions (4)
  svc-deploy @ CI-01 since 23:04:41 from 10.20.0.11
  bob @ DEV-01 since 22:58:03 from 10.10.1.22
  bob @ VPN-01 since 22:52:11 from 203.0.113.45
  bob @ WS-02 since 22:53:40 from 10.40.0.2

Running processes (3)
  find [20877] on DEV-01 (find /opt -name *.env)
  cat [20903] on DEV-01 (cat /opt/deploy/.env)
  ssh [20950] on DEV-01 (ssh svc-deploy@ci-01)
...
```

**Window** (`--from` / `--to`, either may be omitted): the events in the interval and what they
changed: new objects (first appearance relative to the state just before the interval), new and
ended relationships, sessions opened and closed, processes, flows, file activity, identity changes
and alerts. `raf replay INC-001 --from 23:00 --to 23:10` reports 11 events, 11 new objects (`.env`,
`cat [20903]`, `deploy.sh [9120]`, `psql [8240]`, ...) and 19 new relationships. `--at` takes
precedence over `--from` / `--to`.

**Playback** (`--play`): prints the step summaries with pauses in compressed time - at `1x` one
minute of incident time takes one second; every pause lasts between 0.03 and 2 seconds; speeds are
0.25, 0.5, 1, 2, 5 and 10 (others are rejected). Ctrl+C stops the playback. `--play` is ignored with
`--json`.

Every CLI run records a `replay.build` audit entry with the number of steps and the final state hash.

## Output

| Schema | View | Fields |
|---|---|---|
| `raf.replay/v1` | overview, `--play --json` | `scope`, `title`, `start`, `end`, `objects` (`{id: {name, type, criticality}}`), `relationships` (`{id: {type, source, target}}`), `initial_objects`, `initial_relationships`, `steps`, `checkpoints` (`[{index, state_hash}]`), `final_state_hash`, `excluded_events`, `notes` |
| `raf.replay.state/v1` | `--at` | `at`, `step_index`, `objects`, `relationships`, `sessions`, `processes`, `recent_flows`, `files`, `identity_changes`, `alerts`, `state_hash`, `scope` |
| `raf.replay.window/v1` | `--from` / `--to` | `from`, `to`, `events`, `new_objects`, `added_relationships`, `removed_relationships`, `sessions_opened`, `sessions_closed`, `processes`, `flows`, `files`, `identity_changes`, `alerts`, `scope` |

A step: `{index, timestamp, event_id, event_type, severity, summary, actor, target, added_objects,
added_relationships, removed_relationships, sessions_opened, sessions_closed, processes_started,
processes_ended, flows, files, identity_changes, alerts}`. The web player (and any client) rebuilds
states from `initial_*` and the step deltas.

## API

| Method | Path | Result |
|---|---|---|
| GET | `/replay/{ref}?include_context=&start=&end=` | the timeline (`raf.replay/v1` fields); `start` / `end` narrow the window that is built |
| GET | `/replay/{ref}/state?at=&include_context=` | the state at `at` (required) |
| GET | `/replay/{ref}/window?start=&end=` | the changes within `start`..`end` (both required) |

`ref` is a single scope word (incident, object ID or name, `analysis-N`, `job-N`, `workspace`);
times must be full timestamps (no `HH:MM` or offsets). The API does not write audit entries for
replays.

## Configuration

| Key | Default | Notes |
|---|---|---|
| `replay.checkpoint_interval` | `500` | steps between recorded checkpoint hashes (minimum 10) |

## Limitations

* Sessions are keyed by user and host: two concurrent sessions of the same user on the same host
  are one session, and a duplicate `auth.login` from a second source re-opens it (shown as `2x`).
* Only the event types listed above change sessions, processes, flows, files, identity changes and
  alerts; other events add objects and relationships and contribute a summary.
* Relationship removal depends on the removal event having ended the relationship (`valid_to`) at
  import time.
* The whole window is rebuilt for every request; there is no stored replay index. Windows above
  50,000 events must be narrowed (API `start` / `end`).
