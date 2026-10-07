# R$F Trace

R$F Trace answers two questions about one object: **how did it become involved** (backward: who
logged in, which process spawned it, which file read preceded a credential being used) and **what
did it do** (forward: logins, processes, connections, file operations). Every link is either
*observed* - stated by a single event - or *correlated* - consistent in time and structure across
events - and correlated links are labeled as such and never presented as proven causation.

Status: **BETA** · category: investigation · command: `raf trace` · API: `GET /api/v1/trace/{ref}`
· web: Investigate (`?trace=`) · depends on: core only (event store)

## Usage

```text
raf trace OBJECT [--direction both|back|forward] [--depth N]
```

* `OBJECT` - any object reference: ID, name, alias or context reference (`alice`, `host:dev-01`,
  `198.51.100.23`, `@last`). Processes, files, users, identities, hosts, IP addresses, domains and
  URLs have rules; other types only appear as causes or effects.
* `--direction` - `both` (default), `back` (also `backward`) or `forward` (also `fwd`).
* `--depth` - how many links away from the object to follow, 1-6 (default 3).

Trace reads events. It uses three relationship types besides them: `HAS_ADDRESS` (which host owns
an IP address), and `CONTAINS_SECRET` / `AUTHENTICATES_AS` (which file holds a credential of an
identity) for the credential-exposure correlation.

## Backward links (causes)

For an object X, Trace reads the events that involve X up to a time bound (none for the subject;
for every later object, the time of the link that led to it) and applies these rules:

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

**Correlations** (kind `correlated`, at most 25 per object):

| Relation | X | Rule | Confidence |
|---|---|---|---|
| `CREDENTIAL_EXPOSURE` | user, identity | a file holds a secret (`CONTAINS_SECRET`) that authenticates as X (`AUTHENTICATES_AS`); the file was read (`file.read`) and X's next successful `auth.login` followed within `trace.correlation_window_minutes`. The cause is the reading process (else the actor). | min(0.65, read × 0.7) |
| `SESSION_CONTEXT` | user, identity | X authenticated (`auth.login`, not failed) from an address of host H; another principal had logged into H within the 2 hours before and had not logged out of H in between. At most five of X's logins are examined. | 0.4 |
| `RESOLUTION_BEFORE_CONNECTION` | IP | a `network.*` event targets X and the same actor resolved a domain to X (`dns.query`) within the correlation window before it. The cause is the domain. | 0.7 |

## Forward links (effects)

For an object X, Trace reads the events that involve X from the time bound on (all observed):

| Condition | Effect and relation |
|---|---|
| X is the actor, the event has a target and did not fail | the target: `LOGGED_INTO` (`auth.login`), `STARTED` (`process.start`), `QUERIED` (`dns.query`), `REQUESTED` (`http.request`), `CONNECTED_TO` (`network.connection`), otherwise the event type in upper case (`FILE_READ`, `NETWORK_FLOW`, `TLS_HANDSHAKE`, ...) |
| X is the `parent` of a `process.start` | the started process: `SPAWNED` |
| X is the `process` of a `file.*` event | the file: `READ`, `CREATE`, `MODIFY`, `DELETE` |
| X is the `host` of a `process.start` | the process: `RAN` |

## Corroboration and confidence

An observed link carries the confidence of its event (`AUTHENTICATED_FROM` × 0.95). Links that
state the same fact - same cause, effect, relation and timestamp - from different sources (event
`source`) are merged: the other records are listed in `corroborated_by` and each one raises the
confidence to 1 − (1 − a)(1 − b), capped at **0.95** for observed and **0.6** for correlated
links. In the demo, bob's `LOGGED_INTO` DEV-01 at 22:58:03 is stated by both `auth.log` and
`raven-events.jsonl` and reaches 0.95. The terminal shows the level next to the value (HIGH ≥ 0.8,
MEDIUM ≥ 0.5, LOW below).

## Traversal

Objects are processed breadth-first up to `--depth`. Backward, the time of the link that reached an
object becomes its bound, so causes of causes are never later than their effect; forward, effects of
effects are never earlier. Each object keeps at most the five most recent links per relation (after
merging) backward and at most 75 links forward. An (object, time) state is explored once; at most 300
states are explored and 400 links collected per direction. Every link records `step` (its position)
and `parent_step` (the link through which its object was reached; `null` for the subject's own
links), which is how trees are drawn.

## The most supported causal chain

From the subject backwards: first the most recent observed link into the subject (a correlated one
only when no observed link exists), then, repeatedly, the link into the current cause - not later
than the previous link and not used before - with the highest confidence / (1 + gap in minutes / 15),
so strong causes close in time win. Links below 0.3 are ignored; the chain has at most 12 links and
is printed earliest cause first, each with its explanation. The chain is greedy and may visit an
object twice (`raf trace alice` alternates between alice and WS-01, her workstation).

## Example

```text
$ raf trace svc-deploy --direction back

R$F TRACE  svc-deploy  (identity:svc-deploy)
────────────────────────────────────────────
Causes      36
Effects     0
Observed    34
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
   │ LOGGED_INTO  2026-10-06 23:04:41  (observed, 0.95)
   ▼
CI-01
   │ AUTHENTICATED_FROM  2026-10-06 23:08:02  (observed, 0.94)
   ▼
svc-deploy  identity:svc-deploy
  · bob authenticated to DEV-01 from 10.10.1.22 (WS-02's address)
  ...

How it became involved (backward)
svc-deploy
├── ← AUTHENTICATED_FROM CI-01  2026-10-06 23:08:02  [observed, HIGH 0.94]  raven-edr line 7  +1 corroborating source(s)
│   ├── ← LOGGED_INTO svc-deploy  2026-10-06 23:04:41  [observed, HIGH 0.95]  raven-edr line 5  +1 corroborating source(s)
│   │   ├── ← AUTHENTICATED_FROM DEV-01  2026-10-06 23:04:41  [observed, HIGH 0.94]  raven-edr line 5  ...
│   │   ├── ← SESSION_CONTEXT bob  2026-10-06 22:58:03  [correlated, MEDIUM 0.60]  auth.log line 1  ...
...
Note: Correlated links are consistent in time and structure but are not proven causation.
```

The second correlated link is the credential exposure (from `--json`):

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
most 10 links per object and 70 per tree (`--json` has everything). Notes are printed when the
backward links contain correlations, and when the subject is not stored as an object. The CLI then
suggests `raf timeline`, `raf graph` and `raf blast` for the subject.

`--json` emits `raf.trace/v1`: `{subject, nodes, backward, forward, chain, notes}`.

| Element | Fields |
|---|---|
| `subject`, `nodes[]` | `id`, `name`, `type`, `depth` (links from the subject), `direction` (`subject`, `backward`, `forward`) |
| `backward[]`, `forward[]`, `chain[]` | `cause`, `effect`, `relation`, `kind` (`observed` / `correlated`), `confidence`, `timestamp`, `event_id`, `explanation`, `provenance` (`source`, `record`, `parser`, `raw_reference`), `direction`, `step`, `parent_step`, `corroborated_by[]` (provenance + `event_id`) |

## API

`GET /trace/{ref}?direction=&depth=` returns the same document without `schema`. `ref` may contain
`/`; `direction` accepts the CLI values; `depth` 1-6 (default 3). Errors: 404 unknown object, 409
ambiguous reference, 422 invalid direction or depth.

## Configuration

| Key | Default | Used for |
|---|---|---|
| `trace.correlation_window_minutes` | `720` | the maximum time between the credential read and the login (`CREDENTIAL_EXPOSURE`), and between the DNS resolution and the connection (`RESOLUTION_BEFORE_CONNECTION`). `SESSION_CONTEXT` uses a fixed 2-hour window, although the key's description mentions session context. |

## Limitations

* Trace follows events. Relationships that no event produced (inventory grants, policies) are not
  traced; use Graph, Blast or IAM for those.
* An incident is not referenced by its events as an object, so `raf trace INC-001` finds nothing;
  use `raf replay INC-001` or `raf timeline INC-001`.
* For the subject, the backward step reads its 500 oldest events and the forward step its 400
  oldest; later objects read the 500 most recent events before their bound. On very busy objects,
  narrow the question with `raf timeline` first.
* Correlations are heuristics. They need the supporting structure (addresses mapped to hosts with
  `HAS_ADDRESS`, credential files linked with `CONTAINS_SECRET` / `AUTHENTICATES_AS`) and stay
  capped at 0.6 even when corroborated.
* Corroboration compares a link only with the first link of the same fact, so a third record from
  the same other source is counted again (svc-deploy's `SESSION_CONTEXT` shows "+2 corroborating
  source(s)" for one corroborating event).
