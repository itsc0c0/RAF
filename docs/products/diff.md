# R$F Diff

R$F Diff compares two security states - two snapshots, a snapshot and the live workspace, or a
Ghost what-if model (directly or as a snapshot) - and lists what changed among objects,
relationships and findings. Every change gets a category, an importance (HIGH, MEDIUM, LOW) and a written reason, from
fixed rules: a new path from the Internet or a new grant onto a privileged role matters more than a
process that started.

Status: **BETA** · category: investigation · command: `raf diff` (states: `raf snapshot`) · API:
`GET /api/v1/diff`, `/api/v1/snapshots` · web: no dedicated view yet (manifest route `/investigate`)
· depends on: core only (`raf.core.snapshots`)

## Usage

```text
raf snapshot create NAME [--source current|ghost:MODEL] [--description TEXT]
raf snapshot list | show NAME | delete NAME
raf diff A B [--only CATEGORY] [--limit N]
```

### States

| State | Meaning |
|---|---|
| `current` (also `now`, `@workspace`) | the live workspace, computed when the command runs |
| a snapshot name (or `snapshot:<name>`; case-insensitive) | a stored snapshot |
| `@snapshot`, `@last` | the snapshot most recently created in this workspace |
| `ghost:<model>` | a Ghost what-if model, computed when the command runs |

A Ghost model can be compared directly or persisted as a snapshot first:

```text
raf ghost clone current hardened
raf ghost modify hardened --remove-access alice:production
raf diff current ghost:hardened
raf snapshot create a
raf snapshot create b --source ghost:hardened -d "alice cut from production"
raf diff a b
```

## Snapshots

A snapshot records every object, relationship and finding of a state as its ID plus the SHA-256 of
its **canonical content**:

| Kind | Content that counts |
|---|---|
| object | type, name, sorted tags, metadata, active (`valid_to` empty), synthetic |
| relationship | type, source, target, metadata (without `via`), active |
| finding | title, severity, status, product, rule ID, sorted affected objects, confidence (2 decimals) |

Metadata keys `state_changed_at`, `status_history`, `last_scan` and `scanned_at` are ignored, and so
are bookkeeping fields (timestamps, `first_seen`/`last_seen`, observation counts, the confidence and
source of objects and relationships): re-observing the same state is not a change. Events, evidence
and provenance are not part of snapshots.

Content bodies are stored once in a content-addressed table shared by all snapshots; an unchanged
item costs one index row. `raf snapshot create` reports the storage effect (`b` above: *0 new
blobs, 1,314 shared*) and a **state hash**, the SHA-256 over the sorted (kind, ID, content hash)
rows: two snapshots with the same hash hold the same state.

Every object and relationship row carries the hash of its content, written with the row, so a
snapshot of the workspace copies hashes inside the database and computes bodies only for content no
snapshot holds yet. Rows without a hash - written before R$F kept them, or relationships ended in
bulk - get one at the next snapshot (the first snapshot of an older workspace computes them all
once). `raf diff` reads the bodies of the items that changed only.

* Names: letters, digits, `.`, `_`, `-` (at most 64 characters, starting with a letter or digit),
  not `current`, unique without regard to case; a duplicate is refused (exit 4).
* `--source ghost:MODEL` stores the model's state (relationships and objects after its what-if
  operations; findings as carried over from the model's base) with source `ghost:MODEL`.
* Ghost keeps its frozen bases as snapshots named `ghost-<model>-base`; they appear in
  `raf snapshot list`.
* `raf snapshot delete NAME` asks for confirmation (`--yes` in scripts) and removes the bodies no
  other snapshot uses.
* Creating and deleting snapshots are audited (`snapshot.create`, `snapshot.delete`); `raf diff`
  records `diff.compare` with the number of changes.

## Comparison

Items are matched by ID within each kind: present only in B is **added** (`+`), only in A
**removed** (`-`), in both with a different content hash **changed** (`~`). Each change is then
classified; categories are `privileges`, `exposure`, `vulnerabilities`, `network`, `policies`,
`hosts`, `services`, `identities`, `packages`, `findings`, `objects`, `relationships`, `activity`.
Changes are sorted HIGH, MEDIUM, LOW, then by category and item ID.

### Objects

| Change | Category | Importance and reason |
|---|---|---|
| added host, service, user, identity, cloud_resource, container | `hosts`, `services`, `identities` (`objects` for cloud resources and containers) | MEDIUM *new <type> in the environment*; HIGH *new internet-facing <type>* (`metadata.internet_facing`) or *new high/critical-criticality <type>* |
| added identity with `metadata.privileged` | `identities` | HIGH *new privileged identity* |
| added policy | `policies` | MEDIUM *policy added* |
| added vulnerability, package, other types | `vulnerabilities`, `packages`, `objects` | LOW *new <type>* |
| removed (any type) | by type, as above | LOW *<type> no longer present* |
| changed: `internet_facing` | `exposure` | HIGH *became internet-facing*, LOW *no longer internet-facing (exposure reduced)* |
| changed: `criticality` | `exposure` | MEDIUM *criticality critical -> high* |
| changed: `privileged` became true | `privileges` | HIGH *<type> became privileged* |
| changed: `disabled` | `identities` | LOW *account disabled*, MEDIUM *account re-enabled* |
| changed: a policy object | `policies` | MEDIUM *policy definition changed* |
| changed: `cvss` | `vulnerabilities` | MEDIUM *vulnerability score changed* |
| changed: anything else (metadata keys, name, tags, active, synthetic) | `objects` | LOW *metadata changed: <fields>* |

The first matching rule applies to a changed object; `details.fields` lists every changed field as
`{from, to}`. A vulnerability's importance comes from its `AFFECTS` relationship, not from the object.

**Package versions.** When `package:<ecosystem>/<name>@<version>` disappears and the same package
appears with another version, one `packages` change *package version changed 2.31.0 -> 2.32.3* (LOW,
`~`, item ID the new package, `details.from`, `details.to`, `details.previous_id`) replaces the
addition and the removal of the two package objects. When several versions of a package disappear or
appear, the newest removed version is paired with the newest added one, and so on (versions compare
number by number: 2.10 is newer than 2.9); versions left without a partner are reported as added or
removed.

### Relationships

| Relationship types | Category | Added | Removed |
|---|---|---|---|
| `HAS_ROLE`, `MEMBER_OF`, `CAN_ACCESS`, `ADMIN_OF`, `CAN_ASSUME`, `HAS_PERMISSION`, `USES`, `AUTHENTICATES_AS`, `TRUSTS`, `DEPLOYS_TO`, `HAS_IDENTITY`, `OWNS` | `privileges` | HIGH when the target is privileged or of high/critical criticality (*HAS_ROLE grants access to a privileged target*) or the type is `ADMIN_OF` (*administrative rights granted*); otherwise MEDIUM *new <TYPE> privilege* | LOW *<TYPE> removed (privilege reduced)* |
| `CAN_REACH`, `ALLOWS`, `DENIES` | `exposure` when the source ID ends in `:internet`, else `network` | HIGH *new reachability from the internet*; HIGH *new network path into <crit>-criticality zone*; otherwise MEDIUM *new network reachability* | LOW *network reachability removed (segmentation)* |
| `AFFECTS` | `vulnerabilities` | HIGH *new vulnerability (CVSS 9.1) on APP-01* when the vulnerability's `cvss` ≥ 7, else MEDIUM | LOW *vulnerability resolved / patched* |
| `LOGGED_INTO`, `SPAWNED`, `STARTED`, `EXECUTED`, `CREATED`, `MODIFIED`, `DELETED`, `READ`, `CONNECTED_TO`, `RESOLVED`, `REQUESTED`, `RUNS` | `activity` | LOW *<TYPE> added* | LOW *<TYPE> removed* |
| every other type | `relationships` | LOW | LOW |

A relationship that became inactive (`valid_to` set) is reported as removed with the reason
*relationship ended*; one that became active again as added (*relationship re-activated*, with the
importance of an addition); any other content change as `changed`, LOW, *relationship attributes
changed*, with the metadata before and after. `details` holds `type`, `source`, `target` (and
`cvss` for `AFFECTS`).

### Findings

| Change | Importance and reason |
|---|---|
| new finding | HIGH *new HIGH finding* / *new CRITICAL finding*; otherwise MEDIUM |
| finding no longer present | LOW |
| severity raised | HIGH when it is now HIGH or CRITICAL, else MEDIUM: *severity MEDIUM -> CRITICAL* |
| severity lowered | LOW *severity HIGH -> MEDIUM (risk reduced)* |
| affects more objects | HIGH for a HIGH or CRITICAL finding, else MEDIUM: *affects 2 more object(s)* |
| affects fewer objects | LOW *affects 1 fewer object(s)* |
| confidence changed | MEDIUM when its level rose (LOW < 0.5 ≤ MEDIUM < 0.8 ≤ HIGH): *confidence 0.60 -> 0.90 (MEDIUM -> HIGH)*; otherwise LOW |
| status changed | LOW *status OPEN -> RESOLVED* |
| title, product or rule changed | LOW *title changed* |

A finding whose content changed is one `~` change: its importance is the highest of the rows that
apply, its reason lists them in the order above, separated by `; ` (*confidence 0.60 -> 0.30; status
OPEN -> RESOLVED*), and `details.fields` holds every changed field as `{from, to}`
(`affected_objects` as `{added, removed}`).

## Example

```text
$ raf diff before after

R$F DIFF  before → after
────────────────────────────────────────
Objects        426 → 430
Relationships  849 → 852
Changes        8  (HIGH 5, MEDIUM 2, LOW 1)

CATEGORY         ADDED  REMOVED  CHANGED
privileges       1      0        0
exposure         1      0        1
vulnerabilities  2      0        0
hosts            1      0        0
services         1      0        0
identities       1      0        0

+ HIGH   exposure        INTERNET -CAN_REACH-> EDGE-01  — new reachability from the internet
+ HIGH   hosts           EDGE-01 (host)  — new internet-facing host
+ HIGH   identities      svc-backup2 (identity)  — new privileged identity
+ HIGH   privileges      carol -HAS_ROLE-> break-glass  — HAS_ROLE grants access to a privileged target
+ HIGH   vulnerabilities SIM-2026-0099 -AFFECTS-> APP-01  — new vulnerability (CVSS 9.1) on APP-01
~ MEDIUM exposure        DB-01 (host)  — criticality critical -> high
+ MEDIUM services        metrics (service)  — new service in the environment
+ LOW    vulnerabilities SIM-2026-0099 (vulnerability)  — new vulnerability
```

(`before` is the Raven demo; `after` adds an internet-facing host, a privileged identity, a service,
a CVSS 9.1 vulnerability on APP-01, carol's `HAS_ROLE break-glass` and lowers DB-01's criticality.)
The Ghost comparison above (`raf diff a b`) lists three LOW changes: `DEV-01 -USES-> svc-deploy`
(privileges), `.env -CONTAINS_SECRET-> DEPLOY_TOKEN` (relationships) and `dave -LOGGED_INTO->
DEV-01` (activity), each *removed*.

## Output

The terminal shows the object and relationship totals, the importance counts, a category table and
the change list (`+`, `-`, `~`). `--only CATEGORY` restricts the list (not the table) to one
category (case-insensitive; any other word is refused with exit 4 and the list of categories),
`--limit` (default 60) caps it, and `--quiet` keeps only HIGH changes.

`--json` emits `raf.diff/v1` with every change, regardless of `--only` and `--limit`:

```json
{
  "schema": "raf.diff/v1", "a": "before", "b": "after", "generated_at": "2026-10-07T13:48:43.752214Z",
  "summary": {"exposure": {"added": 1, "removed": 0, "changed": 1}, "...": {}},
  "importance": {"HIGH": 5, "MEDIUM": 2, "LOW": 1},
  "totals": {"objects_a": 426, "objects_b": 430, "relationships_a": 849, "relationships_b": 852, "changes": 8},
  "changes": [{"category": "exposure", "change": "added", "item_kind": "relationship",
               "item_id": "rel:269a101acafe0b77895a5626", "label": "INTERNET -CAN_REACH-> EDGE-01",
               "importance": "HIGH", "reason": "new reachability from the internet",
               "details": {"type": "CAN_REACH", "source": "network:internet", "target": "host:edge-01"}}]
}
```

Snapshot commands emit `raf.snapshot/v1` (`{id, name, source, description, created_at, stats:
{objects, relationships, findings, new_blobs, shared_blobs}, content_hash}`), `raf.snapshots/v1`
(`items`) and `raf.snapshot.delete/v1` (`{name, items, blobs_removed}`).

## API

| Method | Path | Result |
|---|---|---|
| GET | `/diff?a=&b=&category=&limit=` | the `raf.diff/v1` fields plus `truncated`; `category` filters `changes` (the summary, importance and totals still count everything; an unknown category is a 422 whose `details.valid_categories` lists the categories); `limit` default 500, clamped to 1-5000 |
| GET | `/snapshots` | `{items: [Snapshot]}` |
| POST | `/snapshots` `{name, source: "current"|"workspace"|"ghost:<model>", description}` | 201 + the snapshot |
| GET | `/snapshots/{name}` | one snapshot |
| DELETE | `/snapshots/{name}` | `{name, items, blobs_removed}` (no confirmation step) |

`a` and `b` accept the same states as the CLI, `ghost:<model>` included.

## Configuration

Diff and snapshots have no configuration keys.

## Limitations

* Snapshots hold objects, relationships and findings, not events; `current` (and a `ghost:<model>`
  state) is recomputed from the whole workspace on every comparison.
* Changes to timestamps and to the confidence of objects and relationships are not changes by
  design.
