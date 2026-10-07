# R$F security object model

Every R$F product reads and writes one shared model: **objects** (hosts, users, files, IPs, ...),
first-class **relationships** between them, normalized **events**, **findings** and **incidents**.
Nothing is kept in product-private copies, so an object imported from a log is the same object that
Graph draws, Blast traverses, Timeline lists and Oracle cites. `raf version` reports the model
versions (`object_model 1.0`, `event_schema 1.0`). Implementation: `raf.core.objects` (models,
types, traversal semantics), `raf.core.ids` (identifiers), `raf.core.events.taxonomy` (event
types), `raf.core.ingestion.builder` (relationships derived from events).

## Identifiers

Objects are identified by `<type>:<normalized key>`. IDs are derived from content, never generated
randomly, so importing the same data twice creates nothing new and every product refers to an entity
by the same ID.

| Type | Key normalization | Example |
|---|---|---|
| all types | whitespace runs collapsed to one space, trimmed; an empty key is an error | |
| `host`, `user`, `identity`, `group`, `role`, `permission`, `organization`, `network`, `service`, `incident`, `certificate`, `package`, `dependency`, `policy`, `snapshot` | lower-cased | `host:dev-01`, `user:alice`, `incident:inc-001` |
| `domain` | lower-cased, trailing dot removed | `domain:files.exfil-test.example` |
| `ip` | parsed and written in compressed form (brackets and IPv6 zone removed); an invalid address is an error | `ip:10.30.0.5`, `ip:2001:db8::1` |
| `url` | scheme and host lower-cased, path and query kept, fragment dropped | `url:http://intranet.raven.example/` |
| every other type (incl. `file`, `process`, `vulnerability`, `secret`, `x-*`) | case preserved | `vulnerability:SIM-2026-0001`, `file:dev-01\|/opt/deploy/.env` |

Keys longer than 200 characters are cut to 200 and suffixed with `~` and a 16-character digest.
Composite keys used by the importers: files `<host>|<path>`; processes `<host>|<pid>|<start time>`
for `process.start` events with a PID (later events of the same PID on the same host reuse it),
`<host>|<pid>|<image name>` when no start was seen, `<host>|<name>` without a PID; secrets found by
Vault `<host>|<path>|<line>|<rule>`. A typed reference in user input is normalized the same way, so
`host:WS-02` finds `host:ws-02`.

Other identifiers:

| Entity | Form | Derived from |
|---|---|---|
| relationship | `rel:<24 hex>` | SHA-256 of (source ID, type, target ID): one relationship per triple |
| event | `event:<24 hex>` | SHA-256 of (the source file's SHA-256, or the source name for generated records; the record locator); a record's own `id` is kept when it already has this form, otherwise hashed |
| finding | `finding:<product>:<rule>:<12 hex>` | the product, the rule and a digest of the finding's subject |
| snapshot | `snapshot:<name in lower case>` | the snapshot name |
| evidence item | `ev-0001` (graph object `evidence:ev-0001`) | per-workspace counter |
| job, analysis | `job-12`, `analysis-3` | per-workspace counters (not typed IDs) |

## Object types

| Group | Types |
|---|---|
| Assets | `host`, `service`, `cloud_resource`, `container`, `network`, `project` (the asset types of Exposure and Blast) |
| Principals | `user`, `identity`, `group`, `role` (plus `permission` for traversal) |
| Identity and organization | `permission`, `organization` |
| Activity | `process`, `file`, `directory`, `session`, `connection` |
| Network and web | `ip`, `domain`, `url`, `port`, `certificate` |
| Credentials | `secret` (values are never stored: `metadata.redacted`, fingerprints) |
| Software | `package`, `dependency`, `vulnerability` |
| Governance | `policy` |
| Investigation | `event`, `alert`, `incident`, `evidence`, `finding`, `snapshot` |

`event`, `finding` and `snapshot` records live in their own tables but use the same `<type>:<key>`
scheme, so relationships and references can point to them. Input also accepts the aliases
`hostname`, `account` (identity), `ipaddress`, `ip_address`, `fqdn`, `cloudresource`, `vuln`, `cve`,
`proc`, `dir`, `cert` and `net`.

**Custom types.** Plugins and imports may use `x-<name>` types (`x-` followed by a lower-case letter
and 1-40 lower-case letters, digits, `_` or `-`, e.g. `x-badge`); the type is lower-cased, the key
keeps its case. Custom objects are stored, listed (`raf objects --type x-badge`), shown and drawn
like any other object, but no traversal rule, risk factor or Diff rule knows them, and they cannot be
used as the `TYPE` word of a scope (`raf graph x-badge NAME` is rejected; use the full ID).

## Common fields

| Field | Meaning |
|---|---|
| `id`, `type`, `name` | identity; `name` is the display name (the highest-confidence observation's name wins on merge) |
| `created_at`, `updated_at` | when R$F first stored / last changed the object |
| `first_seen`, `last_seen` | earliest and latest observation time (event time, or the record's own `first_seen`/`last_seen`) |
| `valid_from`, `valid_to` | validity interval; `valid_to` set means the object (or relationship) ended |
| `source` | the first named source that contributed it |
| `confidence`, `confidence_level` | 0..1; HIGH ≥ 0.8, MEDIUM ≥ 0.5, LOW below (computed) |
| `tags` | set of labels (`raven`, `forge`, `dependency`, ...); the tag `critical` implies critical criticality when `metadata.criticality` is absent |
| `metadata` | type-specific attributes (below) |
| `observations` | how many records observed it (mere references, such as the endpoints of a relationship record, count 0) |
| `synthetic` | generated data (demo, Range, Forge, labs); stays true only while every observation is synthetic |

**Merging.** Observations of the same ID merge deterministically: earliest `first_seen` /
`valid_from`, latest `last_seen` / `valid_to`, maximum confidence, union of tags, recursive metadata
merge in which newer scalar values win and the lists `aliases`, `sources`, `addresses`, `ports` and
`sans` are unioned. An ended object or relationship that is observed again after its `valid_to`
becomes active again.

**Confidence.** Inputs accept 0..1, percentages (1-100) and the words LOW (0.3), MEDIUM / MED (0.6),
HIGH (0.9), CONFIRMED / CERTAIN (1.0). Defaults: inventory object records 0.9, objects referenced by
events 0.8, relationships and events 0.8, relationship endpoints that are only referenced at most
0.5, incidents 1.0, imported findings 0.5. Relationships derived from an event take the event's
confidence or the rule's, whichever is lower.

**Metadata conventions** read by products:

| Key | On | Used by |
|---|---|---|
| `criticality` (`low`, `medium`, `high`, `critical`) | assets | Exposure, Blast, Diff, Oracle; Graph marks high/critical |
| `internet_facing` | hosts, services | Exposure (direct exposure), Diff |
| `privileged`, `wildcard` | roles, identities, permissions | IAM, Blast (privileged paths), Diff |
| `aliases` | any | extra names for reference resolution (`production`) |
| `disabled` | users, identities | cannot be taken over in propagation; set by `iam.user.disable` / `enable` events (with `state_changed_at`) |
| `mfa` | users, identities | Blast (`blast.mfa`), IAM (`privileged-without-mfa`) |
| `cvss`, `exploit_available` | vulnerabilities | vulnerability upgrade, Exposure, Diff |
| `role` (`workstation`, `laptop`, `desktop`) | hosts | Exposure entry points (also hosts a user `OWNS`) |
| `cidr`, `zone` | networks | Internet zones (`0.0.0.0/0`, `::/0`, zone `external` / `internet`, or `network:internet`) |
| `ip`, `os`, `owner`, `environment` | hosts | display, policy zones |
| `path`, `host` | files | display, Vault |
| `pid`, `image`, `command_line`, `host` | processes | Replay, Trace, display |

## Relationships

A relationship is first-class: `{id, relationship_type, source_object, target_object, first_seen,
last_seen, valid_from, valid_to, confidence, confidence_level, source, metadata, observations,
created_at, updated_at, synthetic, timestamp}`, where `timestamp` (computed) is `first_seen`, else
`valid_from`. Endpoints are universal IDs and may point to events, findings or evidence items.
Relationships derived from events record the producing event type in `metadata.via`.

| Group | Types |
|---|---|
| Identity and access | `LOGGED_INTO`, `MEMBER_OF`, `HAS_ROLE`, `HAS_PERMISSION`, `HAS_IDENTITY`, `CAN_ACCESS`, `CAN_ASSUME`, `ADMIN_OF`, `TRUSTS`, `OWNS`, `USES`, `AUTHENTICATES_AS` |
| Activity | `SPAWNED`, `STARTED`, `EXECUTED`, `CREATED`, `MODIFIED`, `DELETED`, `READ`, `CONNECTED_TO`, `RESOLVED`, `REQUESTED` |
| Infrastructure | `RESOLVES_TO`, `RUNS`, `LISTENS_ON`, `HAS_ADDRESS`, `CAN_REACH`, `DEPLOYS_TO`, `CONTAINS`, `CONTAINS_SECRET`, `PRESENTS`, `ISSUED_FOR` |
| Software supply chain | `DEPENDS_ON`, `DECLARES`, `AFFECTS` |
| Policy | `ALLOWS`, `DENIES`, `APPLIES_TO` |
| Investigation | `INVOLVES`, `PART_OF`, `SUPPORTS`, `DERIVED_FROM`, `RELATED_TO` |

Typical endpoints: `user LOGGED_INTO host`; `user|identity|group MEMBER_OF group`, `host MEMBER_OF
network`; `principal HAS_ROLE role`; `role HAS_PERMISSION permission`; `user HAS_IDENTITY identity`;
`principal|role CAN_ACCESS resource`; `host USES identity` (credentials present on the host); `secret
AUTHENTICATES_AS identity`; `file CONTAINS_SECRET secret`; `host CONTAINS file`; `environment
CONTAINS compute`; `host RUNS service|process`; `service LISTENS_ON port`; `host|port HAS_ADDRESS
ip`; `network CAN_REACH network|host`; `service DEPLOYS_TO environment`; `domain RESOLVES_TO ip`;
`port PRESENTS certificate`, `certificate ISSUED_FOR domain`; `domain PART_OF domain`; `project
DECLARES dependency`, `package DEPENDS_ON package`; `vulnerability AFFECTS asset|package`; `policy
APPLIES_TO object`; `evidence RELATED_TO incident`, `evidence DERIVED_FROM evidence`. `INVOLVES`
appears only as the virtual incident edge of Graph views; `ALLOWS`, `DENIES` and `SUPPORTS` are
defined (Diff classifies `ALLOWS` / `DENIES` as network changes) but no built-in importer produces
them. Any other `UPPER_SNAKE_CASE` type (2-49 characters) is accepted for plugins and imports
(`HOLDS_BADGE`); unknown types are stored and drawn but not traversed.

### Relationships derived from events

The relationship builder adds relationships for these event types (`≤ 0.9`: the relationship's
confidence is at most 0.9):

| Event type | Relationships | Failed event (`outcome` failure) |
|---|---|---|
| `auth.login` | actor `LOGGED_INTO` target (`method`, `protocol`, `logon_type`); `src_ip CONNECTED_TO` target (≤ 0.9) when the target is a host or IP | nothing |
| `auth.privilege` as `root`, `administrator`, `system`, `admin` or `nt authority\system` on a host | actor `ADMIN_OF` host (≤ 0.9) | nothing |
| `process.start` | parent `SPAWNED` process; a user or identity actor `STARTED` process; process `EXECUTED` image file; host `RUNS` process | nothing (the process did not start) |
| `process.end` | ends host `RUNS` process | same |
| `file.create`, `file.modify`, `file.delete`, `file.read` | process (else actor) `CREATED` / `MODIFIED` / `DELETED` / `READ` file; host `CONTAINS` file (≤ 0.9; ended by `file.delete`) | nothing |
| `network.connection`, `network.flow` | actor `CONNECTED_TO` target (not when `attributes.blocked` is true); host `HAS_ADDRESS src_ip` (≤ 0.8) | only `HAS_ADDRESS` |
| `dns.query` | actor `RESOLVED` domain; domain `RESOLVES_TO` each answer (≤ 0.95) | same |
| `http.request` | actor `REQUESTED` URL; domain `RESOLVES_TO dst_ip` (≤ 0.8) | same |
| `tls.handshake` | actor `CONNECTED_TO` target | nothing |
| `iam.role.assign`, `iam.role.remove` | target `HAS_ROLE` role (`granted_by`; ended by remove) | nothing (a failed assignment grants nothing, a failed removal ends nothing) |
| `iam.group.add`, `iam.group.remove` | target `MEMBER_OF` group (`changed_by`; ended by remove) | nothing (a failed addition adds nothing, a failed removal ends nothing) |
| `iam.permission.grant`, `iam.permission.revoke` | target `CAN_ACCESS` resource (`granted_by`, `access`; ended by revoke) | nothing |
| `iam.user.disable`, `iam.user.enable` | sets `metadata.disabled` and `state_changed_at` on the target | nothing |
| `service.access` | actor `CAN_ACCESS` service (≤ 0.8, `observed`) | nothing |
| `cloud.api` | actor `CAN_ASSUME` role (target is a role), else principal `CAN_ACCESS` resource (≤ 0.7, `observed`, `api`) | nothing |
| `policy.change` | actor `MODIFIED` policy | nothing |

Removal events *end* relationships (`valid_to` = event time) instead of deleting them, so history
stays queryable with `--at` and Replay.

## Traversal semantics

Blast, IAM paths, Exposure, Ghost and Oracle propagate over the same rules
(`raf.core.objects.semantics`, `raf.core.graph.propagation`). A hop has a **mode** and a **factor**:

* `control` - acting with the privileges of, or owning, the next object;
* `reach` - network reachability only: it never grants control by itself and continues only through
  network rules (and, from a reached host, to the services it runs, still as reach);
* `trust` - identities of one realm are accepted in another.

The confidence of a path is the product over its hops of `factor × (0.5 + 0.5 × relationship
confidence)`; paths below the caller's minimum confidence are pruned.

| Relationship (endpoint condition) | Forward (source → target) | Reverse (target → source) |
|---|---|---|
| `LOGGED_INTO` | control 0.8: the credentials work on the target | control 0.5: a session on the host can be captured |
| `ADMIN_OF` | control 1.0 | - |
| `MEMBER_OF` (source is a user, identity, group, role or permission) | control 1.0: inherits the group's access | - |
| `MEMBER_OF` (target is a network) | reach 1.0 | reach 1.0 |
| `HAS_ROLE`, `HAS_PERMISSION`, `CAN_ASSUME`, `HAS_IDENTITY` | control 1.0 | - |
| `CAN_ACCESS` | control 0.9 | - |
| `USES` (target is an identity or user) | control 0.8: the credentials are present on the source | - |
| `RUNS` (target is a service or container) | control 0.9; from a reach state: reach 1.0 | control 0.4: code execution in the service can extend to its host |
| `RUNS` (target is a process) | control 0.9 | - |
| `DEPLOYS_TO` | control 0.9 | - |
| `CONTAINS` (source is a cloud resource or organization, or target is a host, service, container or cloud resource) | control 0.9 | - |
| `CONTAINS` (host or directory → file or directory) | control 1.0 | - |
| `CONTAINS_SECRET` | control 0.9 | - |
| `AUTHENTICATES_AS` | control 1.0 | - |
| `OWNS` (source is a principal) | control 0.6 | - |
| `TRUSTS` | - | trust 0.8: the target's identities are accepted by the source |
| `CAN_REACH` | reach 0.9 | - |
| `CONNECTED_TO` (host or IP → host or IP) | reach 0.6 | - |
| `HAS_ADDRESS` | reach 1.0 | reach 1.0 |
| every other type | - | - |

Further rules:

* **Vulnerability upgrade.** An object reached in `reach` mode that is affected (`AFFECTS`) by a
  vulnerability with `cvss` ≥ 7 or `exploit_available` becomes controllable with factor
  0.6 × min(score, 10) / 10, where the score is the CVSS (at least 7 when an exploit is available).
  The hop names the vulnerability.
* **Disabled accounts.** A user or identity with `metadata.disabled` cannot be entered in `control`
  mode.
* **Search.** Best-first search keeping, per (object, mode), the Pareto front of (confidence,
  depth); ties are broken by depth, then object ID, so results are deterministic. A reached object's
  final mode is the best of control/trust over reach.
* **Time.** With `--at`, only relationships valid at that time are traversed (see
  [Temporal model](#temporal-model)).

| Product | Start | Depth / minimum confidence | Vulnerability upgrade |
|---|---|---|---|
| Blast (`raf blast`) | the subject, control | `blast.max_depth` (8) / `blast.min_confidence` (0.2), per command | yes |
| Exposure, network | each Internet zone and workstation, reach | `blast.max_depth` / 0.05 | no (yes for the critical-path metric) |
| Exposure, control | each user and identity (up to 300), control | `blast.max_depth` / 0.2 | no |
| IAM effective access (`raf iam show`) | the principal, on grant relationships only | per command / 0.2 | no |
| IAM paths (`raf iam path`) | the source, on grants plus `USES`, `LOGGED_INTO`, `CONTAINS_SECRET`, `AUTHENTICATES_AS`, `TRUSTS`, `RUNS`, `OWNS` | `--max-depth` (10) / 0.01 | no |
| Oracle | the subject | blast settings (paths between two objects: 12 / 0.01) | yes |

Ghost runs the same Exposure model on its what-if states. Graph and Trace do **not** use these
semantics: Graph shows relationships as stored, Trace follows events. The factor tables for the
resulting scores are in [risk-model.md](risk-model.md).

## Events

An event is one normalized record of something that happened:

| Field | Meaning |
|---|---|
| `id` | `event:<24 hex>` (see [Identifiers](#identifiers)) |
| `timestamp` | UTC; naive input times use `ingest.default_timezone` or `--timezone` |
| `event_type`, `category`, `action` | `category.action[.detail]` in lower case (at most six segments, 128 characters); `category` is the first segment; `action` the last segment unless given |
| `outcome` | `success`, `failure`, `unknown`, or the lower-cased value as imported (`ok`, `allowed`, `true` → success; `failed`, `denied`, `blocked`, `false`, `error` → failure) |
| `actor`, `target` | object IDs |
| `objects` | every involved object with its role (below) |
| `severity` | INFO, LOW, MEDIUM, HIGH, CRITICAL (aliases: `warning` → MEDIUM, `error` → HIGH, `emergency` → CRITICAL, ...; numbers map like CVSS: ≥ 9 CRITICAL, ≥ 7 HIGH, ≥ 4 MEDIUM, > 0 LOW) |
| `confidence` | 0..1 (default 0.8) |
| `attributes` | the remaining structured fields (`src_ip`, `dst_port`, `command_line`, `bytes_out`, ...) |
| `message` | free text (at most 4,000 characters) |
| `source`, `parser`, `record` | source name, parser label (`syslog-sshd/1.0`, `jsonl/1.0+ecs/1.0`), record locator (`line 12`, `row 4`, `record 753`) |
| `raw_reference`, `raw` | `<source>#<locator>` or `evidence:<item>#<locator>`; a bounded excerpt of the raw record (`ingest.store_raw`, `ingest.raw_max_bytes` = 2048) |
| `relationships` | IDs of the relationships the event produced or carried |
| `incidents` | incidents the event is linked to |
| `synthetic`, `job_id`, `ingested_at` | generated data flag, the import job, the import time |

**Roles** in `objects`: `actor`, `target`, `host`, `src_ip`, `dst_ip`, `ip`, `domain`, `answer`,
`url`, `file`, `image`, `parent`, `process`, `role`, `group`, `resource`, `policy`, `service`, and any
role named in a record's `objects` list (default `related`). The native importer turns these
attributes into involved objects: `src_ip`, `dst_ip`, `ip`; `domain` / `query` / `sni`; `answers` /
`resolved_ips`; `url`; `file` / `file_path` / `path`; for `process.start` the `image` and the parent
(`parent_pid`, `parent_image`); for `file.*` the `process`; `role`, `group`, `resource`
(`resource_type`), `policy`, `service`.

**Taxonomy.** Known types define the default object type of a bare actor or target name (an actor
`svc-deploy` is resolved against existing objects of compatible types first):

| Event type | Actor | Target | Meaning |
|---|---|---|---|
| `auth.login`, `auth.failure`, `auth.logout`, `auth.mfa`, `auth.privilege` | user | host | logon, failed attempt, logoff, MFA challenge, elevation (sudo, su, runas) |
| `process.start`, `process.end` | user | process | process creation and termination |
| `file.create`, `file.modify`, `file.delete`, `file.read` | process | file | file activity |
| `network.connection` | host | ip | connection attempt |
| `network.flow` | ip | ip | flow summary |
| `dns.query` | host | domain | DNS resolution |
| `http.request` | host | url | HTTP request |
| `tls.handshake` | ip | domain | TLS handshake (server name) |
| `iam.role.assign`, `iam.role.remove`, `iam.group.add`, `iam.group.remove`, `iam.permission.grant`, `iam.permission.revoke`, `iam.user.create`, `iam.user.disable`, `iam.user.enable` | identity | user | identity administration |
| `iam.credential.create` | identity | identity | credential or key created |
| `service.access` | user | service | access to an application |
| `policy.change` | identity | policy | policy modified |
| `cloud.api` | identity | cloud_resource | cloud control-plane call |
| `alert` (and `alert.*`) | host | host | detection from a security tool |
| `evidence.collected` | user | evidence | evidence acquisition |
| `log.message` | host | host | unstructured log line |

Categories: `auth`, `process`, `file`, `network`, `dns`, `http`, `tls`, `iam`, `service`, `policy`,
`cloud`, `alert`, `evidence`, `log`. Unknown types are accepted (their category is their first
segment; a bare actor is then a user and a bare target a host).

## Findings

A finding is a conclusion of a product:

| Field | Meaning |
|---|---|
| `id` | `finding:<product>:<rule>:<digest>`: re-running an analysis updates the same finding |
| `title`, `description`, `recommendation` | text |
| `severity` | the impact if the finding is true (INFO .. CRITICAL) |
| `confidence`, `confidence_level` | how likely it is true; independent of severity (Vault: a private key is CRITICAL, a high-entropy string LOW with confidence 0.3) |
| `product`, `rule_id` | who produced it and by which rule |
| `status` | `OPEN`, `ACKNOWLEDGED`, `RESOLVED`, `FALSE_POSITIVE`, `SUPPRESSED` |
| `affected_objects` | object IDs (indexed: `raf findings --object REF`) |
| `evidence` | `[{kind, id, note}]`, kind `object`, `relationship`, `event`, `evidence`, `finding`, `policy`, `rule` or `external` |
| `explanation` | the factors behind it, e.g. `{factor, label, sign, points}` for scored findings ([risk-model.md](risk-model.md)) |
| `created_at`, `updated_at`, `tags`, `metadata` | `metadata.status_history` records status changes |

**Lifecycle.**

* Analysts set statuses with `raf finding ack | resolve | false-positive | reopen ID [--note]` or
  `PATCH /api/v1/findings/{id}` (which also accepts `SUPPRESSED`). Any status can follow any other;
  each change appends `{from, to, note, at}` to `metadata.status_history` (the last 50 are kept;
  `at` is ISO 8601 UTC, `2026-10-07T13:48:43.752214Z`; entries written by earlier versions end in
  `+00:00` and are kept as they are) and writes a `finding.status` audit entry.
* When an analysis runs again, `ACKNOWLEDGED`, `FALSE_POSITIVE` and `SUPPRESSED` are kept (analyst
  decisions survive re-analysis). A `RESOLVED` finding that the analysis produces again becomes
  `OPEN` with the history entry *"reappeared in a new analysis"*. `OPEN` findings of the same product
  and rules that the run no longer produces are set to `RESOLVED` (only within the run's scope for
  partial runs) with the history entry *"resolved: not found by re-analysis"*. These automatic
  entries carry `automatic: true`.
* `raf findings` lists `OPEN` and `ACKNOWLEDGED` findings unless `--status` says otherwise.

Findings can also be imported (`{"kind": "finding", "title", "severity", "confidence", "affected",
...}`): product `import`, rule `imported` by default, confidence 0.5, an `external` evidence
reference to the source record.

## Incidents

An incident is an object of type `incident` (`incident:inc-001`) whose metadata holds `title`,
`status` (default `open`), `severity` (default MEDIUM), `description`, `start` and `end`, plus an
index of the events linked to it. Events are linked by the `incident` / `incidents` field of an
event record, by `--incident NAME` on `raf import` / `raf analyze` (every imported event), by
incident records (`{"kind": "incident", "name", ..., "events": [event IDs]}`), by evidence cases
(events inside the incident's time window only) and by Forge scenarios (`SIM-<SCENARIO>-<SEED>`).
The incident view (`raf incidents`, `/api/v1/incidents`) adds `event_count`, and `start` / `end`
fall back to the first and last linked event. Graph, Timeline, Lens and Replay accept an incident as
scope; an evidence case named like an incident resolves to it.

## Provenance

Every object and relationship records where each observation came from, so any fact can answer
"where did this come from?", analyses and jobs can be scoped exactly, and generated data can be
removed precisely (Range `reset` deletes an object only when all of its provenance comes from the
range). A provenance record holds `subject_id`, `subject_kind` (`object`, `relationship`), `source`
(name), `source_sha256` (hash of the input file), `record` (locator), `parser` (label), `event_id`
(when derived from an event), `observed_at`, `job_id`, `evidence_id` (when the input is an evidence
item), `note` and `recorded_at`.

* Inventory records (objects without an event) get a record without `event_id`; objects involved in
  an event and relationships derived from it get one with the event.
* At most `ingest.provenance_cap` (200) records are kept per subject per import job; further
  observations still count in `observations`.
* Events keep `source`, `parser`, `record`, `raw_reference`, the raw excerpt and `job_id`; evidence
  imports point `raw_reference` at the evidence item, whose stored copy is hashed and under chain of
  custody ([Evidence](products/evidence.md)).
* Rejected records are not dropped silently: each is quarantined with its reason and a raw excerpt
  (`raf import report JOB`).
* Findings carry their own `evidence` references and `explanation` instead of provenance rows.

`raf show OBJECT` prints the first records (`Provenance (10 of N)`); the API serves them at
`GET /api/v1/objects/{ref}/provenance`. Code that writes objects outside the ingestion pipeline is
expected to record provenance too ([plugin-development.md](plugin-development.md#provenance)).

## Snapshots

A snapshot freezes the objects, relationships and findings of a state as content hashes, with
bodies shared between snapshots; sources are the workspace (`current`) or a Ghost model
(`ghost:<model>`). What counts as content, the state hash and the comparison rules are described in
[Diff](products/diff.md#snapshots).

## Temporal model

* `first_seen` / `last_seen` bound the observations; `valid_from` / `valid_to` bound validity.
  "Current" means `valid_to` is empty.
* A relationship is valid at time T when its start (`valid_from`, else `first_seen`) is empty or not
  after T and its `valid_to` is empty or after T. `raf graph --at`, `raf blast --at` and the initial
  state of Replay use this rule; objects themselves are not filtered by time.
* Removal events end relationships at the event time; a later observation re-activates them.
* Replay orders events by (timestamp, event ID) and hashes states canonically, so time-based views
  are reproducible ([Replay](products/replay.md)).

## Risk model

Scores are explainable sums of named factors (`raf-risk/1.0`): levels LOW (0-24), MEDIUM (25-49),
HIGH (50-74), CRITICAL (75-100); each factor has a rule, a label, a sign, points and evidence IDs. The
blast-radius and asset-exposure factor tables, the IAM and policy finding rules and the traversal
summary are in [risk-model.md](risk-model.md).
