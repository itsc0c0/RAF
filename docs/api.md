# R$F HTTP API (`/api/v1`)

The API exposes the same application services as the CLI (the CLI never contains
business logic the API lacks). OpenAPI is generated at `/api/v1/openapi.json`;
interactive docs at `/api/docs`.

* **Workspace scoping** — every route operates on the current workspace unless
  `?workspace=<name>` or the `X-RAF-Workspace` header selects another.
* **Errors** — always `{"error": {"code", "message", "reason?", "hint?", "suggestions?", "details?"}}`
  with an HTTP status (404 not found, 409 conflict/ambiguous, 422 invalid input, 403 forbidden host,
  401 unauthorized, 503 dependency unavailable, 500 internal).
  A product's routes answer 503 (`raf.product_disabled`) while the product is disabled or otherwise
  unavailable, from the next request on, and serve again once it is enabled.
* **Security** — `raf serve` binds to 127.0.0.1. Requests with a Host header other than loopback
  names are rejected (DNS-rebinding defense). Binding to another address requires a bearer token
  (`Authorization: Bearer <token>`), generated or taken from `RAF_API_TOKEN`.
* **Pagination** — collections use `limit`/`offset` (`total` included) except events, which use
  keyset cursors (`next_cursor`).
* **References** — `{ref}` path/query parameters accept everything the CLI accepts: full IDs
  (`host:ws-04`), names (`WS-04`), aliases (`production`), incidents (`INC-001`), analyses
  (`analysis-3`). Path parameters use the `:path` converter, so IDs containing `/` work.
* Timestamps are ISO-8601 UTC (`2026-10-06T22:52:11Z`).

## Common shapes

```jsonc
// SecurityObject
{"id": "host:ws-04", "type": "host", "name": "WS-04", "created_at": "...", "updated_at": "...",
 "first_seen": "...|null", "last_seen": "...|null", "valid_from": null, "valid_to": null,
 "source": "raven-events.jsonl", "confidence": 0.9, "confidence_level": "HIGH",
 "tags": ["raven"], "metadata": {"criticality": "high", "...": "..."}, "observations": 3, "synthetic": false}

// Relationship
{"id": "rel:…", "relationship_type": "LOGGED_INTO", "source_object": "user:alice", "target_object": "host:ws-01",
 "timestamp": "...", "first_seen": "...", "last_seen": "...", "valid_from": null, "valid_to": null,
 "confidence": 0.8, "confidence_level": "HIGH", "source": "...", "metadata": {}, "observations": 4, ...}

// Event
{"id": "event:…", "timestamp": "...", "event_type": "auth.login", "category": "auth", "action": "login",
 "outcome": "success", "actor": "user:bob", "target": "host:vpn-01",
 "objects": [{"object_id": "ip:203.0.113.45", "role": "src_ip"}], "source": "...", "parser": "jsonl/1.0",
 "record": "line 750", "raw_reference": "...", "raw": "...", "severity": "MEDIUM", "confidence": 0.8,
 "attributes": {}, "relationships": ["rel:…"], "message": null, "synthetic": true, "incidents": ["incident:inc-001"]}

// Finding
{"id": "finding:…", "title": "...", "description": "...", "severity": "HIGH", "confidence": 0.6,
 "confidence_level": "MEDIUM", "product": "iam", "rule_id": "...", "status": "OPEN",
 "affected_objects": ["identity:old-admin"], "evidence": [{"kind": "object", "id": "...", "note": "..."}],
 "recommendation": "...", "explanation": [{"label": "...", "sign": "+", "points": 20}], ...}

// GraphNode / GraphEdge / Subgraph
{"roots": ["user:alice"], "depth": 2, "truncated": false, "at": null,
 "nodes": [{"id", "type", "name", "depth", "criticality", "tags", "synthetic", "first_seen", "last_seen",
            "metadata", "missing"}],
 "edges": [{"id", "type", "source", "target", "confidence", "first_seen", "last_seen", "valid_to",
            "observations", "metadata"}]}   // incident views add virtual INVOLVES edges (metadata.virtual=true)

// Risk factor (explainable scoring; see docs/risk-model.md)
{"label": "internet-facing", "sign": "+", "points": 20, "evidence": ["host:vpn-01"]}
```

## Platform

| Method | Path | Description |
|---|---|---|
| GET | `/health` | liveness (no auth) |
| GET | `/version` | version identifiers |
| GET | `/status` | workspace, counts, products, open findings by severity, oracle provider |
| GET | `/config` | effective configuration with origins (secrets shown as set/not set) |
| GET | `/audit?limit=` | audit entries + chain verification |
| GET | `/products` | `{"items": [ProductInfo]}` — name, display_name, status (`STABLE`…`DISABLED`), maturity, description, category, depends_on, commands, enabled, available, unavailable_reason, ui |
| GET | `/products/{name}` | one product + dependents |
| POST | `/products/{name}/enable` / `/disable` | toggle |
| GET/POST | `/workspaces` | list (`items`, `current`) / create `{name, description}` |
| POST | `/workspaces/{name}/use` | make current |

## Data

| Method | Path | Description |
|---|---|---|
| GET | `/objects?type=&q=&tag=&limit=&offset=` | `{items, total, limit, offset}` |
| GET | `/objects/types` | counts by object type and relationship type |
| GET | `/objects/{ref}` | `{object, notes, activity, relationship_count, findings, pivots}`; 422 for event, finding and snapshot IDs (the error names the route that describes them) |
| GET | `/objects/{ref}/relationships?direction=&at=` | `{object_id, items, total}` |
| GET | `/objects/{ref}/provenance` | `{object_id, items, total}` |
| GET | `/objects/{ref}/pivots` | `{items: [{key, product, label, command, view}]}` — `view` is a web route; 422 for event, finding and snapshot IDs |
| GET | `/relationships?type=&source=&target=` | relationships |
| GET | `/search?q=` | `{objects, incidents, findings}` |
| GET | `/events?start=&end=&type=&category=&object=&incident=&severity=&q=&actor=&job=&cursor=&limit=&descending=` | `{items, next_cursor, total}` |
| GET | `/events/{id}` | one event |
| GET | `/findings?product=&severity=&status=&object=&q=&limit=&offset=` | `{items, total}` |
| GET/PATCH | `/findings/{id}` | read / `{status, note}` (OPEN, ACKNOWLEDGED, RESOLVED, FALSE_POSITIVE, SUPPRESSED) |
| GET | `/incidents`, `/incidents/{ref}` | incidents with window and event counts |
| GET | `/jobs?status=`, `/jobs/{id}`; POST `/jobs/{id}/cancel` | job status/progress/result |
| GET/POST | `/snapshots` | list / create `{name, source: "current"|"ghost:<model>", description}` |
| GET/DELETE | `/snapshots/{name}` | read / delete |
| POST | `/analyze` (multipart `file`; form `incident?`, `correlate?`, `synthetic?`) | upload and analyze (see [analyze.md](analyze.md)); returns `{id, input, input_name, input_sha256, detected_type, detected_label, detection, status, steps: [{name, product, status, detail, duration_ms, stats}], stats, suggestions, job_id, job_ids, incidents, created_at, duration_ms}`; no route accepts a server path, and server paths never appear in responses |
| GET | `/analyses?limit=` | `{items: [Analysis], total}`, newest first |
| GET | `/analyses/{id}` | one analysis, in the shape `POST /analyze` returns (`detection` and `duration_ms` are null for analyses recorded before 0.1.0 stored them); server paths are never returned |

## Investigation products

| Method | Path | Description |
|---|---|---|
| GET | `/graph/view?ref=&depth=&rel=&type=&at=&max_nodes=&direction=` | Subgraph + `scope` (`ref` omitted or `workspace` = overview) |
| GET | `/graph/neighbors?ref=&direction=&rel=&at=&limit=` | depth-1 Subgraph (UI "expand") |
| GET | `/graph/path?source=&target=&directed=&rel=&at=&max_depth=` | `{found, length, hops: [{source, source_name, target, target_name, relationship: GraphEdge, forward}]}` |
| GET | `/graph/export?ref=&format=graphml|dot|csv|json|cytoscape` | text |
| GET | `/graph/stats` | counts and most connected objects |
| GET | `/timeline?ref=&start=&end=&type=&category=&severity=&q=&filter=&group_by=&cursor=&limit=&descending=&buckets=` | `{scope, filters, total, first, last, items, names, next_cursor, group_by, groups: [{key, count}], histogram: [{start, count}]}` |
| GET | `/timeline/export?ref=&format=csv|json|jsonl|raf&...` | file download |
| GET | `/trace/{ref}?direction=both|back|forward&depth=` | `{subject, nodes, backward: [TraceLink], forward: [TraceLink], chain: [TraceLink], notes}`; TraceLink = `{cause, effect, relation, kind: observed|correlated, confidence, timestamp, event_id, explanation, provenance, direction, step, parent_step, corroborated_by}` |
| GET | `/replay/{ref}?include_context=&start=&end=` | `{scope, title, start, end, objects: {id: {name, type, criticality}}, relationships: {id: {type, source, target}}, initial_objects, initial_relationships, steps: [ReplayStep], checkpoints, final_state_hash, notes}`; ReplayStep = `{index, timestamp, event_id, event_type, severity, summary, actor, target, added_objects, added_relationships, removed_relationships, sessions_opened, sessions_closed, processes_started, processes_ended, flows, files, identity_changes, alerts}`. The web player applies the deltas client-side. |
| GET | `/replay/{ref}/state?at=` | `{at, step_index, objects, relationships, sessions, processes, recent_flows, files, identity_changes, alerts, state_hash}` |
| GET | `/replay/{ref}/window?start=&end=` | changes in a window |
| GET | `/diff?a=&b=&category=&limit=` | `{a, b, summary: {category: {added, removed, changed}}, importance: {HIGH, MEDIUM, LOW}, totals, changes: [{category, change, item_kind, item_id, label, importance, reason, details}]}` |

## Exposure products

| Method | Path | Description |
|---|---|---|
| GET | `/blast/{ref}?max_depth=&min_confidence=` | `{target: {id, name, type}, reachable_assets, critical_assets, privileged_paths, max_depth, direct: [Reach], indirect: [Reach], identity_propagation: [ids], network_propagation: [ids], trust_propagation: [ids], risk: {level, score, factors: [RiskFactor]}, primary_path: [Hop]}`; Reach = `{id, name, type, depth, confidence, mode: control|reach|trust, criticality}`; Hop = `{source, source_name, target, target_name, relationship_type, relationship_id, why, confidence}` |
| GET | `/exposure?limit=&min_level=` | `{items: [{object: {id, name, type, criticality}, score, level, factors: [RiskFactor], entry_points, vulnerabilities: [{id, cvss}]}]}` |
| GET | `/exposure/{ref}` | one explained assessment (+ `internet`, `controllers`, `stepping_stone_to`, `secrets`) |
| POST | `/exposure/analyze` | recompute and record HIGH/CRITICAL findings |
| GET | `/iam/analyze` | dry run: `{summary: {principals, privileged_principals, findings, by_rule, resolved, reference_time}, findings: [Finding]}` |
| POST | `/iam/analyze?persist=true` | same shape; records findings |
| GET | `/iam/principals/{ref}` | effective access `{principal, privileged, groups, roles, identities, resources, last_activity, findings}` |
| GET | `/iam/path?source=&target=&max_depth=&limit=` | `{source, target, paths: [{confidence, hops: [Hop]}]}` |
| GET | `/policy/policies` | `{items: [Policy + {object_id, rule_count, digest}]}` (rules included) |
| GET | `/policy/policies/{id}` | one normalized policy |
| POST | `/policy/evaluate` `{subject?|principal?, source?, target, action?, port?, protocol?, ports?, sources?}` | `{decision: allow|deny|not-evaluated, reason, parts: [{part: network|identity, policy, decision, allowed_ports, decisions: [{policy, rule, effect, ports, actions, summary}], preempted, explanation}], indirect: [{pivot, legs, summary}], notes}` |
| POST | `/policy/analyze?persist=` | `{policies, findings, by_rule, warnings}` |
| POST | `/policy/check` `{document, format: json|yaml|csv, principal?}` | normalize + analyze without storing: `{set: {name, format, revision, source, policies, warnings}, analysis: {policies, findings, by_rule, warnings, workspace_aware}}` |
| GET | `/policy/diff?before=&after=current` | revision diff between workspace states (current, snapshots): `{before, after, policies_added, policies_removed, defaults_changed: [{policy, before, after}], changes: [{policy, rule, change: added|removed|modified|moved, impact: access-expanded|access-reduced|changed, fields, before, after}], findings_introduced, findings_resolved, access_expanded}` (`access_expanded` counts the access-expanding rule changes) |

## Synthetic environments

| Method | Path | Description |
|---|---|---|
| GET | `/ghost/models` | `{items: [{name, base_snapshot, base_label, parent, ops_count, created_at, updated_at, description}]}` |
| POST | `/ghost/models` `{name, base: "current"|"<snapshot>", description?}` | 201: create a model (a frozen base snapshot) |
| POST | `/ghost/models/{name}/clone` `{name}` | 201: clone |
| GET | `/ghost/models/{name}` | model with operations log (each op: `{op, arg, summary, explanation, effects, applied_at}`) |
| POST | `/ghost/models/{name}/ops` `{op, arg}` | apply a what-if operation -> `{model, applied}` |
| POST | `/ghost/models/{name}/undo` | remove the last operation |
| GET | `/ghost/models/{name}/simulate?limit=` | `{summary: {label, metrics, levels, user_control}, items: [AssetExposure]}` |
| DELETE | `/ghost/models/{name}` | delete (and its base snapshot when unused) |
| GET | `/ghost/operations` | supported operations |
| GET | `/ghost/compare?a=&b=` | `{a, b, delta, assets: [{id, name, before, after}], users: [{id, name, before, after, lost, gained}], relationships_removed, relationships_added, a_metrics, b_metrics}`; Metrics = `{attack_paths, critical_paths, reachable_assets, entry_points, exposed_critical_assets}`; `a`/`b` may be `current`, a model or a snapshot |
| GET | `/range/presets` | presets with their configuration |
| GET | `/range/ranges` | `{items: [RangeState]}`; RangeState = `{name, preset, seed, config, status, start, clock, periods, jobs, counts}` |
| POST | `/range/ranges` `{name, preset?, seed?, config?, start?}` | create (inventory ingested) -> `{state, job, report}` |
| GET | `/range/ranges/{name}` | `{state, live: {objects, relationships, events}, organization}` |
| POST | `/range/ranges/{name}/start|tick` `{hours}` | generate activity for the next period -> `{state, job, report, window}` |
| POST | `/range/ranges/{name}/stop|reset` | lifecycle |
| DELETE | `/range/ranges/{name}` | destroy (removes only what the range wrote) |
| GET | `/forge/catalog` | generators and scenarios |
| POST | `/forge/generate` `{kind, count<=100000, seed, start?, hours, noise, population}` | `{kind, seed, population, window, records, job, report, sample}` |
| POST | `/forge/scenario` `{name, seed, start?, population}` | same + `incident`, `subject` |
| GET | `/lab/status?backend=` | `{backend, available, reason, version}` |
| GET | `/lab/labs` | `{items: [Lab], total, invalid?}`; Lab = `{name, state, live, image, network, allow_outbound, mounts: [{source, target, read_only}], memory, cpus, pids_limit, user, root, backend, container, container_id, description, created_at, updated_at, state_at, note?}` |
| POST | `/lab/labs` `{name, image?, mounts?: [absolute paths], allow_outbound?, memory?, cpus?, root?, description?, backend?}` | 201 + Lab with `container_args` (no container yet; unknown fields rejected) |
| GET | `/lab/labs/{name}` | Lab with live state and `container_args` |
| POST | `/lab/labs/{name}/start`, `/lab/labs/{name}/stop` | Lab + `{changed, created}`; 503 when no container backend is available |
| DELETE | `/lab/labs/{name}?forget=` | `{name, destroyed, container, container_removed, note?}` — there is deliberately no exec or shell route |

## R$F OS screens

Read-only routes behind `raf tui` (the `raf-os` terminal panel); see [tui.md](tui.md) for the block
protocol. Ghost experiments shown here run in an unsaved in-memory model.

| Method | Path | Description |
|---|---|---|
| GET | `/tui/pages` | `{system, stats, focus: {incident, incident_id, subject, subject_id, target, target_id}, pages: [{id, title, param: {name, label, default}\|null}]}` |
| GET | `/tui/screen/{page}?ref=` (`?question=` for `oracle`) | a screen document `{page, title, subtitle, param, blocks, notes}`; 404 for an unknown page or reference, 503 when the page's product is disabled, 422 when a parameter exceeds 500 characters |
| GET | `/tui/inspect?ref=` | an object, relationship (`rel:…`), event (`event:…`) or finding (`finding:…`) as a screen document |

## Specialized analysis and AI

| Method | Path | Description |
|---|---|---|
| GET | `/evidence/cases`; POST `{name, title?}` | cases |
| GET | `/evidence/cases/{case}` | case + items |
| GET | `/evidence/items/{id}` | item metadata + custody chain |
| POST | `/evidence/cases/{case}/verify` | `{verified, items: [{id, ok, expected, actual}]}` |
| GET | `/lens/query?ref=&filter=&group_by=&buckets=&limit=` | `{scope, total, items, groups, histogram, involved: [{type, count}], top_objects: [...]}` |
| POST | `/oracle/ask` `{question}` (unknown fields rejected) | `{question, answer, provider, mode: builtin|model|builtin-fallback, model, intent, entities, citations: [{id, label, type}], invalid_references: [ids], facts: [{key, kind, text, refs, source, untrusted}], suggestions: [commands], warnings, generated_at, notice}`; 503 when Oracle is disabled |
| GET | `/oracle/status` | `{provider, enabled, ready, mode, detail, max_facts, tools, stores_answers}` + model settings; never the API key |
| POST | `/protocol/inspect` (multipart `file`, `?protocol=&host=&port=&flow=&limit=`) | capture summary + `upload` id (uploads are size-checked, verified as captures and addressed only by id) |
| GET | `/protocol/uploads?limit=` | earlier uploads of the workspace, newest first: `{items: [{id, name, size, sha256, uploaded_at}], total}`; `limit` 1–1000 (default 100), `total` counts every complete upload; entries with a missing, unreadable or inconsistent record are skipped; never a server path |
| GET | `/protocol/inspect?upload=&...` | re-inspect a stored upload with filters |
| GET | `/protocol/packet?upload=&n=` | one packet: layered fields with explanations (`file.sha256` is the upload's) |
| GET | `/protocol/flows?upload=&sort=id|bytes|packets|duration&limit=` | flow table with client/server inference and Community ID |
| GET | `/vault/findings?status=&limit=` | secret findings (values always redacted) |
| GET | `/vault/secrets` | discovered secret objects (redacted, fingerprinted) |
| GET | `/vault/rules` | detection rules with severity and confidence |
| GET | `/dependency/projects` | scanned projects |
| GET | `/dependency/projects/{ref}/graph` | dependency tree of a project |
| GET | `/dependency/vulnerable?include_unused=` | `{items: [{package, basis, confidence, advisories: [{id, object_id, severity, cvss, fixed, reason, basis, constraint, confidence, …}], projects}], total}`; `basis` `exact` (an installed version is affected, 0.9) comes first, then `constraint` (only a declared range admits affected versions, 0.5; `package` is the declared dependency) |
| GET | `/dependency/advisories` | imported (OSV) advisories (`object_id` is the vulnerability object) |
| GET | `/surface/summary?at=&expiring_days=`, `/surface/assets?kind=&scope=in\|out\|all&references=&limit=&offset=`, `/surface/scope`, `/surface/findings?rule=&min_severity=&status=` | summary tree, assets, authorized scope, findings |
| POST, DELETE | `/surface/scope` `{target, kind?, owner?, authorization?, replace?}`, `/surface/scope/{target}` | manage the authorized scope (201 / 409 on conflict) |
| POST | `/surface/import?apply_scope=&format=&source_name=` (body: the inventory; never a path), `/surface/analyze?at=&expiring_days=&persist=` | import an inventory (20 MB, 413 above), analyze — see [products/surface.md](products/surface.md) |
