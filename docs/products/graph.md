# R$F Graph

R$F Graph shows how security objects are connected: the neighborhood of an object, every object
involved in an incident or an analysis, the shortest connection between two objects, and the graph
as it was at an earlier time. It reads the shared relationship store; it never infers, scores or adds
relationships (what an attacker could *do* along them is Blast, IAM and Exposure).

Status: **BETA** · category: investigation · command: `raf graph` · API: `/api/v1/graph` · web: Graph
· depends on: core only (`raf.core.graph`)

## Usage

```text
raf graph [SCOPE] [--depth N] [--rel TYPE]... [--node-type TYPE]... [--direction in|out|both]
                  [--at TIME] [--max-nodes N] [--output FILE [--format FORMAT]]
raf graph neighbors OBJECT [--direction in|out|both] [--rel TYPE]... [--at TIME] [--max-nodes N]
raf graph path FROM TO [--directed] [--rel TYPE]... [--at TIME]
raf graph export [SCOPE] [--format json|cytoscape|graphml|dot|csv] [--output FILE] [view options]
raf graph stats
```

`path`, `neighbors`, `export` and `stats` are subcommand words: an object with one of these names
must be given as a full ID (`host:stats`) or with its type (`raf graph host stats`).

### Scopes

The scope syntax is shared with Timeline, Lens and Replay (see [cli.md](../cli.md#references)).

| Scope | Example | View |
|---|---|---|
| nothing, `workspace`, `all`, `@workspace` | `raf graph` | workspace overview |
| an object: ID, name or alias | `raf graph alice`, `raf graph host:ws-02`, `raf graph production` | neighborhood |
| `TYPE NAME` | `raf graph user alice`, `raf graph host WS-02` | neighborhood of that object |
| an incident | `raf graph INC-001` | incident view |
| an analysis or a job | `raf graph analysis-1`, `raf graph job-1` | the data that analysis or job imported |
| a context reference | `raf graph @last`, `@incident`, `@object`, `@analysis`, `@job`, `@case` | what it refers to |

A bare name that matches objects of several types is resolved by a fixed type priority (incident,
user, host, identity, service, ...) and the choice is printed: `raf graph git` reports *"'git' also
matches file:dev-01|/usr/bin/git, ...; using service:git"*. Several matches of the same type are an
error (exit 4) listing the candidates.

## Views

**Neighborhood (object scopes).** Breadth-first expansion from the object, one layer at a time, up
to `--depth` (default `graph.default_depth` = 2; the CLI accepts 1-6). `--direction out` follows
relationships whose source is the current node, `in` those whose target is, `both` (default) both.
`--rel` keeps only the given relationship types (repeatable; normalized to `UPPER_SNAKE_CASE`, and
any syntactically valid type is accepted, including custom ones). `--node-type` keeps only objects of
the given types (repeatable; the starting object is always kept). Relationships are collected while
expanding layers 0 to N-1, so a relationship between two objects that are both at the outermost
depth is not part of the view.

**Incident view.** Every object involved, in any role, in an event linked to the incident, every
relationship among those objects, and one virtual `INVOLVES` edge from the incident to each object
(`id` `virtual:<digest>`, `metadata.virtual = true`, `metadata.reason = "involved in incident
events"`). `--depth`, `--node-type` and `--direction` do not apply.

**Analysis and job views.** The objects a job recorded provenance for, plus the objects involved in
the events it imported (for an analysis that re-read data an earlier, larger import already holds,
only that source), and every relationship among them. `--depth`, `--node-type` and `--direction` do
not apply.

**Workspace overview.** Objects of the types host, user, identity, group, role, service, network,
cloud_resource, vulnerability and secret (or the `--node-type` list) and every relationship among
them. On the Raven demo: 73 nodes and 116 edges.

**Size limit.** A view holds at most `--max-nodes` nodes (default `graph.max_nodes` = 1500). A
neighborhood stops expanding when the limit is reached; incident, analysis, job and overview views
keep the first objects by ID. Either way `truncated` is `true` and the terminal prints
`warning: view truncated at graph.max_nodes`.

**Time (`--at`).** Without `--at` only current relationships are used (`valid_to` empty). With
`--at T` a relationship is used when its start (`valid_from`, else `first_seen`) is empty or not
after T, and its `valid_to` is empty or after T. Inventory relationships without any start time are
always included. Objects are not filtered by time: they appear when a relationship valid at T
reaches them (the starting object and incident members always appear). `T` accepts ISO 8601, epoch
seconds (or ms/us/ns), RFC 2822 and `now`; a bare `HH:MM[:SS]` is placed on the current UTC date,
and relative values such as `+15m` are rejected because a graph has no time anchor.

```text
$ raf graph alice --at 2026-10-06T08:00:00Z

R$F GRAPH  alice  (user:alice)
────────────────────────────────────────
Nodes   13
Edges   13
Depth   2
As of   2026-10-06T08:00:00Z

alice  user
├── MEMBER_OF → all-staff  group
│   ├── ← MEMBER_OF bob  user
│   ...
├── MEMBER_OF → engineering  group
│   ├── ← APPLIES_TO Raven access policy  policy
│   ├── HAS_ROLE → developer  role
│   └── ← MEMBER_OF dave  user
└── OWNS → WS-01  host
    ├── HAS_ADDRESS → 10.10.1.21  ip
    └── MEMBER_OF → CORP  network
```

Without `--at` the same view has 69 nodes and 125 edges: the sessions, processes and requests of
the working day only begin after 08:14.

**Determinism.** Relationships are read in (source, type, target) order and nodes are expanded in
ID order, so the same data always produces the same view, the same truncation and the same path.

## Neighbors

`raf graph neighbors OBJECT` is the depth-1 neighborhood (the web UI's "expand"). It honors
`--direction`, `--rel`, `--at` and `--max-nodes`; `--node-type` is not applied.

## Paths

`raf graph path FROM TO` answers "how are these two objects connected?" with a breadth-first
shortest path (fewest relationships):

* undirected by default: relationships may be followed against their direction; each hop says
  whether it was traversed forward (`forward: true`) and the terminal marks reverse hops
  `(reverse)`;
* `--directed` only follows relationships from source to target;
* `--rel` and `--at` restrict the relationships as in views;
* at most 8 hops (the API accepts `max_depth` 1-12) and at most 50,000 expanded nodes; when either
  limit is hit the result is "No path found".

A shortest path is a structural connection, not an access path. On the Raven demo the undirected
path from alice to DB-01 has three hops through the access policy's `APPLIES_TO` edges, while the
directed path restricted to grant and deployment relationships is the privilege chain:

```text
$ raf graph path alice production --directed --rel MEMBER_OF --rel HAS_ROLE --rel CAN_ACCESS \
      --rel USES --rel DEPLOYS_TO

R$F GRAPH PATH  user:alice → cloud_resource:production
──────────────────────────────────────────────────────

alice  user:alice
   │ MEMBER_OF
   ▼
engineering  group:engineering
   │ HAS_ROLE
   ▼
developer  role:developer
   │ CAN_ACCESS
   ▼
DEV-01  host:dev-01
   │ USES
   ▼
svc-deploy  identity:svc-deploy
   ...
ci-cd  service:ci-cd
   │ DEPLOYS_TO
   ▼
production  cloud_resource:production

8 hop(s)
```

For "could alice obtain control of production, and why?" use `raf blast alice` or
`raf iam path alice production`, which apply the traversal semantics of the
[object model](../object-model.md#traversal-semantics).

## Export

`raf graph export SCOPE` exports exactly the view the same options would display (incident views
include the virtual `INVOLVES` edges). Without `--output` the text is printed to stdout (control
characters in names are escaped for the terminal); `--output FILE` writes the file, records a
`graph.export` audit entry and prints `Exported 49 nodes / 120 edges to inc.graphml`. `--output`
also works without the `export` word (`raf graph alice -o alice.json`). With `--json` and no
`--output`, the subgraph document is printed and `--format` is ignored.

| `--format` | Content |
|---|---|
| `json` (CLI default) | the `raf.graph/v1` subgraph: `roots`, `nodes`, `edges`, `truncated`, `at`, `depth` |
| `cytoscape` | `{"elements": [...]}`; nodes `{id, label, type, criticality}`, edges `{id, source, target, label, confidence}` |
| `graphml` | GraphML, `edgedefault="directed"`; node data `name`, `type`, `criticality`; edge data `relationship_type`, `confidence` |
| `dot` | Graphviz `digraph raf` (`rankdir=LR`), node labels `name (type)`, edge labels the relationship type |
| `csv` | edge list: `relationship_id, source, relationship_type, target, confidence, first_seen, last_seen, valid_to` |

```text
raf graph export INC-001 --format graphml --output inc.graphml
raf graph export alice --format dot | dot -Tsvg > alice.svg
```

## Stats

`raf graph stats` prints object counts by type, relationship counts by type, the totals, and the
ten most connected objects (number of relationships touching each) among the first 2,000 objects of
the overview types. On the Raven demo: 426 objects, 849 relationships; DEV-01 (30), WS-05 (29),
WS-01 (28) and dave (28) are the most connected.

## Terminal rendering

The terminal shows a tree: each object is attached once, under a neighbor one level closer to the
root; `TYPE →` means the relationship points away from the parent, `← TYPE` towards it. Objects with
high or critical criticality are marked `[HIGH]` / `[CRITICAL]`, objects referenced by a relationship
but not stored are marked `(not in store)`. The tree stops after 80 branches; relationships that are
not tree edges are not drawn. The complete view is in `--json`, the exports and the web UI. After an
object view the CLI suggests `raf timeline`, `raf trace` and `raf blast`; after an incident view
`raf replay` and `raf timeline`.

## Output

| Schema | Command | Fields |
|---|---|---|
| `raf.graph/v1` | views, `neighbors`, `export --json` | `roots`, `nodes`, `edges`, `truncated`, `at`, `depth`, and `scope` (`{kind, id, label, job_ids, source?}`) for views |
| `raf.graph.path/v1` | `path` | `source`, `target`, `found`, `directed`, `hops: [{source, source_name, target, target_name, relationship, forward}]`, `at`, `length` |
| `raf.graph.stats/v1` | `stats` | `objects`, `relationships` (counts by type), `total_objects`, `total_relationships`, `most_connected: [{id, name, degree}]` |
| `raf.graph.export/v1` | `export --output` | `path`, `format`, `nodes`, `edges` |

Node: `{id, type, name, depth, criticality, tags, synthetic, first_seen, last_seen, metadata,
missing}`; `metadata` is limited to display keys (`criticality`, `internet_facing`, `privileged`,
`ip`, `os`, `role`, `kind`, `cvss`, `path`, `port`, `display_name`, `disabled`, `aliases`, `cidr`,
`zone`, `redacted`, `full_name`, `department`). Edge: `{id, type, source, target, confidence,
first_seen, last_seen, valid_to, observations, metadata}`.

## API

| Method | Path | Result |
|---|---|---|
| GET | `/graph/view?ref=&depth=&rel=&type=&at=&max_nodes=&direction=` | subgraph + `scope`; `ref` omitted or `workspace` = overview; `depth` 1-6; `max_nodes` 1-5000; `rel` and `type` repeatable |
| GET | `/graph/neighbors?ref=&direction=&rel=&at=&limit=` | depth-1 subgraph; `limit` 1-5000 |
| GET | `/graph/path?source=&target=&directed=&rel=&at=&max_depth=` | path result + `length`; `max_depth` 1-12, default 8 |
| GET | `/graph/export?ref=&format=&depth=` | the export as text (`json`/`cytoscape` application/json, `graphml` application/xml, `dot` text/vnd.graphviz, `csv` text/csv); default `graphml` |
| GET | `/graph/stats` | statistics |

`ref`, `source` and `target` accept everything the CLI accepts as a single word (IDs, names,
aliases, incidents, `analysis-N`, `job-N`). `at` must be a full timestamp. Unlike the CLI, the API
passes `rel` and `type` through unchanged: use canonical upper-case relationship types and
lower-case object types. Errors: 404 unknown reference, 409 ambiguous reference, 422 invalid input.

## Configuration

| Key | Default | Notes |
|---|---|---|
| `graph.default_depth` | `2` | neighborhood depth when `--depth` / `depth` is omitted (minimum 1) |
| `graph.max_nodes` | `1500` | node limit of one view (minimum 10); `--max-nodes` / `max_nodes` override it per request |

## Limitations

* Graph shows recorded relationships only; it does not decide whether a relationship grants control
  or reachability. Shortest paths can run through structural relationships (`APPLIES_TO`, `MEMBER_OF`
  a network) that carry no access.
* Objects are not filtered by `--at`, only relationships.
* `--node-type` applies to object views and the overview, `--depth` and `--direction` to object
  views only.
* The terminal tree is a summary. For analysis and job scopes it shows only the first object (the
  scope itself is not a node); use `--json`, an export or the web UI.
* CSV exports write `first_seen`/`last_seen`/`valid_to` as `2026-10-06 13:29:29+00:00` rather than
  the ISO form used elsewhere (`2026-10-06T13:29:29Z`).
