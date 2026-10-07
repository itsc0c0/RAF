# R$F web workbench (`web/`)

The web workbench is a React + TypeScript single-page application that talks to the R$F HTTP API
(`/api/v1`, see [api.md](api.md)). It is a set of views into one security graph, not a collection of
separate dashboards: every object anywhere in the UI can be inspected and pivoted to the other
products, exactly like `raf show` in the terminal.

`raf serve` serves the production build from `web/dist` (SPA fallback to `index.html`) with the CSP
`default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self';
connect-src 'self'; frame-ancestors 'none'`.

## Stack

| Concern | Choice |
|---|---|
| Build | Vite 8, `@vitejs/plugin-react` |
| Language | TypeScript 6.0, `strict` + `noUncheckedIndexedAccess` |
| UI | React 19, hand-written CSS with design tokens (no UI kit, no CSS-in-JS) |
| Routing | React Router 7 (data router, lazy pages) |
| Data | TanStack Query 5 (cache, retries, polling, invalidation) |
| Lists | TanStack Virtual 3 (windowed rendering) |
| Graph | Cytoscape.js 3 (ships its own types) |
| Quality | ESLint 10 flat config (+ typescript-eslint type-checked, react-hooks 7 incl. compiler rules), Prettier |
| Tests | Vitest 5, jsdom, Testing Library (react, user-event, jest-dom) |

Version notes: TypeScript is pinned to `~6.0` because typescript-eslint 8.x supports TypeScript
`< 6.1`. jsdom is pinned to 29 because jsdom 30 requires Node `>= 22.22.2`. `@types/cytoscape` is not
installed: it is a deprecated stub since Cytoscape bundles its own type definitions. Besides the
requested packages, the dev dependencies include the usual glue: `@eslint/js`, `globals`,
`@types/react`, `@types/react-dom`, `@types/node` (Vite config) and `@testing-library/dom` (peer of
`@testing-library/react`).

## Layout of the code

```
web/
  index.html              entry; loads /theme-init.js (external, CSP-safe) before the bundle
  public/                 favicon.svg, theme-init.js (applies the saved theme before first paint)
  vite.config.ts          dev proxy /api -> http://127.0.0.1:8765, build to dist/, Vitest config
  eslint.config.js        flat config + security rules (see "Security")
  src/
    main.tsx              mounts <App/>, imports global CSS
    api/
      client.ts           typed fetch wrapper, ApiError, URL/query builders, download URLs,
                          token-aware downloads (fetch + Blob + object URL)
      auth.ts             bearer token store (sessionStorage, memory fallback), 401 listeners
      types.ts            API payload types (docs/api.md + observed backend JSON)
      hooks.ts            React Query hooks, query keys, mutations + invalidation
    app/                  application shell
      App.tsx             providers + router; AppProviders is reused by tests
      router.tsx          route table (pages are lazy chunks), redirects, route error/404 views
      Shell.tsx           layout grid, ShellProviders, WorkspaceGate
      TopBar.tsx, LeftNav.tsx, WorkspaceSwitcher.tsx, JobIndicator.tsx
      auth.tsx            token prompt, top-bar token indicator, "Enter token" state, forget token
      workspace.tsx       selected workspace (header scoping), create/switch
      shellState.tsx      inspector stack, Oracle panel, command palette contexts
      analyze.tsx         hidden file input + POST /analyze upload, then opens the analysis
      theme.tsx           dark (default) / light, persisted in localStorage
      navigation.ts       primary navigation items, their sections and backing products
      queryClient.ts      React Query defaults (retry policy, no focus refetch)
    components/           shared primitives: Badge (Severity/Confidence/Product/Job/Risk),
                          Button/IconButton, Icon, Panel/PageHeader/Callout/Toolbar, Drawer,
                          Modal/ConfirmDialog, Form controls, Tabs, Table, Data (Time, KeyValueList,
                          MetadataList, FactorList, StatTile, Meter, CopyButton, CommandList...),
                          Chain, Histogram (+ histogramMath), VirtualList, ObjectChip/TypeTag, States
                          (ErrorState, UnavailableState, EmptyState, NoDataHint, QueryView), Toast,
                          DownloadLink (export link that also works when a token is required)
    features/             one folder per area: inspector, palette, search, oracle, graph, replay,
                          timeline, trace, investigate, exposure, findings, lifecycle, overview,
                          analyses, diff, ghost, policy, surface, lab, protocol, vault, dependency
    pages/                route components that compose features (one per nav item)
    lib/                  format (UTC time, sizes...), routes (safe internal routes), objectTypes
                          (visual encoding), storage, hooks, cx
    styles/               tokens.css (design tokens), base.css, components.css, shell.css,
                          pages.css + per-view CSS loaded with the lazy page chunks
    test/                 setup.ts (jsdom shims), utils.tsx (fetch mock, provider wrapper)
```

## Routes

All views are deep-linkable; the query parameters are exactly what the backend pivot API
(`GET /objects/{id}/pivots`, field `view`) produces, so any object can pivot anywhere.

| Route | Parameters | View |
|---|---|---|
| `/` | | Overview: counts, open findings by severity, incidents, jobs, snapshots, quick actions |
| `/findings` | `finding=<id>`, `tab=vault\|dependency`, `project=<id>` | Findings table, detail drawer, triage; tabs **Secrets (Vault)** and **Dependencies** |
| `/investigate` | `object=<ref>` (Lens scope), `trace=<ref>` | Lens-style workbench; Trace tree and causal chain |
| `/graph` | `focus=<ref>`, `depth=1..4`, `at=<ISO>` | Cytoscape graph (overview when no focus) |
| `/replay` | `incident=<ref>` | Incident replay player |
| `/timeline` | `object=<ref>` or `scope=<ref>` (also `incident=`) | Timeline with filters, histogram, virtual list |
| `/analyses` | `analysis=<id>` | Analysis records, upload form, executed steps of one analysis |
| `/diff` | `a=<snapshot>\|current`, `b=<snapshot>\|current`, `category=`, `limit=100\|500\|1000\|2000` | Snapshots & Diff |
| `/exposure` | `blast=<ref>`, `object=<ref>`, `iam=<ref>`; `view=policies`, `policy=<id>`; `view=policy-check`; `view=policy-diff`, `before=<snapshot>\|current`, `after=<snapshot>\|current` | Ranked exposure, asset detail, blast radius, IAM paths; **Policies** tab (stored policies, check a document, compare revisions) |
| `/surface` | `view=assets\|scope\|findings\|import` (default overview), `finding=<id>` | Surface: authorized external attack surface |
| `/ghost` | `model=<name>`, `view=simulate\|compare` (default operations) | Ghost what-if models |
| `/ranges` | | Synthetic ranges (lifecycle actions) |
| `/lab` | `lab=<name>` | Isolated container labs |
| `/protocol` | `upload=<id>`, `view=flows\|packet` (default summary), `packet=<n>` | Saved packet captures explained |
| `/evidence` | `case=<name>`, `object=<ref>` | Cases, items, custody, integrity verification |
| `/oracle` | | Oracle: ask grounded questions, provider status |
| `/products` | | Product registry, enable/disable |
| `/settings` | | Appearance, access token, workspaces, effective config, Oracle status, versions |

`<ref>` is anything the API resolves: full IDs (`host:ws-04`), names (`WS-04`), aliases,
incidents (`INC-001`). Redirects keep the query string: `/labs` → `/lab` (the earlier route) and
`/range` → `/ranges` (the `ui.route` declared by the Range and Forge manifests).

## Shell

* **Top bar**: brand, workspace switcher, global search (`/` focuses it), token indicator (only
  while the server asks for a token), running-jobs indicator, command palette button, Oracle button,
  theme toggle.
* **Left navigation**: sections follow the product categories (Overview and Findings on top, then
  Investigation, Exposure, Synthetic, Analysis, Platform); collapsible to icons (sections are then
  separated by a hairline). Items whose backing products are all unavailable are marked `n/a`.
* **Access token** (`app/auth.tsx`): the first 401 `raf.unauthorized` opens a modal "Access token
  required" (password field, autocomplete off). After Cancel (or "Forget token") it does not pop up
  by itself again while polling queries keep answering 401; the key button in the top bar, the
  "Enter token" state shown in place of the page, and Settings → Access token reopen it. A 401 to a
  request sent with an older token is ignored; when the current token is rejected the prompt says
  so. Entering or forgetting a token resets every cached query, so all data is fetched again with
  (or without) it.
* **Workspace scoping**: `GET /workspaces` provides the list and the server's current workspace.
  Switching calls `POST /workspaces/{name}/use` (so the CLI follows) and re-scopes the UI. Every API
  request carries `X-RAF-Workspace`; plain download links use `?workspace=` instead (links cannot
  carry headers). Query keys include the workspace, so cached data is never mixed across workspaces.
* **Global search** (`GET /search?q=`, debounced 250 ms): ARIA combobox/listbox, ↑/↓, Enter, Esc.
  Objects and incidents open the inspector; findings open the findings drawer. Enter before results
  arrive inspects the typed reference directly (the API resolves names and aliases).
* **Command palette** (Ctrl/⌘ K): navigation (every nav item), `Replay Incident <name>` /
  `Timeline of <name>` (from `GET /incidents`), Create Snapshot (inline name prompt,
  `POST /snapshots`), Analyze Evidence (file picker, multipart `POST /analyze`; the new analysis
  opens on `/analyses?analysis=<id>`), Switch/Create Workspace, Ask Oracle, theme, and live
  `Open <object>` results from `GET /search`. Fuzzy subsequence ranking (`features/palette/fuzzy.ts`).
* **Object inspector**: a non-modal drawer opened from anywhere (chips, graph, search, citations).
  `GET /objects/{ref}` (details, notes, activity, findings, pivots), `/relationships` and
  `/provenance`. Relationship endpoints are chips; the inspector keeps a back stack. It also shows
  events (`GET /events/{id}`) with the raw record marked as untrusted.
* **Job indicator**: polls `GET /jobs?status=RUNNING` every 3 s, lists progress and allows cancel;
  when the last job finishes every cached query is invalidated (imports change the data).
* **Oracle panel**: `POST /oracle/ask`, the same conversation component as the `/oracle` page (see
  "Oracle" below). The panel always states "AI output is not authoritative; verify against R$F
  data."
* **Empty workspaces** explain `raf demo load` and `raf analyze <file>`.

## Data flow and error model

* `api/client.ts` is the only place that calls `fetch`. Errors always become `ApiError`
  (`status`, `code`, `message`, `reason`, `hint`, `suggestions`, `details`), parsed from the API
  envelope `{"error": {...}}`; network and proxy failures become "Cannot reach the R$F API".
* Every request carries `X-RAF-Workspace` and, when a token is set for the tab,
  `Authorization: Bearer <token>`. A 401 `raf.unauthorized` (`ApiError.isUnauthorized`) notifies
  the token prompt with the token the request was sent with.
* 422 `raf.invalid_request` answers list their field problems (`details.problems: [{loc, msg}]`,
  exposed as `ApiError.problems`); `ErrorState` lists them under the message, and toasts built with
  `errorSummary` include them.
* Uploads: multipart for `POST /analyze` and `POST /protocol/inspect` (field `file`); the raw file as
  the request body for `POST /surface/import` (`application/json`, `application/x-ndjson`,
  `application/yaml` or `text/csv` by format); a policy document as JSON text for `POST /policy/check`
  (`{document, format, principal?}`, read in the browser). The server never receives a path from the UI.
* **Graceful degradation**: products are implemented and enabled independently. An `ApiError` is
  *unavailable* when the route does not exist (`raf.http_404`, `raf.http_405`), a dependency is
  missing (503, `raf.dependency_unavailable`) or the product is disabled (`raf.product_disabled`).
  Views render an inline "<Feature> is not available yet" state instead of failing; a real
  "object not found" (`raf.not_found`) is shown as an error with the API's hint and suggestions.
  The left navigation marks items whose backing products are all unavailable (`n/a`).
* React Query: 15 s stale time, no refetch on window focus, no retries for 4xx/unavailable, one
  retry for network/5xx. Mutations invalidate the affected API paths (`invalidatePaths`).
* `components/States.tsx` → `QueryView` renders loading / unavailable / error / data uniformly.

## Feature notes

### Graph (`features/graph`)

* Data: `GET /graph/view` (focus + depth + `at`, or the overview), expansions via
  `GET /graph/neighbors` (double-click or "Expand"), paths via `GET /graph/path`. The client model
  (`graphModel.ts`, pure) only ever contains nodes/edges returned by the API; server truncation is
  surfaced (view and expansions).
* **Collapse branch** removes the nodes that are only reachable through the collapsed node: the
  node is removed temporarily and everything still connected to an anchor (the view's roots, or the
  initially loaded nodes for root-less overviews) is kept.
* Filters (object and relationship types, built from the loaded data, with counts) hide elements
  via classes; no relayout. The type list doubles as the color legend.
* Encoding: fill = type family (assets, principals, activity, neutral) using a categorical palette
  validated for colour-vision deficiencies in both themes; shape = exact type; border width/colour
  = business criticality; incident `INVOLVES` edges (metadata.virtual) are dashed; edge labels only
  on hover/selection. Labels are canvas text (never HTML).
* Layouts: cose (deterministically seeded, constrained to the container aspect ratio),
  breadthfirst, concentric. The viewport is fitted to node geometry (label boxes excluded).
* The Cytoscape instance lives for the component lifetime; React state is applied as diffs
  (add/remove elements, toggle classes), so unrelated state never re-creates or re-lays out the graph.
  A node list provides keyboard and screen-reader access to every node.

### Replay (`features/replay`)

* `engine.ts` is pure and deterministic: `applyStep` mirrors
  `raf.products.replay.service.apply_step` (objects/relationships added, relationships removed,
  sessions keyed `user@host`, processes keyed by process ID, flows/files/identity changes/alerts
  appended). State at index `i` = initial state + steps `0..i` (`-1` = before the first step).
* `ReplayEngine.seek(i)` continues forward from the last computed state, or restarts from the
  nearest checkpoint (full copies every 32 steps, taken while moving forward) when seeking backward.
  Handed-out states are never mutated. Tests assert that seeking forward to N then back to M equals
  replaying `0..M` directly, for every N/M.
* Playback is compressed time: at 1x one minute of incident time plays in one second, each step
  delay is capped at 2 s; speeds 0.25x–10x. Controls: step back, step, pause, play (Space, ←/→).
* The scrubber spans the replay window with markers for HIGH/CRITICAL steps. The state graph is laid
  out once over every element that becomes visible during the incident (stable positions); per step,
  elements are present, newly added (highlighted), removed (dashed, faded) or absent (hidden).
* Side panels: active sessions, running processes, flows of the last 10 minutes (same window as
  `GET /replay/{ref}/state`), file activity, identity changes, alerts; plus a virtualized event log.

### Timeline (`features/timeline`)

Scope (incident/object/workspace), event types, categories, minimum severity, R$F filter language,
from/to (UTC). Group-by counts (click to add a filter term), an SVG histogram with brush (drag to
zoom into a window; keyboard: ←/→ + Enter, Esc clears), and a virtualized event list with keyset
pagination ("load more" and automatic loading near the end). Exports (CSV, JSON, R$F bundle) are
same-origin links to `GET /timeline/export` carrying the same filters (categories are converted to
filter-language terms because the export endpoint has no category parameter).

### Investigate (`features/investigate`, `features/trace`)

Lens-style workbench: scope + filter language + group-by + histogram + results, plus object search
with per-object pivots (Graph, Timeline, Trace/Replay, Evidence, Exposure). It uses
`GET /lens/query` when the Lens product is available and otherwise answers the same question with
`GET /timeline` and `GET /objects`. `?trace=` renders `GET /trace/{ref}`: the most supported causal
chain (earliest cause first), and backward/forward trees built from `step`/`parent_step`. Observed
links are solid, correlated links dashed and labelled; confidence is shown on every link, with the
reminder that correlation is not causation.

### Analyses (`features/analyses`, `/analyses`)

* Upload form: multipart `POST /analyze` with `file`, optional `incident` (link the imported events
  to an incident) and `correlate`; the result opens on `?analysis=<id>`, with a toast whose tone
  follows the status. The list shows the 100 most recent records (`GET /analyses`).
* Detail (`GET /analyses/{id}`): status, detected type and parser label, input name and SHA-256,
  jobs, incidents, stat tiles, and every executed step in order with its status (OK / SKIPPED /
  FAILED as icon + word, never colour alone), detail text, duration and statistics. Suggestions are
  copyable commands.
* Explore: Lens (`/investigate?object=<id>`), Graph (`/graph?focus=<id>`) and Timeline
  (`/timeline?scope=<id>`) scoped to exactly the analysis' data (the API resolves the analysis ID
  through job provenance), plus Replay for each linked incident.
* The API puts the server's temporary upload path into some suggestions (see "Known limitations");
  the UI replaces absolute paths in suggestions with the uploaded file name and says so.

### Snapshots & Diff (`features/diff`, `/diff`)

* Compare form: A and B are `current` (the live workspace), any snapshot from `GET /snapshots` or any
  Ghost model (`ghost:<model>`, from `GET /ghost/models`);
  optional category (privileges, exposure, vulnerabilities, network, policies, hosts, services,
  identities, packages, findings, objects, relationships) and limit (100–2000). Swap exchanges A/B.
* Result (`GET /diff?a=&b=&category=&limit=`): `a → b` header with object and relationship totals,
  a by-category table (added / removed / changed; a row click filters the category), counts by
  importance with the backend's importance rules, and the change table (change, importance,
  category, item with inspector chips, why, details such as `metadata: old → new`). Server-side
  truncation is shown.
* Snapshots panel: create a snapshot from `current` or from a Ghost model (`ghost:<model>`,
  `POST /snapshots`), list snapshots, and "Diff → current" per snapshot.

### Ghost (`features/ghost`, `/ghost`)

* A notice states that models are in-memory copies of a frozen state: operations never touch the
  workspace or any real system, and there are no connectors that apply changes.
* Models (`GET /ghost/models`): create (`POST /ghost/models {name, base, description}`; base
  `current` or a snapshot), clone, delete (also removes the model's frozen base snapshot; asks for
  the name), and "Save as snapshot" (a snapshot of `ghost:<model>`, then a link to Diff it against
  the model's base snapshot).
* Operations tab: the operations log (`GET /ghost/models/{name}`) with each operation's effects,
  the apply form (`POST /ghost/models/{name}/ops {op, arg}`) whose operation list and argument hints
  come from `GET /ghost/operations`, and Undo (`POST /ghost/models/{name}/undo`, confirmed).
* Simulate tab (`GET /ghost/models/{name}/simulate`): exposure metrics, assets by level, user
  control over high/critical assets and the most exposed assets with their factor breakdown.
* Compare tab (`GET /ghost/compare?a=&b=`; A/B = `current`, snapshots or models): metric table with
  deltas ("N fewer/more", lower is better), level counts per side, assets whose exposure changed
  and users whose control over high/critical assets changed.

### Policies (Exposure → Policies, `features/policy`)

Three sub-tabs: **Stored policies** (`?view=policies`, `?policy=<id>`), **Check a document**
(`?view=policy-check`) and **Compare revisions** (`?view=policy-diff&before=&after=`).

* `GET /policy/policies`: policies with domain, evaluation strategy, default decision, revision and
  source; the selected policy's rules (effect, principals/resources/actions for access policies,
  sources/destinations/ports for network policies).
* Analysis findings: recorded `policy` findings (overly broad, shadowed, redundant and conflicting
  rules, stale references, default-allow). "Analyze (dry run)" calls `POST /policy/analyze?persist=false`
  and changes nothing; "Analyze and record" (`persist=true`) is behind a confirmation.
* Evaluate a request: `POST /policy/evaluate {subject | source, target, action, port}` shows the
  decision and its reason, then per part the policy's decision, its explanation, the deciding rules
  and the pre-empted ones (would have matched, but an earlier rule decided); indirect paths are
  called out.
* Check a document (`POST /policy/check {document, format, principal?}`): paste the document or pick a
  file (.json, .yaml/.yml, .csv; at most 5 MB, checked before sending). The browser reads the file into
  the editor and only its text is sent. The format (json, yaml, csv) is set from the file extension and
  can be changed; the optional principal applies to AWS-style statements without one. A notice says that
  nothing is stored: the route writes no policy, finding, job or audit entry. The result reuses the
  stored-policy components: the normalized policies (with findings per policy), the selected policy's
  rules, then the analysis (findings by rule, warnings, findings table). Its findings exist only in the
  answer, so they open in a drawer marked NOT STORED, without triage. The route has no file-name field:
  CSV exports without a policy column and AWS-style documents are named `request` (the CLI uses the
  file name).
* Compare revisions (`GET /policy/diff?before=&after=`): before and after are `current` or any snapshot
  from `GET /snapshots` (latest snapshot → `current` preselected; Swap). Policy files are compared from
  the CLI only (`raf policy diff FILE current`). The result says whether access expanded (rule changes
  with impact `access-expanded`, counted by the API in `access_expanded`, and default actions that
  became allow), then lists added and removed policies, changed defaults, every rule change (impact,
  kind, rule summary before and after, changed fields such as `ports: tcp/22, tcp/8443 → any`) and the
  analysis findings the later revision introduces or resolves (computed for the comparison, not
  stored). Identical revisions show "No policy differences"; without snapshots the view explains how to
  create one.

### Surface (`features/surface`, `/surface`)

* A notice above the tabs (so on every tab) says "Surface never scans": no DNS resolution, port
  scanning, HTTP requests, certificate retrieval or WHOIS lookups; everything comes from imported
  inventories and the declared scope, so a finding means "according to the imported data".
* Overview (`GET /surface/summary?expiring_days=7|14|30|60|90`): stat tiles, open findings by
  severity with the top findings (open the findings drawer), inventory by kind and owners, and the
  **domain tree**: domains → DNS records → addresses (with host, internal-address and scope marks)
  → services (INTERNET-FACING) and certificates with their state (VALID "N days left", EXPIRING
  "expires in N days", EXPIRED "expired N days ago", UNKNOWN) and validity end, plus cloud assets
  (PUBLIC) and claimed owners ("claimed by X (not accepted)"). Tables list cloud assets, addresses
  without a name and out-of-scope addresses, services and cloud assets. "Dry run"
  (`POST /surface/analyze?persist=false`) and "Analyze" (`persist=true`) run the rules.
* Assets: `GET /surface/assets` with kind (domain, ip, service, certificate, cloud_asset) and scope
  (all / in / out) filters, optionally including references.
* Authorized scope: a callout explains that scope means explicit authorization (only covered assets
  are treated as the organization's; every change is audited by the backend). Entries come from
  `GET /surface/scope`; adding (`POST /surface/scope {target, kind?, owner, authorization,
  replace}`) and removal (`DELETE /surface/scope/{target}`) are explicit; removal opens a
  confirmation that requires typing the target.
* Findings: `GET /surface/findings` in the shared findings table and drawer (`?finding=`).
* Import: the inventory file (raf-surface/1 JSON or YAML, JSON Lines, CSV with a `kind` column, JSON
  list) is sent as the request body of `POST /surface/import?format=&source_name=`; the format comes
  from the file name unless chosen. "Apply the file's scope section" is **off by default**, explained
  next to the checkbox, and only when checked is `apply_scope=true` sent. Files over 20 MB (the
  server limit) are refused before upload. The result lists accepted/rejected records, rejections
  with reasons, warnings and scope changes.

### Lab (`features/lab`, `/lab`)

* Container backend (`GET /lab/status` → `{backend, available, reason, version}`): when it is down
  the page says what still works (create, list, destroy) and start/stop are disabled with the
  reason as tooltip.
* Running commands: the API has no exec or shell route on purpose; the page says that commands run
  through the local CLI (`raf lab exec <name> -- …`, `raf lab shell <name>`) as copyable commands.
* New lab: `POST /lab/labs` with exactly `{name, image?, mounts?, allow_outbound, memory?, cpus?,
  root, description?, backend?}` (the API rejects unknown fields with 422). The form checks the
  name, absolute mount paths (at most 8), memory and CPU ranges before sending; outbound access and
  root show warnings; defaults come from `GET /config` (`lab.default_image`, ...). Mounts are always
  read-only at `/lab/input/<name>`.
* Labs table and drawer (`?lab=<name>`, `GET /lab/labs/{name}`): state (live or last recorded),
  network, mounts (READ-ONLY), resources, user, container, note, description and the container
  command (`container_args`). Lifecycle: `POST /lab/labs/{name}/start|stop` and
  `DELETE /lab/labs/{name}` (destroy asks for the name and can "forget" a definition whose container
  cannot be removed: `?forget=true`). Unreadable definitions reported by the list (`invalid`) can be
  forgotten.

### Protocol (`features/protocol`, `/protocol`)

* Upload: multipart `POST /protocol/inspect` (`file`, `limit=50`) stores the capture under a
  generated upload ID and returns its summary; the page then shows `?upload=<id>`. R$F never captures
  live traffic.
* Earlier uploads (`GET /protocol/uploads?limit=100`, newest first): name, size, upload time and
  SHA-256 prefix. A row opens the upload exactly like an ID typed into the form below the list; the open
  upload is highlighted and the list refreshes after an upload. With more than 100 uploads, older ones
  are opened by ID.
* Summary (`GET /protocol/inspect?upload=` with `protocol`, `host`, `port`, `flow` filters): file,
  packet counts, protocols, flows, DNS, TLS and HTTP metadata.
* Flows (`GET /protocol/flows?upload=&sort=&limit=`): client → server (inferred), application
  protocol, packets and bytes per direction, duration, TCP flags.
* Packet (`GET /protocol/packet?upload=&n=`): every decoded layer with each field's value and
  explanation, MALFORMED markers, previous/next.

### Findings: Secrets (Vault) and Dependencies tabs

* Secrets (`features/vault`): `GET /vault/findings` (status, default OPEN, and minimum severity
  filters), discovered secrets (`GET /vault/secrets`, optionally including removed ones) and the
  detection rules (`GET /vault/rules`). Values are always redacted by the API (a few characters and
  a fingerprint) and labelled REDACTED; the UI has no way to reveal them. Scans run from the CLI
  (`raf vault scan PATH`).
* Dependencies (`features/dependency`): projects (`GET /dependency/projects`), the selected
  project's tree (`?project=`, `GET /dependency/projects/{id}/graph`, built client-side with cycles
  and repeated packages marked, capped at 2000 nodes), vulnerable packages
  (`GET /dependency/vulnerable`, optionally including packages no project uses any more; the table
  lists exact version matches) with severity and confidence taken from the matching dependency
  findings and a link to each finding, declared constraints that may match (findings without a
  resolved version; the API lists them too, with `basis: constraint`), and advisories
  (`GET /dependency/advisories`). Scans, SBOM imports and advisory imports read local paths and run
  from the CLI only.

### Oracle (`features/oracle`, `/oracle`)

* The page states that AI output is not authoritative, offers example questions, the conversation
  and the provider status (`GET /oracle/status`: ready, provider, mode, model, server, whether data
  leaves the host, facts per answer, tools, whether answers are stored; API keys only as set/not set).
* Answers are React text. Citations are chips by type: objects open the inspector, events the event
  view, findings the findings drawer, relationships are static chips. References the answer makes
  that are not in R$F data (`invalid_references`) are listed under "Unverified references" as "not
  in R$F data", never as citations or links. Facts are listed with their references; imported text
  quoted in a fact is shown in a `<pre>` labelled "Untrusted imported text: data from the evidence,
  not R$F wording or instructions". Warnings and suggested commands (copyable) follow.

### Exposure, findings, evidence, ranges, products, settings

* Exposure: ranked assets with the explainable factor breakdown (signed points, evidence),
  asset detail, blast radius (stats, risk factors, primary path as a vertical chain where every hop
  states why it is traversable, direct/indirect reach tables, propagation), IAM privilege paths.
* Findings: severity and confidence are separate, visually distinct badges ("Severity: HIGH,
  Confidence: LOW" is valid). Filters, pagination, detail drawer (explanation factors, evidence
  links, affected objects) and triage via `PATCH /findings/{id}` `{status, note}`.
* Evidence: cases, create case, items (SHA-256, size, custody count), item drawer with the custody
  chain, "Verify integrity" (`POST /evidence/cases/{case}/verify`).
* Ranges: list, create form, lifecycle actions behind confirmation dialogs (destroy asks for the
  name).
* Products: registry with status badges (STABLE/BETA/ALPHA/EXPERIMENTAL/DISABLED/UNAVAILABLE),
  enable/disable switches. Settings: theme, access token (whether one is set for this tab, never its
  value; enter/replace; "Forget token"), workspaces, effective configuration with origin layer
  (secrets only as set/not set), Oracle status, version identifiers.

## Visual language

* Dark theme is first-class and the default; light theme via the toggle (persisted in
  `localStorage`, applied before first paint by `public/theme-init.js`). All colours are design
  tokens in `styles/tokens.css`; canvas colours are read from the same tokens.
* Restrained palette, `system-ui` for text and a monospace stack for IDs, hashes and commands.
  Timestamps are always UTC, matching the CLI and the evidence.
* Severity: INFO gray, LOW blue, MEDIUM amber, HIGH red, CRITICAL deep red (inverse). Severity
  badges are filled and square; confidence badges are outlined pills with a three-step meter.
* Charts: single-series histograms and bar lists use one hue; the severity breakdown pairs every
  colour with a labelled badge and count; no colour carries meaning alone.

## Security

Imported data is untrusted (names, metadata, raw log lines, Oracle answers):

* Everything is rendered as React text. ESLint forbids `dangerouslySetInnerHTML`, `innerHTML`,
  `outerHTML`, `insertAdjacentHTML`, `createContextualFragment`, `document.write`, `eval`,
  `new Function`, implied eval and `javascript:` URLs (`eslint.config.js`). Cytoscape labels are
  canvas text. Metadata values are stringified (`displayValue`), never interpreted.
* Navigation targets that come from data (pivot `view`s, product `ui.route`) go through
  `lib/routes.ts#toInternalRoute`: only known in-app paths are accepted (no scheme, no `//`, no
  backslashes, no control characters) and raw object IDs are re-encoded. URLs found in data
  (e.g. `url:` objects) are displayed as text, never as links.
* Raw source records are shown verbatim in a `<pre>` with an "untrusted input" label; so is
  imported text quoted in Oracle facts ("Untrusted imported text"). Surface inventories, checked
  policy documents, lab descriptions, analysis details, packet fields and upload names are rendered as
  React text like everything else.
* CSP compatibility: no inline scripts (theme bootstrap is a same-origin file), no `eval`, no
  external fonts, CDNs or images. Downloads are same-origin `/api/v1/...` links, or same-origin
  fetches saved through a `blob:` object URL when a token is set (see below).
* The UI never displays secrets: configuration secrets arrive as "set/not set", the Oracle status
  endpoint never includes API keys, and Vault values are redacted by the API (the UI has no reveal
  action).

**Bearer token** (`raf serve` bound to a non-loopback address requires one: the `api.token`
secret, `RAF_API_TOKEN`, or a token generated and printed once at startup; every `/api/` route
except `/api/v1/health` then answers 401 `raf.unauthorized` without it):

* Stored only in `sessionStorage` under `raf.api.token` (this tab; cleared when the tab closes),
  never in `localStorage`, cookies or URLs. If session storage is blocked it is kept in memory until
  the page is reloaded. Only visible ASCII without spaces (at most 4096 characters) is accepted.
* Sent only as `Authorization: Bearer <token>` by `api/client.ts`. It is never rendered (the prompt
  uses a password field; Settings shows only whether a token is set) and never logged; tests check
  that it appears in no text or attribute of the page.
* Exports (Timeline CSV/JSON/bundle, Graph) cannot carry a header as plain links. With a token they
  are fetched with the header, saved through a `blob:` object URL (revoked after 10 s) and named
  from `Content-Disposition` (sanitized; fallback name otherwise). Without a token they stay plain
  same-origin links.
* "Forget token" (Settings) removes it from the tab and drops all cached API data.

**Actions with side effects** are explicit and described where they happen: lab destroy and Ghost
model deletion ask for the name; Surface scope removal asks for the target; policy "Analyze and
record" and Ghost undo are confirmed; the Surface import applies the file's scope section only when
the (unchecked by default) box is ticked. The Lab page has no command execution: the API has no
exec or shell route, and the page points to `raf lab exec` / `raf lab shell`. Surface never scans
and Ghost never touches real systems; both say so on the page.

## Accessibility and performance

* Visible focus rings, skip link, labelled icon buttons, ARIA combobox/listbox patterns for search
  and palette, modal focus trap and focus restoration, Escape closes drawers and dialogs, keyboard
  operation of tabs, tables (Enter/Space on rows), virtual lists (↑/↓), histogram brush and replay.
  `prefers-reduced-motion` disables animations.
* Pages are lazy chunks (Cytoscape loads only with Graph/Replay); long lists are virtualized; search
  is debounced; React Query caches per workspace; the graph applies diffs instead of re-rendering.

## Develop, build, test

```bash
cd web
npm install
npm run dev          # http://127.0.0.1:5173, proxies /api to a running `raf serve` (127.0.0.1:8765)
npm run typecheck    # tsc -b (strict)
npm run lint         # eslint .
npm run format       # prettier --write .  (format:check for CI)
npm run test         # vitest run
npm run build        # tsc -b && vite build -> web/dist (served by `raf serve`)
```

Against demo data:

```bash
raf demo load
raf serve            # API + built UI on http://127.0.0.1:8765
```

Tests (`src/**/*.test.ts(x)`, fetch is mocked with `src/test/utils.tsx#mockFetch`):

| Test | Covers |
|---|---|
| `features/palette/CommandPalette.test.tsx` | Ctrl+K / ⌘K open/close, fuzzy filtering, arrow keys, Enter/click execution, incident commands, live object results |
| `features/inspector/ObjectInspector.test.tsx` | `<img src=x onerror=...>` names, metadata, tags, provenance and relationship IDs render as literal text (no `img`/`script`/`a[href^=javascript]` elements); only internal pivots |
| `features/replay/engine.test.ts` | forward-to-N-then-back-to-M equals 0..M (all pairs, several checkpoint intervals), removals, sessions and processes open/close, immutability, playback timing, markers, element statuses |
| `features/timeline/EventList.test.tsx` | 5000 events render only a window of rows; scrolling moves the window and requests the next page |
| `components/States.test.tsx`, `api/client.test.ts` | ApiError rendering (message, reason, hint, suggestions, retry), error envelope parsing, unavailable vs not found, network errors, workspace header, bearer header and 401 notification with the token used, 422 field problems, safe download file names |
| `app/auth.test.tsx` | 401 opens the prompt; the token goes to `sessionStorage` only and is sent on every later request; it appears in no text or attribute; Cancel; a rejected token is reported; Forget token; exports are fetched with the header and saved from an object URL, plain links without a token |
| `features/lab/LabPage.test.tsx` | create sends exactly the accepted fields (no unknown keys), client-side validation, list/drawer (network, read-only mounts, user, container command), start/stop disabled when the backend is down, destroy with "forget" closes the drawer without refetching the deleted lab, no exec route, `/labs` redirect |
| `features/analyses/AnalysisViews.test.tsx` | detail renders the detected type and every step with status, detail, duration and stats; upload sends `incident`/`correlate` and opens the result; server paths in suggestions are replaced |
| `features/diff/DiffViews.test.tsx` | summary by category, importance counts, every change with its reason; current + snapshots offered for A/B |
| `features/ghost/GhostViews.test.tsx` | applying an operation (`POST …/ops {op, arg}`) updates the operations log; comparison deltas, assets and users |
| `features/oracle/OraclePage.test.tsx` | invalid references are flagged as unverified (not chips), untrusted fact text is labelled and stays text, citations open by type |
| `features/surface/SurfaceViews.test.tsx` | the tree renders certificate states (valid/expiring/expired), scope and claimed owners as text; scope removal needs the typed confirmation; the import sends the file as the body with `apply_scope` only when checked; format inference |
| `features/policy/PolicyViews.test.tsx` | check: a picked file is sent as text with the format from its extension and the principal, pasted text with a format chosen by hand, API errors are shown; normalized policies, rules, warnings and findings render as literal text (no `img`/`script`/`b` elements); computed findings open in a NOT STORED drawer without triage or `GET /findings`; compare: `current` and the snapshots are offered (latest snapshot preselected), Compare updates the URL, access expansion (incl. a default that became allow), every rule change with impact and changed fields, introduced findings; the "No policy differences" state; format inference |
| `features/protocol/ProtocolViews.test.tsx` | a packet with every decoded layer, field explanations and malformed markers; value formatting; earlier uploads (name, size, time, SHA-256 prefix; hostile names stay text) open through the upload ID flow |
| `features/vault/FindingsTabs.test.tsx` | Vault values only as redacted text + fingerprint; dependency tree (cycles, repeats) and finding join for confidence |
| `components/Badge.test.tsx` | severity and confidence badges render independently (incl. in the findings table) |
| others | fuzzy ranking, internal route validation (incl. the new routes and redirects), graph model (merge/collapse/filter/path), histogram brush math, trace tree, timeline filters, formatting, factor lists, Oracle panel, global search |

## Not implemented yet / known limitations

* **Lab**: commands inside a lab run only through the CLI (by design); start/stop need Docker or
  Podman with a running daemon.
* **Replay**: client states are not verified against the server's `checkpoints[].state_hash`
  (byte-identical canonical JSON between Python and JavaScript, e.g. float formatting, would be
  needed).
* **Evidence `?object=`** narrows the items of the selected case by their `objects` field; there is
  no documented endpoint to list evidence by object across cases.
* **Shapes** are typed from `docs/api.md` and from JSON observed on a live backend; optional fields
  are read defensively, so a changed shape degrades the affected view to partial data rather than
  failing.
* Graph expansions/collapses and positions are client-side only (lost on reload).
* There is no end-to-end browser test suite in the repository. The views were smoke-tested with
  headless Chromium against `raf demo load` data (every route, the write flows, and a
  token-protected server for the token prompt and token downloads).

### Backend issues the UI works around

* `GET /objects/{id}` and `GET /objects/{id}/pivots` do not describe event and finding IDs. Oracle
  citations are therefore dispatched by type: events open `GET /events/{id}`, findings the findings
  drawer.
* Analyses stored before `detection` and `duration_ms` were recorded return them as empty/null; the
  UI shows those fields only when present.
