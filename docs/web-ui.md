# R$F web workbench (`web/`)

The web workbench is a React + TypeScript single-page application that talks to the R$F HTTP API
(`/api/v1`, see [api.md](api.md)). It is a set of views into one security graph, not a collection of
separate dashboards: every object anywhere in the UI can be inspected and pivoted to the other
products, exactly like `raf show` in the terminal.

`raf serve` serves the production build from `web/dist` (SPA fallback to `index.html`) with the CSP
`default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'`.

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
      client.ts           typed fetch wrapper, ApiError, URL/query builders, download URLs
      types.ts            API payload types (docs/api.md + observed backend JSON)
      hooks.ts            React Query hooks, query keys, mutations + invalidation
    app/                  application shell
      App.tsx             providers + router; AppProviders is reused by tests
      router.tsx          route table (pages are lazy chunks), route error/404 views
      Shell.tsx           layout grid, ShellProviders, WorkspaceGate
      TopBar.tsx, LeftNav.tsx, WorkspaceSwitcher.tsx, JobIndicator.tsx
      workspace.tsx       selected workspace (header scoping), create/switch
      shellState.tsx      inspector stack, Oracle panel, command palette contexts
      analyze.tsx         hidden file input + POST /analyze upload
      theme.tsx           dark (default) / light, persisted in localStorage
      navigation.ts       primary navigation items (and backing products)
      queryClient.ts      React Query defaults (retry policy, no focus refetch)
    components/           shared primitives: Badge (Severity/Confidence/Product/Job/Risk),
                          Button/IconButton, Icon, Panel/PageHeader/Callout/Toolbar, Drawer,
                          Modal/ConfirmDialog, Form controls, Tabs, Table, Data (Time, KeyValueList,
                          MetadataList, FactorList, StatTile, Meter, CopyButton...), Chain,
                          Histogram (+ histogramMath), VirtualList, ObjectChip/TypeTag, States
                          (ErrorState, UnavailableState, EmptyState, NoDataHint, QueryView), Toast
    features/             one folder per area: inspector, palette, search, oracle, graph, replay,
                          timeline, trace, investigate, exposure, findings, lifecycle, overview
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
| `/investigate` | `object=<ref>` (Lens scope), `trace=<ref>` | Lens-style workbench; Trace tree and causal chain |
| `/graph` | `focus=<ref>`, `depth=1..4`, `at=<ISO>` | Cytoscape graph (overview when no focus) |
| `/replay` | `incident=<ref>` | Incident replay player |
| `/timeline` | `object=<ref>` or `scope=<ref>` (also `incident=`) | Timeline with filters, histogram, virtual list |
| `/exposure` | `blast=<ref>`, `object=<ref>`, `iam=<ref>` | Ranked exposure, asset detail, blast radius, IAM paths |
| `/ranges`, `/labs` | | Synthetic ranges, isolated labs (lifecycle actions) |
| `/evidence` | `case=<name>`, `object=<ref>` | Cases, items, custody, integrity verification |
| `/findings` | `finding=<id>` | Findings table, detail drawer, triage |
| `/products` | | Product registry, enable/disable |
| `/settings` | | Appearance, workspaces, effective config, Oracle status, versions |

`<ref>` is anything the API resolves: full IDs (`host:ws-04`), names (`WS-04`), aliases,
incidents (`INC-001`).

## Shell

* **Top bar**: brand, workspace switcher, global search (`/` focuses it), running-jobs indicator,
  command palette button, Oracle button, theme toggle.
* **Workspace scoping**: `GET /workspaces` provides the list and the server's current workspace.
  Switching calls `POST /workspaces/{name}/use` (so the CLI follows) and re-scopes the UI. Every API
  request carries `X-RAF-Workspace`; plain download links use `?workspace=` instead (links cannot
  carry headers). Query keys include the workspace, so cached data is never mixed across workspaces.
* **Global search** (`GET /search?q=`, debounced 250 ms): ARIA combobox/listbox, ↑/↓, Enter, Esc.
  Objects and incidents open the inspector; findings open the findings drawer. Enter before results
  arrive inspects the typed reference directly (the API resolves names and aliases).
* **Command palette** (Ctrl/⌘ K): navigation, `Replay Incident <name>` / `Timeline of <name>`
  (from `GET /incidents`), Create Snapshot (inline name prompt, `POST /snapshots`), Analyze Evidence
  (file picker, multipart `POST /analyze`), Switch/Create Workspace, Ask Oracle, theme, and live
  `Open <object>` results from `GET /search`. Fuzzy subsequence ranking (`features/palette/fuzzy.ts`).
* **Object inspector**: a non-modal drawer opened from anywhere (chips, graph, search, citations).
  `GET /objects/{ref}` (details, notes, activity, findings, pivots), `/relationships` and
  `/provenance`. Relationship endpoints are chips; the inspector keeps a back stack. It also shows
  events (`GET /events/{id}`) with the raw record marked as untrusted.
* **Job indicator**: polls `GET /jobs?status=RUNNING` every 3 s, lists progress and allows cancel;
  when the last job finishes every cached query is invalidated (imports change the data).
* **Oracle panel**: `POST /oracle/ask`. Answers are plain text; citations are inspector chips;
  `invalid_references` are flagged as unverified; facts and suggested commands are listed. The
  panel always states "AI output is not authoritative; verify against R$F data."
* **Empty workspaces** explain `raf demo load` and `raf analyze <file>`.

## Data flow and error model

* `api/client.ts` is the only place that calls `fetch`. Errors always become `ApiError`
  (`status`, `code`, `message`, `reason`, `hint`, `suggestions`, `details`), parsed from the API
  envelope `{"error": {...}}`; network and proxy failures become "Cannot reach the R$F API".
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

### Exposure, findings, evidence, ranges, labs, products, settings

* Exposure: ranked assets with the explainable factor breakdown (signed points, evidence),
  asset detail, blast radius (stats, risk factors, primary path as a vertical chain where every hop
  states why it is traversable, direct/indirect reach tables, propagation), IAM privilege paths.
* Findings: severity and confidence are separate, visually distinct badges ("Severity: HIGH,
  Confidence: LOW" is valid). Filters, pagination, detail drawer (explanation factors, evidence
  links, affected objects) and triage via `PATCH /findings/{id}` `{status, note}`.
* Evidence: cases, create case, items (SHA-256, size, custody count), item drawer with the custody
  chain, "Verify integrity" (`POST /evidence/cases/{case}/verify`).
* Ranges / Labs: lists, create forms, lifecycle actions behind confirmation dialogs (destroy asks for
  the name), lab backend availability (`GET /lab/status`).
* Products: registry with status badges (STABLE/BETA/ALPHA/EXPERIMENTAL/DISABLED/UNAVAILABLE),
  enable/disable switches. Settings: theme, workspaces, effective configuration with origin layer
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
* Raw source records are shown verbatim in a `<pre>` with an "untrusted input" label.
* CSP compatibility: no inline scripts (theme bootstrap is a same-origin file), no `eval`, no
  external fonts, CDNs or images. Downloads are same-origin `/api/v1/...` links.
* The UI never displays secrets: configuration secrets arrive as "set/not set" and the Oracle status
  endpoint never includes API keys.

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
| `components/States.test.tsx`, `api/client.test.ts` | ApiError rendering (message, reason, hint, suggestions, retry), error envelope parsing, unavailable vs not found, network errors, workspace header |
| `components/Badge.test.tsx` | severity and confidence badges render independently (incl. in the findings table) |
| others | fuzzy ranking, internal route validation, graph model (merge/collapse/filter/path), histogram brush math, trace tree, timeline filters, formatting, factor lists, Oracle panel, global search |

## Not implemented yet / known limitations

* **Bearer-token deployments**: when `raf serve` is bound to a non-loopback address with a token,
  the UI has no way to enter it (requests are sent without `Authorization`).
* **Products without views**: Diff (`GET /diff`), Ghost what-if models, Policy evaluation,
  Protocol, Vault, Dependency and Surface have no dedicated pages yet; they appear in the product
  registry. Analysis records (`GET /analyses`) are not listed (uploads report their job/analysis ID).
* **Replay**: client states are not verified against the server's `checkpoints[].state_hash`
  (byte-identical canonical JSON between Python and JavaScript, e.g. float formatting, would be
  needed).
* **Evidence `?object=`** narrows the items of the selected case by their `objects` field; there is
  no documented endpoint to list evidence by object across cases.
* **Shapes still being finalized** by parallel backend work (evidence, ranges, labs, lens, oracle,
  analyze, IAM paths) are read defensively; if they change, the affected views degrade to partial
  data rather than failing.
* Graph expansions/collapses and positions are client-side only (lost on reload).
* There is no end-to-end browser test suite in the repository (UI flows were smoke-tested manually
  against `raf demo load` with headless Chromium).
