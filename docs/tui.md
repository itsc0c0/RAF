# R$F OS (`raf tui`)

R$F OS is the full-screen terminal control panel of R$F: one keyboard- and mouse-driven screen per
product story (the incident timeline, the attack trace, IAM, blast radius, exposure, policy, a Ghost
containment experiment, the graph, Oracle, findings and evidence), with a boot sequence and a
digital-rain look. Every name and number on every page comes from the same services the CLI and the
API use; the panel only lays them out.

```text
raf tui                              open on HOME (boot sequence, then the panel)
raf tui --page blast --param alice   open BLAST for alice
raf tui --no-boot --no-mouse         skip the boot animation; keep the terminal's own mouse selection
raf tui --dump trace --width 120     print one page as plain text and exit (no terminal UI)
```

It runs on Linux terminals (developed and tested there; macOS terminals should work through
crossterm but are not tested; Windows is not supported yet). It needs a UTF-8 locale and a font
with box-drawing characters; 256 colors or true color look best. The minimum size is 80×24.

## Building it

The panel is the `raf-os` binary (Rust + [Ratatui](https://ratatui.rs)) in `tui/`. Build it once:

```bash
cargo build --release --manifest-path tui/Cargo.toml     # or: ./scripts/bootstrap (when cargo is installed)
```

`raf tui` looks for the binary in `RAF_OS_BIN`, `tui/target/release/`, `tui/target/debug/`, next
to the Python interpreter (the virtual environment's `bin/`) and on `PATH`. Without it, `raf tui`
explains how to build it and exits with status 6. Everything else in R$F works without Rust.

## How it works

```text
raf tui
  │  starts the R$F API inside the raf process: 127.0.0.1, a random free port,
  │  a one-time random bearer token (never printed, never written to disk)
  ▼
raf-os (child process; RAF_OS_API, RAF_OS_TOKEN, RAF_OS_WORKSPACE in its environment)
  │  GET /api/v1/tui/pages            system, statistics, focus, page list
  │  GET /api/v1/tui/screen/<page>    one page as a screen document
  │  GET /api/v1/tui/inspect?ref=     the inspector popup
  ▼
draws the screen documents (raf-os never computes security results itself)
```

* **Loopback only.** The API listens on 127.0.0.1 for the lifetime of the panel and requires the
  token; it stops when the panel exits. `RAF_API_TOKEN` is not passed to the panel.
* **Read-only.** No page changes the workspace: Policy and Exposure are analyzed without recording
  findings, and the Ghost page runs its experiment in an unsaved in-memory model ("No production
  changes have been made"). `raf tui` records one audit entry (`tui.session`).
* **Untrusted text.** Imported data reaches the screen as data: the panel replaces control
  characters, C1 controls, bidirectional overrides and zero-width characters before drawing and
  never writes escape sequences from data.
* **Performance.** Pages are computed on demand (on the Raven demo each takes well under a second;
  on a workspace with 150,000 events and 200,000 relationships the slowest, IAM and Ghost, take
  about one second). The panel caches each page for the session; `r` reloads.

## Pages

Pages open on one *focus* by default: the most severe incident, the identity at the center of its
most important path (the same path Oracle explains) and the most critical asset that identity can
control. On the demo that is INC-001, bob and production. Press `/` on a page to choose another
subject.

| # | Page | What it shows | Parameter (`/`) |
|---|---|---|---|
| 1 | HOME | version, products online, the pipeline RAW LOGS → INGEST → SECURITY WORLD MODEL → products → ORACLE with live counts, the product grid, open findings by severity, incidents, the focus | — |
| 2 | TIMELINE | the incident replay: events with categories, repeated steps collapsed (`6x`), results, the gaps between events, a summary (events, telemetry sources, identities and assets, window) | incident or object (default: the focus incident) |
| 3 | TRACE | the attack chain from the outside address through the gateway to the identity and on to the critical asset; observed edges (backed by incident events, with time and event type) versus modeled edges; corroboration and the evidence event IDs | incident or object |
| 4 | IAM | identity, memberships, roles, the inherited access tree, the credential-derived path (e.g. bob → DEV-01 → .env → DEPLOY_TOKEN → svc-deploy) and what it leads to, IAM findings, the shortest critical path | identity |
| 5 | BLAST | starting assumption, reachability counts, the critical path as a `└─►` staircase, the `raf-risk/1.0` assessment and its factors, the primary reason, and the reminder that this is modeled reachability | identity or host |
| 6 | EXPOSURE | every asset's exposure score, level and primary factors; the "interesting" asset (high CVSS, low exposure, and why); one asset's details | asset (optional) |
| 7 | POLICY | rules analyzed, findings by severity, each finding with its rules (ALLOW/DENY, source, destination, port) and the reason | — |
| 8 | GHOST | a containment experiment: the minimum set of relationships to remove so the identity no longer controls the target, the proposed changes, and BEFORE/AFTER (reachability through access paths and through exploitable vulnerabilities, blast score, critical assets, privileged identities, workspace attack paths) — never saved | `subject → target` |
| 9 | GRAPH | the neighborhood (2 hops, up to 40 drawn nodes) as a layered diagram of boxes and labeled arrows with the critical path highlighted, the remaining links, the critical path as a chain | object |
| 10 | ORACLE | Oracle's answer with validated citations (clickable), warnings and suggested commands (never executed) | question |
| 11 | FINDINGS | open and acknowledged findings of every product with severity and confidence | product or minimum severity |
| 12 | EVIDENCE | an evidence case: items, SHA-256, read-only status and integrity verification | case |

Lines that carry a reference (an object, relationship, event or finding) are clickable: the
inspector shows the object's metadata, relationships and findings, a relationship's endpoints, what
it means for propagation and its provenance, an event's fields (its message labelled as imported,
untrusted text) or a finding's explanation.

## Keys and mouse

| Key | Action |
|---|---|
| `←` `→`, `h` `l`, `Tab` `Shift+Tab` | previous / next page |
| `1`–`9`, `0` | jump to page 1–10 |
| `↑` `↓`, `j` `k` | move the line cursor (the content scrolls with it) |
| `PgUp` `PgDn` (`Space`), `Home` `End` (`g` `G`) | scroll by a page, to the top, to the end |
| `[` `]` | scroll a wide graph sideways |
| `n` `N` | jump to the next / previous line with a reference |
| `/` or `s` | edit the page parameter (Enter loads, Esc cancels) |
| `Enter` or `i` | inspect the reference on the cursor line |
| `r` | reload the page from the API |
| `v` | graph: switch between the diagram and a compact indented layout |
| `m` | toggle the digital-rain column |
| `?` | help |
| `Ctrl+L` | repaint the screen |
| `q`, `Esc`, `Ctrl+C` | close a popup, or quit |

In the inspector: `Enter` follows the reference on the cursor line, `Backspace` (or `←`) goes back,
`g` opens GRAPH, `b` BLAST, `t` TIMELINE and `I` IAM for the inspected object; `Esc`, `q` or a
click outside closes it. While editing a parameter: `Enter` loads, `Esc` cancels, `←` `→` move,
`Backspace` deletes, `Ctrl+U` clears.

Mouse: click a tab or a sidebar entry to switch pages, click a line to move the cursor, click a
line with a reference (or double-click) to inspect it, wheel to scroll (Shift+wheel sideways), click
the parameter box to edit it. Start with `--no-mouse` to keep the terminal's own text selection
(most terminals also select text with Shift held while mouse capture is on).

The binary's own options (`--api`, `--workspace`, `--low-cpu`, `--graph-list`, …), its environment
variables and the details of the graph layout are in [tui/README.md](../tui/README.md).

## Plain-text output

`raf tui --dump PAGE [--param VALUE] [--width N]` prints one page without the terminal UI, the same
layout without colors (handy for reports, tickets and tests). `raf-os --render FILE.json` renders a
saved screen document without any network access.

## Screen protocol

Each page is a JSON *screen document*; the full schema is enforced by
`tests/integration/test_tui_screens.py` and every R$F OS page is a sequence of typed blocks:

```json
{"page": "trace", "title": "R$F TRACE — INC-001", "subtitle": "entry → production",
 "param": "INC-001", "blocks": [{"t": "chain", "nodes": [...], "edges": [...]}, ...], "notes": []}
```

| Block (`t`) | Fields |
|---|---|
| `section` | `text` (a heading with a rule) |
| `text` | `lines`, `style` |
| `kv` | `rows: [{k, v, style, ref}]` (aligned label/value rows) |
| `event` | `time` (`22:52:11.000`), `date`, `category` (`AUTH`, `NETWORK`, …), `lines`, `severity`, `ref` |
| `gap` | `text` (`+5m 11s`, the time between two events; gaps under a second are not drawn) |
| `chain` | `nodes: [{label, type, ref, note}]`, `edges: [{label, kind: observed\|modeled\|correlated, note, ref}]` (one edge fewer than nodes; an edge's `ref` is its relationship) |
| `tree` | `root: {label, type, ref, note, style, children}`, `arrows` (the `└─►` staircase) |
| `table` | `columns`, `align` (`l`/`r`/`c`), `rows: [{cells, style, ref}]` |
| `finding` | `severity`, `title`, `id`, `lines`, `ref` |
| `compare` | `left`, `right`, `rows: [{label, before, after, verdict: better\|worse\|same\|info}]` |
| `graph` | `root`, `nodes: [{id, label, type, criticality, highlight, parent, edge, dir: in\|out}]` (a spanning tree: the root first, every parent before its children), `links: [{source, target, label}]` (the other relationships) |
| `diagram` | `lines`, `style` (preformatted) |
| `citations` | `items: [{id, label, type}]` |
| `bars` | `rows: [{label, value, max, style}]` |
| `grid` | `columns`, `items: [{label, status, style}]` |
| `spacer` | — |

`style` is one of `normal`, `dim`, `accent`, `ok`, `info`, `warn`, `danger`, `note`; `severity` is
`INFO` … `CRITICAL`; `ref` is an R$F reference or null. Optional values are `null`, never missing;
renderers ignore unknown fields and show unknown block types as a placeholder, so the protocol can
grow. The routes are listed in [api.md](api.md#rf-os-screens); errors use the API's error document.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `R$F OS (the terminal panel) is not built yet.` | `cargo build --release --manifest-path tui/Cargo.toml`, or point `RAF_OS_BIN` at the binary |
| `raf tui needs an interactive terminal.` | run it in a terminal, or use `raf tui --dump PAGE` |
| boxes or arrows look broken | use a UTF-8 locale (`LANG=C.UTF-8`) and a font with box-drawing characters |
| the mouse does not work in tmux | `set -g mouse on` in tmux, or use the keyboard |
| a page shows an error panel | the page's product may be disabled (`raf products`) or the parameter does not resolve; press `/` to change it, `r` to retry |
| "terminal too small" | enlarge the window to at least 80×24 |

## Limitations

* Pages are views; changes (saving a Ghost model, recording findings, triage) are made with the CLI,
  the API or the web workbench.
* The graph page draws up to 40 nodes of the 2-hop neighborhood; use `raf graph` or the web
  workbench for larger views.
* The panel talks only to the API started by `raf tui`; connecting it to a remote `raf serve` is
  not supported.
