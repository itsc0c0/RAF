# R$F OS

**R$F OS** is the terminal control panel of R$F: a full-screen, mouse-enabled console in the
spirit of the screens in *The Matrix* (phosphor green on black, digital rain, a boot sequence),
built in Rust with [Ratatui](https://ratatui.rs). It shows the R$F security world model page by
page (home, timeline, trace, IAM, blast radius, exposure, policy, Ghost, graph, Oracle, findings,
evidence), lets you follow any object into an inspector, and never blocks: every request runs on a
worker thread.

```
 R$F OS  v0.2.0 │ workspace default │ ● ONLINE 8ms │ api 127.0.0.1:41234           2026-10-07 14:45:44 UTC
  HOME   TIMELINE   TRACE   IAM   BLAST   EXPOSURE   POLICY   GHOST   GRAPH   ORACLE   FINDINGS   EVIDENCE
┌ ◢ PAGES ───────────────┐┌ ◈ TIMELINE ─────────────────────────────────────────────────────── 11/208 ┐
│ 1  HOME                ││ incident or object ❯ INC-001                                       / edit │
│▶2  TIMELINE            ││ R$F TIMELINE — INC-001                                                   ┃│
│ 3  TRACE               ││ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ┃│
│ …                      ││ ─── 2026-10-06 ───────────────────────────────────────────────────────── ┃│
└────────────────────────┘│›22:47:00.000  AUTH                                                       ││
┌ FOCUS ─────────────────┐│›               6x failed login for bob on VPN-01 from 203.0.113.45       ││
│ ⚑ INC-001              ││›               result=FAILURE                                            ││
│ ◉ bob                  ││                                                                          ││
│ ◎ production           ││        +5m 11s                                                           ││
│ ❯ INC-001              ││                                                                          ││
└────────────────────────┘│›22:52:11.000  AUTH                                                       ││
 ←→ pages  ↑↓ line  ⏎ inspect  / param  r reload  v graph  m rain  ? help  q quit                  2/12
```

## Build

Requirements: Rust 1.88 or newer (edition 2024), a Linux terminal. No C dependencies, no async
runtime, no TLS (R$F OS only talks to the local R$F API).

```bash
cd tui
cargo build --release          # → target/release/raf-os
```

## Run

The normal way is through the R$F CLI, which starts the API on the loopback interface and launches
the binary with the right environment:

```bash
raf tui                          # boot sequence, then HOME
raf tui --page graph --param alice
```

`raf-os` can also be started by hand against a running `raf serve`:

```bash
RAF_OS_API=http://127.0.0.1:8765/api/v1 ./target/release/raf-os
```

| Option | Meaning |
|---|---|
| `--page PAGE` | open on this page (`home`, `timeline`, `trace`, `iam`, `blast`, `exposure`, `policy`, `ghost`, `graph`, `oracle`, `findings`, `evidence`, or any page the API lists); unknown ids exit with status 2 and the list of pages |
| `--param VALUE` | parameter of the start page (sent as the page's own query name, e.g. `?ref=alice`, `?question=…`); ignored with a notice when the page takes none |
| `--api URL` | API base URL including `/api/v1` (default `$RAF_OS_API`, else `http://127.0.0.1:8765/api/v1`) |
| `--workspace NAME` | workspace, sent as `X-RAF-Workspace` (default `$RAF_OS_WORKSPACE`) |
| `--no-boot` | skip the boot sequence (also `RAF_OS_NO_BOOT=1`) |
| `--no-mouse` | do not capture the mouse (lets the terminal select text) |
| `--low-cpu` | freeze the side rain after the boot |
| `--dump PAGE [--param V] [--width N]` | print one screen as plain text and exit (`--dump inspect --param REF` prints an inspector screen) |
| `--render FILE.json [--width N]` | render a Screen JSON file as plain text, without any network |
| `--graph-list` | with `--dump`/`--render`: draw graphs as an indented list |
| `--version`, `--help` | |

Environment: `RAF_OS_TOKEN` is sent as `Authorization: Bearer …` (it is only read from the
environment and never printed), `RAF_OS_API`, `RAF_OS_WORKSPACE`, `RAF_OS_NO_BOOT`,
`RAF_OS_COLOR=256` (force the 256-color palette; truecolor is used when `COLORTERM` says
`truecolor`/`24bit`). Proxy variables (`HTTP_PROXY`, …) are deliberately ignored, and HTTP
redirects are never followed (a 3xx answer is reported as an error), so the token cannot reach
another origin.

Exit status: 0 on success, 1 for runtime/API errors (`--dump`, `--render`), 2 for usage errors
(bad flags, unknown page, no terminal for the interactive console).

## Keys

| Key | Action |
|---|---|
| `←` `→`, `h` `l`, `Tab` `Shift-Tab` | previous / next page (wraps around) |
| `1` … `9`, `0` | jump to page 1–10 |
| `↑` `↓`, `j` `k` | move the line cursor (blank lines and rules are skipped; the view follows) |
| `PgUp` `PgDn`, `Home` `End`, `g` `G`, `Space` | page / top / bottom |
| `[` `]` | scroll wide diagrams (graphs) sideways |
| `n` `N` | next / previous line with a reference |
| `Enter`, `i` | inspect the reference on the cursor line (lines marked `›` have one) |
| `/`, `s` | edit the page parameter (`Enter` loads, `Esc` cancels; `←` `→` `Home` `End` `Backspace` `Delete` `Ctrl-U`, paste) |
| `r` | reload, bypassing the cache (also retries the page list) |
| `v` | graph: layered diagram ⇄ indented list |
| `m` | digital rain column on/off (on by default from 140 columns) |
| `?` | help overlay |
| `q`, `Esc`, `Ctrl-C` | quit (`Esc` first closes popups and the editor) |
| `Ctrl-L` | repaint the whole screen |

In the inspector: `↑` `↓` `PgUp` `PgDn` `Home` `End` `n` `N` move, `Enter` opens the reference under
the cursor (nested; `Backspace`/`←` goes back), `g` `b` `t` `I` open the GRAPH, BLAST, TIMELINE or
IAM page for the inspected object, `r` reloads, `Esc`/`q` closes.

## Mouse

- Click a tab or a page in the sidebar to switch pages; click the parameter bar (or the `❯` line
  in FOCUS) to edit the parameter; click `⚑ ◉ ◎` in FOCUS to inspect the incident, subject or
  target.
- Click a content line to move the cursor there; if the line refers to an object (`›`), the
  inspector opens. In graph drawings every box (and every row of a stacked box) is clickable;
  chain connectors that carry a relationship id (`rel:…`) open the relationship; inline citations
  such as `[host:dev-01]` in Oracle answers are clickable too. A double click on an
  unmarked line opens the reference of its block.
- Wheel scrolls the content (or the inspector); `Shift`+wheel or a horizontal wheel scrolls
  sideways. Click or drag the scrollbar to jump.
- Clicking outside a popup closes it.

## Screen protocol

R$F OS renders whatever the API sends; the Python side owns the content.

| Request | Response |
|---|---|
| `GET {api}/tui/pages` | `{system, stats, focus: {incident, incident_id, subject, subject_id, target, target_id}, pages: [{id, title, param: {name, label, default} \| null}]}` |
| `GET {api}/tui/screen/{page}?{param.name}={value}` | a **Screen** (the query parameter is omitted for the page default) |
| `GET {api}/tui/inspect?ref={id or name}` | a **Screen** describing one object |
| `GET {api}/health` | `{status, version}` |

Errors are any status ≥ 400 with `{"error": {"code", "message", "reason"?, "hint"?, "suggestions"?}}`
(shown in an error panel; `r` retries). A **Screen** is
`{page, title, subtitle, param, blocks: [...], notes: [...]}`. Blocks are tagged by `t`:

| `t` | Fields | Rendering |
|---|---|---|
| `section` | `text` | blank line, bold heading, full-width `─` rule |
| `text` | `lines`, `style` | wrapped paragraphs (indentation and list items hang); inline `[type:id]` citations become clickable |
| `kv` | `rows: [{k, v, style, ref}]` | aligned label/value rows (label column = longest + 3, min 18) |
| `event` | `time, date, category, lines, severity, ref` | `22:47:00.000  AUTH` + indented detail lines; a `─── date ───` rule when the date changes |
| `gap` | `text` | dimmed, indented, with blank lines around |
| `chain` | `nodes: [{label, type, ref, note}]`, `edges: [{label, kind, note, ref}]` | centered vertical chain; `● observed` / `◌ modeled` / `◐ correlated`; an edge `ref` (`rel:…`) makes its connector clickable |
| `tree` | `root: {label, type, ref, note, style, children}`, `arrows` | `├─ │ └─` guides, or a `└─►` staircase |
| `table` | `columns, align, rows: [{cells, style, ref}]` | header, rule, rows; severity words colored; the last column truncates with `…` |
| `finding` | `severity, title, id, lines, ref` | `HIGH  id`, rule, bold title, lines |
| `compare` | `left, right, rows: [{label, before, after, verdict}]` | before → after columns, `✔`/`▼ better`, `▲ worse`, `= same` |
| `graph` | `root, nodes: [{id, label, type, criticality, highlight, parent, edge, dir}], links` | layered tree diagram (below), then `A ─LABEL→ B` for `links` |
| `diagram` | `lines, style` | preformatted, clipped |
| `citations` | `items: [{id, label, type}]` | `[id]  label`, clickable |
| `bars` | `rows: [{label, value, max, style}]` | horizontal bars with eighth blocks |
| `grid` | `columns, items: [{label, status, style}]` | `● label status` grid |
| `spacer` | | blank line |

`style` ∈ `normal dim accent ok info warn danger note`; `severity` ∈ `INFO LOW MEDIUM HIGH CRITICAL`;
`ref` is an R$F id (lines carrying one are clickable). Decoding is forward compatible: unknown
fields are ignored, optional fields may be missing or `null`, scalars are accepted where strings are
expected, and unknown or malformed blocks render as a dim `[unsupported block: …]` line instead of
failing the screen.

**Untrusted text.** Every string from the API is sanitized while it is decoded: C0/C1 control
characters (ESC included), DEL, bidi embeddings/overrides/isolates and zero-width or invisible
format characters become `�`, so nothing can move the cursor, recolor the terminal or disguise
text.

### Graph drawing

Nodes form a spanning tree (parent pointers). Each node is a box with its criticality
(`◆` critical, `▲` high, `■` medium) and type; children hang side by side under their parent on a
bus (`┌────┴────┐`), each connector carrying the relationship label and an arrow (`▼` parent →
child, `▲` child → parent). Subtree widths are computed bottom-up, so subtrees never overlap and
parents sit centered over their children. The critical path (`highlight`) is drawn with double
lines (`╔═╗ ║ ═`) in bright green; junctions mixing single and double lines get the matching glyph.

Wide fan-outs are kept readable: leaf children sharing a relationship are listed in one stacked
box (`STARTED ×12`). If the diagram is still wider than the panel, the parents with the most leaves
are compacted one by one (all their leaves in one box, each row naming its relationship), then
long rows are shortened (object names keep priority). Whatever remains wider scrolls sideways
(`[` `]`, an indicator shows the visible columns). A wide drawing opens with the root box centered
in the panel (clamped to the drawing), again after a new parameter, a resize or a layout switch;
a reload keeps where you scrolled to. `v` switches to an indented list with one line (and one
reference) per node.

## Plain-text modes

```bash
raf-os --dump timeline --param INC-001 --width 100     # fetch and print one screen
raf-os --dump inspect --param host:dev-01               # an inspector screen
raf-os --render tests/fixtures/blast.json --width 100   # render a saved Screen, no network
```

Output is the same rendering as the console, without colors. Lines fit the width, except graph
drawings, which are printed in full.

## Development

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
RAF_OS_BLESS=1 cargo test --test render_fixtures snapshots   # update the text snapshots
```

- `src/model.rs`: serde model (lenient decoders, sanitization).
- `src/render/`: blocks → styled lines + reference map + hotspots (`graph.rs`: tree layout on a
  character canvas). Pure and width-aware; shared by the console and the plain-text modes.
- `src/api.rs`: HTTP client (ureq, no proxy, timeouts) and the worker pool.
- `src/app.rs`: state, keys, mouse, caching, the event loop. `src/ui.rs`: frame layout and widgets.
  `src/boot.rs`: boot sequence. `src/rain.rs`: digital rain (seeded xorshift). `src/theme.rs`:
  palette and the 256-color fallback. `src/text.rs`: sanitizing, widths, wrapping.
- `tests/fixtures/`: real `/tui/pages`, `/tui/screen/*` and `/tui/inspect` responses of the
  Raven Industries demo (incident INC-001), plus hostile-input, forward-compatibility and graph
  fan-out fixtures; `tests/snapshots/` holds their plain-text renderings at width 100.
- Tests run without network or terminal: unit tests (renderers, sanitizer, wrapping, graph layout,
  key/mouse handling, frames on Ratatui's test backend), `--render` over every fixture,
  and `--dump` against an in-process mock API (headers, query encoding, proxy bypass, errors).

Terminal notes: the console needs at least 80×24 (smaller terminals show a notice) and a font with
box-drawing characters and half-width katakana. It uses the alternate screen, mouse capture,
bracketed paste and focus events (animations pause while the terminal is unfocused), and restores
the terminal on exit and on panic.
