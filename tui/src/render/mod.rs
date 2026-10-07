//! Screen → terminal lines.
//!
//! [`render_screen`] turns a [`Screen`] into a [`Doc`]: styled lines already wrapped to the
//! target width, plus a per-line reference map (the R$F id a line points to, used by Enter and
//! mouse clicks) and rectangular hotspots for diagrams where one line holds several clickable
//! objects (graph boxes, inline citations). Rendering is pure and width-aware; the same output
//! feeds the TUI and the plain-text `--render`/`--dump` modes.

pub mod graph;

use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

use crate::model::{
    BarsBlock, Block, ChainBlock, CitationsBlock, CompareBlock, DiagramBlock, EventBlock,
    FindingBlock, GapBlock, GraphBlock, GridBlock, KvBlock, Screen, SectionBlock, Severity,
    StyleName, TableBlock, TextBlock, TreeBlock, TreeNode,
};
use crate::text::{self, spaces, width};
use crate::theme;

/// Narrowest width the renderer lays out for (narrower requests are clamped).
pub const MIN_WIDTH: usize = 24;

/// One rendered line.
#[derive(Debug, Clone, Default)]
pub struct DocLine {
    pub line: Line<'static>,
    /// R$F object/event/finding id this line refers to (Enter / click opens the inspector).
    pub reference: Option<String>,
    /// Part of a drawing that may be wider than the viewport (scrolls horizontally).
    pub wide: bool,
}

/// A clickable rectangle in document coordinates (columns include horizontal scrolling for
/// wide lines).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hotspot {
    pub line: usize,
    pub height: usize,
    pub col: usize,
    pub width: usize,
    pub reference: String,
}

impl Hotspot {
    pub fn contains(&self, line: usize, col: usize) -> bool {
        line >= self.line
            && line < self.line + self.height
            && col >= self.col
            && col < self.col + self.width
    }
}

/// A rendered screen.
#[derive(Debug, Clone, Default)]
pub struct Doc {
    pub lines: Vec<DocLine>,
    pub hotspots: Vec<Hotspot>,
    /// Horizontal offset to start at when the document is first shown (centers the root of
    /// the first graph drawing that is wider than the render width).
    pub initial_hscroll: Option<usize>,
}

impl Doc {
    pub fn len(&self) -> usize {
        self.lines.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// Reference of a whole line (keyboard selection).
    pub fn reference(&self, line: usize) -> Option<&str> {
        self.lines.get(line)?.reference.as_deref()
    }

    /// Reference under a document position (mouse): a hotspot wins over the line reference.
    pub fn reference_at(&self, line: usize, col: usize) -> Option<&str> {
        self.hotspots
            .iter()
            .find(|h| h.contains(line, col))
            .map(|h| h.reference.as_str())
            .or_else(|| self.reference(line))
    }

    /// True when a line refers to something (directly or through a hotspot).
    pub fn is_clickable(&self, line: usize) -> bool {
        self.reference(line).is_some()
            || self
                .hotspots
                .iter()
                .any(|h| line >= h.line && line < h.line + h.height)
    }

    /// True for lines with no content worth stopping at: empty lines and plain horizontal
    /// rules (the line cursor skips them).
    pub fn is_blank(&self, line: usize) -> bool {
        self.lines.get(line).is_none_or(|l| {
            l.line.spans.iter().all(|s| {
                s.content
                    .chars()
                    .all(|c| matches!(c, ' ' | '─' | '━' | '═'))
            })
        })
    }

    /// Width of the widest horizontally scrollable line (0 when there is none).
    pub fn wide_width(&self) -> usize {
        self.lines
            .iter()
            .filter(|l| l.wide)
            .map(|l| text::line_width(&l.line))
            .max()
            .unwrap_or(0)
    }

    /// Plain text (no styles), one line per document line, trailing spaces removed.
    pub fn to_plain(&self) -> String {
        let mut out = String::new();
        for l in &self.lines {
            out.push_str(text::plain(&l.line).trim_end());
            out.push('\n');
        }
        out
    }

    /// The per-line reference map.
    pub fn refs(&self) -> Vec<Option<&str>> {
        self.lines.iter().map(|l| l.reference.as_deref()).collect()
    }
}

/// Rendering options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenderOptions {
    /// Content width in cells.
    pub width: usize,
    /// Draw graph blocks as an indented list instead of the layered diagram.
    pub graph_vertical: bool,
}

impl RenderOptions {
    pub fn new(width: usize) -> Self {
        RenderOptions {
            width,
            graph_vertical: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Prev {
    Start,
    Event,
    Gap,
    Other,
}

/// Line builder shared by all block renderers.
pub(crate) struct Out {
    pub(crate) doc: Doc,
    pub(crate) width: usize,
    graph_vertical: bool,
    prev: Prev,
    last_date: Option<String>,
}

impl Out {
    pub(crate) fn new(opts: RenderOptions) -> Out {
        Out {
            doc: Doc::default(),
            width: opts.width.max(MIN_WIDTH),
            graph_vertical: opts.graph_vertical,
            prev: Prev::Start,
            last_date: None,
        }
    }

    pub(crate) fn push(&mut self, spans: Vec<Span<'static>>, reference: Option<&str>) {
        self.doc.lines.push(DocLine {
            line: Line::from(spans),
            reference: reference.map(str::to_owned),
            wide: false,
        });
    }

    /// Pushes a line, truncating it (with `…`) to the width.
    pub(crate) fn push_fit(&mut self, spans: Vec<Span<'static>>, reference: Option<&str>) {
        let spans = text::truncate_spans(&spans, self.width);
        self.push(spans, reference);
    }

    fn push_wide(&mut self, spans: Vec<Span<'static>>, reference: Option<&str>) {
        self.doc.lines.push(DocLine {
            line: Line::from(spans),
            reference: reference.map(str::to_owned),
            wide: true,
        });
    }

    pub(crate) fn blank(&mut self) {
        self.push(Vec::new(), None);
    }

    fn blank_unless_blank(&mut self) {
        let last_blank = self
            .doc
            .lines
            .last()
            .is_none_or(|l| text::plain(&l.line).trim().is_empty());
        if !last_blank {
            self.blank();
        }
    }

    pub(crate) fn rule(&mut self, ch: char, style: Style, reference: Option<&str>) {
        let s: String = std::iter::repeat_n(ch, self.width).collect();
        self.push(vec![Span::styled(s, style)], reference);
    }

    /// Wraps `content` after `first` (first line) / `cont` (continuation lines) prefixes.
    pub(crate) fn wrap(
        &mut self,
        first: Vec<Span<'static>>,
        cont: Vec<Span<'static>>,
        content: Vec<Span<'static>>,
        reference: Option<&str>,
    ) {
        let fw = self.width.saturating_sub(text::spans_width(&first)).max(1);
        let cw = self.width.saturating_sub(text::spans_width(&cont)).max(1);
        for (i, row) in text::wrap_spans(&content, fw, cw).into_iter().enumerate() {
            let mut spans = if i == 0 { first.clone() } else { cont.clone() };
            spans.extend(row);
            self.push(spans, reference);
        }
    }

    /// A paragraph line: continuation lines are indented like the first one, or aligned with
    /// the text of a list item (`1. `, `- `, `• `).
    pub(crate) fn para(&mut self, s: &str, style: Style, reference: Option<&str>) {
        let body = s.trim_start_matches(' ');
        let lead = s.len() - body.len();
        let hang = lead + list_marker_width(body);
        let (indent, hang, body) = if hang * 2 > self.width {
            (0, 0, s)
        } else {
            (lead, hang, body)
        };
        self.wrap(
            vec![Span::raw(spaces(indent))],
            vec![Span::raw(spaces(hang))],
            vec![Span::styled(body.to_string(), style)],
            reference,
        );
    }
}

/// Width of a leading list marker (`1. `, `2) `, `- `, `* `, `• `, `· `), or 0.
pub fn list_marker_width(s: &str) -> usize {
    let bytes = s.as_bytes();
    let digits = bytes.iter().take_while(|b| b.is_ascii_digit()).count();
    if (1..=3).contains(&digits)
        && bytes.len() > digits + 1
        && matches!(bytes[digits], b'.' | b')')
        && bytes[digits + 1] == b' '
    {
        return digits + 2;
    }
    ["- ", "* ", "• ", "· ", "– "]
        .iter()
        .find(|m| s.starts_with(*m))
        .map_or(0, |m| width(m))
}

/// Renders a screen: title, `━` rule, subtitle, blocks, notes.
pub fn render_screen(screen: &Screen, opts: RenderOptions) -> Doc {
    let mut out = Out::new(opts);
    let title = if screen.title.trim().is_empty() {
        screen
            .page
            .as_deref()
            .map(|p| format!("R$F {}", p.to_uppercase()))
            .unwrap_or_else(|| "R$F".to_string())
    } else {
        screen.title.clone()
    };
    out.wrap(
        Vec::new(),
        Vec::new(),
        vec![Span::styled(title, theme::title())],
        None,
    );
    out.rule('━', theme::title_rule(), None);
    if let Some(sub) = &screen.subtitle {
        out.para(sub, theme::dim(), None);
    }
    if !screen.blocks.is_empty() {
        out.blank();
    }
    render_blocks(&mut out, &screen.blocks);
    if !screen.notes.is_empty() {
        out.blank_unless_blank();
        for note in &screen.notes {
            let style = theme::named(StyleName::Note);
            out.wrap(
                vec![Span::styled("※ ", theme::dim())],
                vec![Span::raw("  ")],
                vec![Span::styled(note.clone(), style)],
                None,
            );
        }
    }
    out.doc
}

/// Renders a list of blocks into an existing builder.
pub(crate) fn render_blocks(out: &mut Out, blocks: &[Block]) {
    for block in blocks {
        let prev = match block {
            Block::Section(b) => {
                section(out, b);
                Prev::Other
            }
            Block::Text(b) => {
                text_block(out, b);
                Prev::Other
            }
            Block::Kv(b) => {
                kv(out, b);
                Prev::Other
            }
            Block::Event(b) => {
                event(out, b);
                Prev::Event
            }
            Block::Gap(b) => {
                gap(out, b);
                Prev::Gap
            }
            Block::Chain(b) => {
                chain(out, b);
                Prev::Other
            }
            Block::Tree(b) => {
                tree(out, b);
                Prev::Other
            }
            Block::Table(b) => {
                table(out, b);
                Prev::Other
            }
            Block::Finding(b) => {
                finding(out, b);
                Prev::Other
            }
            Block::Compare(b) => {
                compare(out, b);
                Prev::Other
            }
            Block::Graph(b) => {
                graph_block(out, b);
                Prev::Other
            }
            Block::Diagram(b) => {
                diagram(out, b);
                Prev::Other
            }
            Block::Citations(b) => {
                citations(out, b);
                Prev::Other
            }
            Block::Bars(b) => {
                bars(out, b);
                Prev::Other
            }
            Block::Grid(b) => {
                grid(out, b);
                Prev::Other
            }
            Block::Spacer => {
                out.blank();
                Prev::Other
            }
            Block::Unsupported { kind, detail } => {
                let mut msg = format!("[unsupported block: {kind}");
                if let Some(d) = detail {
                    msg.push_str(" (");
                    msg.push_str(d);
                    msg.push(')');
                }
                msg.push(']');
                out.para(&msg, theme::dim(), None);
                Prev::Other
            }
        };
        out.prev = prev;
    }
}

fn section(out: &mut Out, b: &SectionBlock) {
    out.blank_unless_blank();
    out.wrap(
        Vec::new(),
        Vec::new(),
        vec![Span::styled(b.text.clone(), theme::section())],
        None,
    );
    out.rule('─', theme::rule(), None);
}

/// Finds inline object references such as `[host:dev-01]`: (start col, end col, id).
pub fn inline_refs(line: &str) -> Vec<(usize, usize, String)> {
    let mut found = Vec::new();
    let mut col = 0;
    let mut chars = line.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if c == '['
            && let Some(close) = line[i + 1..].find(']')
        {
            let inner = &line[i + 1..i + 1 + close];
            if looks_like_ref(inner) {
                let w = width(inner) + 2;
                found.push((col, col + w, inner.to_string()));
                col += w;
                // Skip past the closing bracket.
                let end = i + 1 + close;
                while chars.peek().is_some_and(|&(j, _)| j <= end) {
                    chars.next();
                }
                continue;
            }
        }
        col += width(c.encode_utf8(&mut [0u8; 4]));
    }
    found
}

fn looks_like_ref(s: &str) -> bool {
    let Some((kind, rest)) = s.split_once(':') else {
        return false;
    };
    !kind.is_empty()
        && kind.len() <= 32
        && kind
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        && kind.starts_with(|c: char| c.is_ascii_lowercase())
        && !rest.is_empty()
        && !rest
            .chars()
            .any(|c| c.is_whitespace() || c == '[' || c == ']')
}

fn text_block(out: &mut Out, b: &TextBlock) {
    let style = theme::named(b.style);
    for line in &b.lines {
        let start = out.doc.lines.len();
        out.para(line, style, None);
        // Inline citations like "[host:dev-01]" become clickable and highlighted.
        for idx in start..out.doc.lines.len() {
            let plain = text::plain(&out.doc.lines[idx].line);
            let refs = inline_refs(&plain);
            if refs.is_empty() {
                continue;
            }
            let mut spans = out.doc.lines[idx].line.spans.clone();
            for (from, to, id) in &refs {
                spans = text::restyle_range(&spans, *from, *to, theme::citation());
                out.doc.hotspots.push(Hotspot {
                    line: idx,
                    height: 1,
                    col: *from,
                    width: to - from,
                    reference: id.clone(),
                });
            }
            let dl = &mut out.doc.lines[idx];
            dl.line = Line::from(spans);
            if dl.reference.is_none() {
                dl.reference = Some(refs[0].2.clone());
            }
        }
    }
}

fn kv(out: &mut Out, b: &KvBlock) {
    let longest = b.rows.iter().map(|r| width(&r.k)).max().unwrap_or(0);
    let col = (longest + 3).max(18).min((out.width / 2).max(10));
    for row in &b.rows {
        let label = text::truncate(&row.k, col.saturating_sub(1));
        let first = vec![Span::styled(text::pad(&label, col), theme::label())];
        let cont = vec![Span::raw(spaces(col))];
        let style = match (row.style, Severity::leading(&row.v)) {
            (StyleName::Normal, Some(sev)) => theme::severity(sev),
            (s, _) => theme::value(s),
        };
        out.wrap(
            first,
            cont,
            vec![Span::styled(row.v.clone(), style)],
            row.reference.as_deref(),
        );
    }
}

fn event(out: &mut Out, b: &EventBlock) {
    if let Some(date) = &b.date
        && out.last_date.as_ref() != Some(date)
    {
        if out.last_date.is_some() || out.prev == Prev::Event || out.prev == Prev::Gap {
            out.blank_unless_blank();
        }
        let head = format!("─── {date} ");
        let rest = out.width.saturating_sub(width(&head));
        out.push(
            vec![
                Span::styled(head, theme::dim()),
                Span::styled("─".repeat(rest), theme::deep()),
            ],
            None,
        );
        out.blank();
        out.last_date = Some(date.clone());
    } else if out.prev == Prev::Event {
        out.blank();
    }
    let r = b.reference.as_deref();
    let tw = width(&b.time);
    let cat_style = match b.severity {
        Some(sev) => theme::severity(sev),
        None => theme::glow(),
    };
    let head_indent = if tw + 2 > out.width / 2 { 2 } else { tw + 2 };
    out.wrap(
        vec![Span::styled(b.time.clone(), theme::text()), Span::raw("  ")],
        vec![Span::raw(spaces(head_indent))],
        vec![Span::styled(b.category.clone(), cat_style)],
        r,
    );
    let indent = if tw + 3 > out.width / 2 { 4 } else { tw + 3 };
    for line in &b.lines {
        let pre = vec![Span::raw(spaces(indent))];
        out.wrap(
            pre.clone(),
            pre,
            vec![Span::styled(line.clone(), theme::body())],
            r,
        );
    }
}

fn gap(out: &mut Out, b: &GapBlock) {
    out.blank();
    out.wrap(
        vec![Span::raw(spaces(7))],
        vec![Span::raw(spaces(7))],
        vec![Span::styled(b.text.clone(), theme::dim())],
        None,
    );
    out.blank();
}

fn chain_kind(kind: &str) -> (&'static str, Style, &'static str) {
    match kind.trim().to_ascii_lowercase().as_str() {
        "observed" => ("●", theme::bold(), "observed"),
        "modeled" | "modelled" => ("◌", theme::dim(), "modeled"),
        "correlated" => ("◐", Style::new().fg(theme::AMBER), "correlated"),
        _ => ("·", theme::dim(), ""),
    }
}

fn chain(out: &mut Out, b: &ChainBlock) {
    if b.nodes.is_empty() {
        return;
    }
    let max_label = out.width.saturating_sub(8).max(8);
    let labels: Vec<String> = b
        .nodes
        .iter()
        .map(|n| text::truncate(&n.label, max_label))
        .collect();
    let maxw = labels.iter().map(|l| width(l)).max().unwrap_or(1).max(1);
    let margin = if maxw + 40 <= out.width { 6 } else { 2 };
    let axis = margin + (maxw - 1) / 2;
    let edge_w = b
        .edges
        .iter()
        .map(|e| width(&e.label))
        .max()
        .unwrap_or(0)
        .min(out.width / 3);
    for (i, node) in b.nodes.iter().enumerate() {
        let lw = width(&labels[i]);
        let start = axis.saturating_sub(lw.saturating_sub(1) / 2);
        let mut spans = vec![
            Span::raw(spaces(start)),
            Span::styled(labels[i].clone(), theme::glow()),
        ];
        if let Some(kind) = &node.kind {
            spans.push(Span::styled(format!(" [{kind}]"), theme::dim()));
        }
        if let Some(note) = &node.note {
            spans.push(Span::styled(format!(" · {note}"), theme::dim()));
        }
        out.push_fit(spans, node.reference.as_deref());
        if i + 1 == b.nodes.len() {
            break;
        }
        let edge = b.edges.get(i);
        let (marker, style, kind_word) =
            edge.map_or(("", theme::dim(), ""), |e| chain_kind(&e.kind));
        // A relationship id makes the whole connector (│, annotation, ▼) inspectable.
        let edge_ref = edge.and_then(|e| e.reference.as_deref());
        out.push(
            vec![Span::raw(spaces(axis)), Span::styled("│", style)],
            edge_ref,
        );
        if let Some(e) = edge {
            let kind_text = if kind_word.is_empty() {
                e.kind.clone()
            } else {
                kind_word.to_string()
            };
            let mut content = vec![
                Span::styled(text::pad(&e.label, edge_w), theme::body()),
                Span::raw("   "),
            ];
            if !marker.is_empty() || !kind_text.is_empty() {
                content.push(Span::styled(format!("{marker} {kind_text}"), style));
            }
            if let Some(note) = &e.note {
                content.push(Span::styled(format!(" {note}"), theme::dim()));
            }
            let first = vec![Span::raw(spaces(axis)), Span::styled("│ ", style)];
            let cont = vec![
                Span::raw(spaces(axis)),
                Span::styled("│ ", style),
                Span::raw(spaces(edge_w + 3)),
            ];
            out.wrap(first, cont, content, edge_ref);
        }
        out.push(
            vec![Span::raw(spaces(axis)), Span::styled("▼", style)],
            edge_ref,
        );
    }
}

fn tree(out: &mut Out, b: &TreeBlock) {
    tree_node(out, &b.root, String::new(), String::new(), b.arrows, true);
}

fn tree_node(
    out: &mut Out,
    node: &TreeNode,
    lead: String,
    child_lead: String,
    arrows: bool,
    root: bool,
) {
    let label_style = match node.style {
        Some(s) if s != StyleName::Normal => theme::value(s),
        _ if root => theme::glow(),
        _ => theme::text(),
    };
    let mut spans = Vec::new();
    if !lead.is_empty() {
        // Guides dim, the arrow head brighter.
        if let Some(stripped) = lead.strip_suffix("► ") {
            spans.push(Span::styled(stripped.to_string(), theme::dim()));
            spans.push(Span::styled("► ", theme::text()));
        } else {
            spans.push(Span::styled(lead.clone(), theme::dim()));
        }
    }
    spans.push(Span::styled(node.label.clone(), label_style));
    if let Some(kind) = &node.kind {
        spans.push(Span::styled(format!("  [{kind}]"), theme::dim()));
    }
    if let Some(note) = &node.note {
        spans.push(Span::styled(format!("  {note}"), theme::dim()));
    }
    out.push_fit(spans, node.reference.as_deref());
    let n = node.children.len();
    for (i, child) in node.children.iter().enumerate() {
        let last = i + 1 == n;
        let (conn, cont) = match (arrows, last) {
            (true, true) => (" └─► ", "     "),
            (true, false) => (" ├─► ", " │   "),
            (false, true) => ("└─ ", "   "),
            (false, false) => ("├─ ", "│  "),
        };
        tree_node(
            out,
            child,
            format!("{child_lead}{conn}"),
            format!("{child_lead}{cont}"),
            arrows,
            false,
        );
    }
}

/// Fits natural column widths into `avail` cells: the last column shrinks first, then the
/// widest columns, never below 3 cells.
pub fn fit_columns(natural: &[usize], avail: usize) -> Vec<usize> {
    let mut w = natural.to_vec();
    let total = |w: &[usize]| w.iter().sum::<usize>();
    if w.is_empty() || total(&w) <= avail {
        return w;
    }
    let last = w.len() - 1;
    let min_last = natural[last].min(12);
    let excess = total(&w) - avail;
    let shrink = excess.min(w[last].saturating_sub(min_last));
    w[last] -= shrink;
    while total(&w) > avail {
        let (i, &mx) = w
            .iter()
            .enumerate()
            .rev()
            .max_by_key(|&(_, &x)| x)
            .expect("non-empty");
        if mx <= 3 {
            break;
        }
        w[i] -= 1;
    }
    w
}

fn align_cell(s: &str, w: usize, align: &str) -> String {
    let s = text::truncate(s, w);
    match align {
        "r" | "right" => text::pad_left(&s, w),
        "c" | "center" => text::center(&s, w),
        _ => text::pad(&s, w),
    }
}

fn table(out: &mut Out, b: &TableBlock) {
    let ncols = b
        .rows
        .iter()
        .map(|r| r.cells.len())
        .chain(std::iter::once(b.columns.len()))
        .max()
        .unwrap_or(0);
    if ncols == 0 {
        return;
    }
    let cell = |cells: &[String], i: usize| cells.get(i).cloned().unwrap_or_default();
    let natural: Vec<usize> = (0..ncols)
        .map(|i| {
            b.rows
                .iter()
                .map(|r| width(&cell(&r.cells, i)))
                .chain(std::iter::once(width(&cell(&b.columns, i))))
                .max()
                .unwrap_or(0)
                .max(1)
        })
        .collect();
    // Generous gaps (3, as in the CLI) unless that would squeeze the last column, which is
    // the one that gets truncated.
    let last_natural = natural[ncols - 1];
    let others: usize = natural[..ncols - 1].iter().sum();
    let room = |g: usize| out.width.saturating_sub(others + g * (ncols - 1));
    let gap = if room(3) >= last_natural.min(30) {
        3
    } else if room(2) >= last_natural.min(20) {
        2
    } else {
        1
    };
    let widths = fit_columns(&natural, out.width.saturating_sub(gap * (ncols - 1)));
    let align = |i: usize| b.align.get(i).map(String::as_str).unwrap_or("l");
    let row_spans = |cells: &[String], style_for: &dyn Fn(usize, &str) -> Style| {
        let mut spans = Vec::new();
        for (i, w) in widths.iter().enumerate() {
            let c = cell(cells, i);
            let last = i + 1 == ncols;
            let mut s = align_cell(&c, *w, align(i));
            if last {
                s = s.trim_end().to_string();
            }
            spans.push(Span::styled(s, style_for(i, &c)));
            if !last {
                spans.push(Span::raw(spaces(gap)));
            }
        }
        spans
    };
    if !b.columns.is_empty() {
        out.push(row_spans(&b.columns, &|_, _| theme::glow()), None);
        out.rule('─', theme::rule(), None);
    }
    for row in &b.rows {
        let base = theme::named(row.style);
        let spans = row_spans(&row.cells, &|_, c| match Severity::leading(c) {
            Some(sev) => theme::severity(sev),
            None => base,
        });
        out.push(spans, row.reference.as_deref());
    }
}

fn finding(out: &mut Out, b: &FindingBlock) {
    let r = b.reference.as_deref();
    let (sev_word, sev_style) = match b.severity {
        Some(s) => (s.label(), theme::severity(s)),
        None => ("FINDING", theme::glow()),
    };
    out.wrap(
        vec![Span::styled(sev_word, sev_style), Span::raw("  ")],
        vec![Span::raw(spaces(width(sev_word) + 2))],
        vec![Span::styled(b.id.clone(), theme::dim())],
        r,
    );
    out.rule('─', theme::rule(), r);
    out.wrap(
        Vec::new(),
        Vec::new(),
        vec![Span::styled(b.title.clone(), theme::glow())],
        r,
    );
    for line in &b.lines {
        out.para(line, theme::body(), r);
    }
    out.blank();
}

fn verdict(v: &str, before: &str, after: &str) -> (String, Style) {
    let num = |s: &str| s.trim().replace(',', "").parse::<f64>().ok();
    match v.trim().to_ascii_lowercase().as_str() {
        "better" => {
            let mark = match (num(before), num(after)) {
                (Some(a), Some(b)) if b < a => "▼",
                _ => "✔",
            };
            (format!("{mark} better"), theme::bold())
        }
        "worse" => (
            "▲ worse".to_string(),
            Style::new().fg(theme::RED).add_modifier(Modifier::BOLD),
        ),
        "same" => ("= same".to_string(), theme::dim()),
        _ => (String::new(), theme::text()),
    }
}

fn compare(out: &mut Out, b: &CompareBlock) {
    let w = out.width;
    let longest = b.rows.iter().map(|r| width(&r.label)).max().unwrap_or(0);
    let label_w = (longest + 3).max(18).min(w * 2 / 5);
    // Narrow panels keep only the verdict symbol.
    let wordy = w >= 60;
    let verdict_w = if wordy { 9 } else { 2 };
    let arrow = " → ";
    let rest = w.saturating_sub(label_w + verdict_w + width(arrow));
    let before_natural = b
        .rows
        .iter()
        .map(|r| width(&r.before))
        .chain(std::iter::once(width(&b.left)))
        .max()
        .unwrap_or(0);
    let before_w = (before_natural + 1).min(rest / 2).max(1);
    let after_room = rest.saturating_sub(before_w).max(1);
    // The verdict column follows the widest "after" value of the rows that carry a verdict;
    // rows without one (info) may run on into the verdict column.
    let after_natural = b
        .rows
        .iter()
        .filter(|r| !verdict(&r.verdict, &r.before, &r.after).0.is_empty())
        .map(|r| width(&r.after))
        .chain(std::iter::once(width(&b.right)))
        .max()
        .unwrap_or(0);
    let after_w = (after_natural + 2).min(after_room);
    out.push_fit(
        vec![
            Span::raw(spaces(label_w)),
            Span::styled(text::fit(&b.left, before_w), theme::glow()),
            Span::raw(spaces(width(arrow))),
            Span::styled(text::truncate(&b.right, after_room), theme::glow()),
        ],
        None,
    );
    out.rule('━', theme::title_rule(), None);
    for row in &b.rows {
        let (mut mark, mark_style) = verdict(&row.verdict, &row.before, &row.after);
        if !wordy {
            mark = mark.chars().take(1).collect();
        }
        let after_style = match row.verdict.trim().to_ascii_lowercase().as_str() {
            "better" => theme::bold(),
            "worse" => Style::new().fg(theme::RED).add_modifier(Modifier::BOLD),
            "same" => theme::dim(),
            _ => theme::text(),
        };
        let has_before = !row.before.trim().is_empty();
        let mut spans = vec![
            Span::styled(
                text::fit(&row.label, label_w.saturating_sub(1)),
                theme::text(),
            ),
            Span::raw(" "),
            Span::styled(text::fit(&row.before, before_w), theme::body()),
            Span::styled(if has_before { arrow } else { "   " }, theme::dim()),
        ];
        if mark.is_empty() {
            let after = text::truncate(&row.after, after_room + verdict_w);
            spans.push(Span::styled(after, after_style));
        } else {
            let after = text::truncate(&row.after, after_w);
            spans.push(Span::styled(text::pad(&after, after_w), after_style));
            spans.push(Span::styled(mark, mark_style));
        }
        out.push_fit(spans, None);
    }
}

fn diagram(out: &mut Out, b: &DiagramBlock) {
    let style = theme::value(b.style);
    for line in &b.lines {
        let clipped = text::clip(line, out.width);
        out.push(vec![Span::styled(clipped, style)], None);
    }
}

fn citations(out: &mut Out, b: &CitationsBlock) {
    let idw = b
        .items
        .iter()
        .map(|c| width(&c.id) + 2)
        .max()
        .unwrap_or(0)
        .min(out.width / 2);
    for item in &b.items {
        let id = text::truncate(&format!("[{}]", item.id), idw);
        let label = if item.label.is_empty() {
            item.kind.clone().unwrap_or_default()
        } else {
            item.label.clone()
        };
        out.push_fit(
            vec![
                Span::styled(text::pad(&id, idw), theme::citation()),
                Span::raw("  "),
                Span::styled(label, theme::text()),
            ],
            if item.id.is_empty() {
                None
            } else {
                Some(&item.id)
            },
        );
    }
}

/// Number formatting for bars: integers without decimals, otherwise one decimal.
pub fn fmt_num(v: f64) -> String {
    if (v - v.round()).abs() < 1e-9 && v.abs() < 1e15 {
        format!("{}", v.round() as i64)
    } else {
        format!("{v:.1}")
    }
}

/// A horizontal bar of `frac` (0..=1) of `cells` cells using eighth blocks.
pub fn bar_string(frac: f64, cells: usize) -> String {
    const PARTIAL: [&str; 8] = ["", "▏", "▎", "▍", "▌", "▋", "▊", "▉"];
    let frac = if frac.is_finite() {
        frac.clamp(0.0, 1.0)
    } else {
        0.0
    };
    let eighths = (frac * cells as f64 * 8.0).round() as usize;
    let mut s = "█".repeat(eighths / 8);
    s.push_str(PARTIAL[eighths % 8]);
    if s.is_empty() && frac > 0.0 {
        s.push('▏');
    }
    s
}

fn bars(out: &mut Out, b: &BarsBlock) {
    let label_w =
        (b.rows.iter().map(|r| width(&r.label)).max().unwrap_or(0) + 2).min(out.width / 3);
    let values: Vec<String> = b.rows.iter().map(|r| fmt_num(r.value)).collect();
    let val_w = values.iter().map(|v| width(v)).max().unwrap_or(1);
    let global_max = b
        .rows
        .iter()
        .map(|r| r.max.unwrap_or(r.value))
        .fold(0.0f64, f64::max);
    let bar_w = out.width.saturating_sub(label_w + val_w + 2).clamp(4, 48);
    for (row, val) in b.rows.iter().zip(values) {
        let max = row.max.filter(|m| *m > 0.0).unwrap_or(global_max);
        let frac = if max > 0.0 { row.value / max } else { 0.0 };
        let bar = bar_string(frac, bar_w);
        let track = bar_w.saturating_sub(width(&bar));
        let style = theme::value(row.style);
        out.push(
            vec![
                Span::styled(text::fit(&row.label, label_w), theme::label()),
                Span::styled(bar, style),
                Span::styled("·".repeat(track), theme::deep()),
                Span::raw("  "),
                Span::styled(text::pad_left(&val, val_w), theme::text()),
            ],
            None,
        );
    }
}

fn grid(out: &mut Out, b: &GridBlock) {
    if b.items.is_empty() {
        return;
    }
    let label_w = b.items.iter().map(|i| width(&i.label)).max().unwrap_or(0);
    let status_w = b.items.iter().map(|i| width(&i.status)).max().unwrap_or(0);
    let need = 2 + label_w + 1 + status_w + 3;
    let requested = b.columns.unwrap_or(4).clamp(1, 12) as usize;
    let cols = requested.min((out.width / need.max(1)).max(1));
    let cell_w = out.width / cols;
    let lw = label_w.min(cell_w.saturating_sub(3 + status_w.min(cell_w / 3)).max(4));
    for chunk in b.items.chunks(cols) {
        let mut spans = Vec::new();
        for (i, item) in chunk.iter().enumerate() {
            let dot_style = theme::value(item.style);
            let status = text::truncate(&item.status, cell_w.saturating_sub(lw + 3));
            let used = 2 + lw + 1 + width(&status);
            spans.push(Span::styled("● ", dot_style));
            spans.push(Span::styled(text::fit(&item.label, lw), theme::text()));
            spans.push(Span::raw(" "));
            spans.push(Span::styled(status, theme::dim()));
            if i + 1 < chunk.len() {
                spans.push(Span::raw(spaces(cell_w.saturating_sub(used))));
            }
        }
        out.push(spans, None);
    }
}

fn graph_block(out: &mut Out, b: &GraphBlock) {
    if b.nodes.is_empty() {
        out.para("(empty graph)", theme::dim(), None);
        return;
    }
    let words: [&str; 6] = if out.width >= 76 {
        [
            " critical  ",
            " high  ",
            " medium   ",
            " critical path   ",
            " outgoing  ",
            " incoming",
        ]
    } else {
        [" crit ", " high ", " med  ", " path  ", " out ", " in"]
    };
    let legend = vec![
        Span::styled("◆", theme::severity(Severity::Critical)),
        Span::styled(words[0], theme::dim()),
        Span::styled("▲", theme::severity(Severity::High)),
        Span::styled(words[1], theme::dim()),
        Span::styled("■", theme::severity(Severity::Medium)),
        Span::styled(words[2], theme::dim()),
        Span::styled("═══", theme::bold()),
        Span::styled(words[3], theme::dim()),
        Span::styled("▼", theme::text()),
        Span::styled(words[4], theme::dim()),
        Span::styled("▲", theme::text()),
        Span::styled(words[5], theme::dim()),
    ];
    out.push_fit(legend, None);
    out.blank();
    let tree = graph::build_tree(b);
    if out.graph_vertical {
        for (spans, reference) in graph::vertical_lines(b, &tree) {
            out.push_fit(spans, reference.as_deref());
        }
    } else {
        let layout = graph::layout(b, &tree, out.width);
        if layout.width > out.width && out.doc.initial_hscroll.is_none() {
            out.doc.initial_hscroll = Some(graph::initial_offset(&layout, out.width));
        }
        let drawing = graph::draw(b, &layout);
        let offset = if drawing.width < out.width {
            (out.width - drawing.width) / 2
        } else {
            0
        };
        let base = out.doc.lines.len();
        for (row, reference) in drawing.rows.into_iter().zip(drawing.row_refs) {
            let mut spans = Vec::with_capacity(row.len() + 1);
            if offset > 0 && !row.is_empty() {
                spans.push(Span::raw(spaces(offset)));
            }
            spans.extend(row);
            out.push_wide(spans, reference.as_deref());
        }
        for spot in drawing.hotspots {
            out.doc.hotspots.push(Hotspot {
                line: base + spot.line,
                col: offset + spot.col,
                ..spot
            });
        }
    }
    if tree.dropped > 0 {
        out.blank();
        out.para(
            &format!("+{} more node(s) not drawn", tree.dropped),
            theme::dim(),
            None,
        );
    }
    if !b.links.is_empty() {
        out.blank();
        out.push(
            vec![Span::styled(
                "OTHER RELATIONSHIPS",
                theme::dim().add_modifier(Modifier::BOLD),
            )],
            None,
        );
        let label_of = |id: &str| {
            b.nodes
                .iter()
                .find(|n| n.id == id)
                .map(|n| n.display_label().to_string())
                .unwrap_or_else(|| id.to_string())
        };
        for link in &b.links {
            let src = text::truncate(&label_of(&link.source), 32);
            let dst = text::truncate(&label_of(&link.target), 32);
            let reference = if link.target.is_empty() {
                None
            } else {
                Some(link.target.as_str())
            };
            out.push_fit(
                vec![
                    Span::raw("  "),
                    Span::styled(src, theme::text()),
                    Span::styled(format!(" ─{}→ ", link.label), theme::dim()),
                    Span::styled(dst, theme::text()),
                ],
                reference,
            );
        }
    }
}

/// A full-panel message (errors, offline state): a framed title, key/value details and hints.
pub fn message_doc(
    title: &str,
    title_style: Style,
    rows: &[(String, String)],
    hints: &[String],
    cols: usize,
) -> Doc {
    let mut out = Out::new(RenderOptions::new(cols));
    let inner = (out.width - 2).min(72);
    let border = title_style.remove_modifier(Modifier::BOLD);
    out.push(
        vec![Span::styled(format!("╔{}╗", "═".repeat(inner)), border)],
        None,
    );
    let t = text::truncate(title, inner.saturating_sub(4));
    out.push(
        vec![
            Span::styled("║  ", border),
            Span::styled(text::pad(&t, inner - 2), title_style),
            Span::styled("║", border),
        ],
        None,
    );
    out.push(
        vec![Span::styled(format!("╚{}╝", "═".repeat(inner)), border)],
        None,
    );
    out.blank();
    let longest = rows.iter().map(|(k, _)| width(k)).max().unwrap_or(0);
    let col = (longest + 3).clamp(10, 18);
    for (k, v) in rows {
        out.wrap(
            vec![Span::styled(text::fit(k, col), theme::label())],
            vec![Span::raw(spaces(col))],
            vec![Span::styled(v.clone(), theme::text())],
            None,
        );
    }
    if !hints.is_empty() {
        out.blank();
        for h in hints {
            out.wrap(
                vec![Span::styled("› ", theme::text())],
                vec![Span::raw("  ")],
                vec![Span::styled(h.clone(), theme::body())],
                None,
            );
        }
    }
    out.doc
}

#[cfg(test)]
mod tests;
