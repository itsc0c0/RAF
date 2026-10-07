//! Graph blocks: a top-down layered tree diagram drawn on a character canvas.
//!
//! The nodes of a graph block form a spanning tree (parent pointers). Each node becomes a box
//! (`┌──────────┐ │ ◆ DEV-01 │ │   host   │ └────┬─────┘`); children hang side by side under
//! their parent, joined by a bus (`┌────┴────┐`), a stem with the relationship label and an
//! arrow (`▼` for parent → child, `▲` for child → parent). Subtree widths are computed bottom-up
//! so subtrees never overlap; a parent is centered over its children. The critical path
//! (highlighted nodes) uses double lines (`╔═╗ ║ ═`) in bright green, everything else single
//! lines in dim green. Junctions are resolved from the four arms of each cell, so mixed
//! single/double crossings get the right glyph (`╤ ╪ ╨ ...`).
//!
//! Wide fan-outs are tamed by *stacking*: leaf children that share a relationship (for example
//! twelve `STARTED` processes) are listed in one box under a single connector (`STARTED ×12`).
//! When even that is wider than the viewport, a compact pass merges all leaves of a parent into
//! one stack. Highlighted nodes are never stacked.

use std::collections::HashMap;

use ratatui::style::{Modifier, Style};
use ratatui::text::Span;
use unicode_segmentation::UnicodeSegmentation;

use crate::model::{GraphBlock, GraphNode};
use crate::render::Hotspot;
use crate::text::{self, grapheme_width, width};
use crate::theme;

/// Height of a node box.
pub const BOX_H: usize = 4;
/// Rows from one level to the next: box, bus, stem, label, arrow.
pub const LEVEL_H: usize = BOX_H + 4;
/// Columns between sibling subtrees.
pub const GAP: usize = 2;
/// Columns between separate trees of a forest.
pub const ROOT_GAP: usize = 4;
/// Longest node label drawn in a box.
pub const MAX_LABEL: usize = 22;
/// Longest relationship label drawn on a connector.
pub const MAX_EDGE: usize = 20;
/// Most nodes drawn (the rest are counted in [`Tree::dropped`]).
pub const MAX_NODES: usize = 400;
/// Most rows listed in a stack box.
pub const STACK_ROWS: usize = 12;
/// More children than this and pairs of same-relationship leaves are stacked too.
const CROWDED: usize = 6;

const UP: u8 = 1;
const DOWN: u8 = 2;
const LEFT: u8 = 4;
const RIGHT: u8 = 8;

/// The spanning tree of a graph block (indices into `block.nodes`).
#[derive(Debug, Clone, Default)]
pub struct Tree {
    pub roots: Vec<usize>,
    pub kids: Vec<Vec<usize>>,
    pub depth: Vec<usize>,
    /// Nodes not drawn (duplicates excluded): beyond [`MAX_NODES`].
    pub dropped: usize,
}

/// Builds the spanning tree: the declared root first, then parentless nodes; unknown parents
/// make a node a root; cycles are broken; duplicate ids are ignored.
pub fn build_tree(b: &GraphBlock) -> Tree {
    let n = b.nodes.len();
    let mut index: HashMap<&str, usize> = HashMap::new();
    let mut dup = vec![false; n];
    for (i, node) in b.nodes.iter().enumerate() {
        if index.contains_key(node.id.as_str()) {
            dup[i] = true;
        } else {
            index.insert(node.id.as_str(), i);
        }
    }
    let root = b.root.as_deref().and_then(|r| index.get(r).copied());
    let parent: Vec<Option<usize>> = (0..n)
        .map(|i| {
            if dup[i] || Some(i) == root {
                return None;
            }
            b.nodes[i]
                .parent
                .as_deref()
                .and_then(|p| index.get(p).copied())
                .filter(|&p| p != i)
        })
        .collect();
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (i, p) in parent.iter().enumerate() {
        if let Some(p) = p {
            children[*p].push(i);
        }
    }
    let mut tree = Tree {
        roots: Vec::new(),
        kids: vec![Vec::new(); n],
        depth: vec![0; n],
        dropped: 0,
    };
    let mut visited = vec![false; n];
    let mut count = 0usize;
    let mut starts: Vec<usize> = root.into_iter().collect();
    starts.extend((0..n).filter(|&i| !dup[i] && parent[i].is_none() && Some(i) != root));
    for s in starts {
        walk(s, &children, &mut tree, &mut visited, &mut count);
    }
    // Whatever is left sits on a cycle: break it at the first unvisited node.
    for i in 0..n {
        if !dup[i] && !visited[i] {
            walk(i, &children, &mut tree, &mut visited, &mut count);
        }
    }
    tree.dropped = (0..n).filter(|&i| !dup[i] && !visited[i]).count();
    tree
}

fn walk(
    start: usize,
    children: &[Vec<usize>],
    tree: &mut Tree,
    visited: &mut [bool],
    count: &mut usize,
) {
    if visited[start] || *count >= MAX_NODES {
        return;
    }
    visited[start] = true;
    *count += 1;
    tree.roots.push(start);
    tree.depth[start] = 0;
    let mut stack: Vec<(usize, usize)> =
        children[start].iter().rev().map(|&c| (c, start)).collect();
    while let Some((node, par)) = stack.pop() {
        if visited[node] || *count >= MAX_NODES {
            continue;
        }
        visited[node] = true;
        *count += 1;
        tree.kids[par].push(node);
        tree.depth[node] = tree.depth[par] + 1;
        for &c in children[node].iter().rev() {
            if !visited[c] {
                stack.push((c, node));
            }
        }
    }
}

/// What a box shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoxKind {
    /// One node.
    Node(usize),
    /// Several leaf nodes listed in one box (`more` of them not listed).
    Stack { members: Vec<usize>, more: usize },
}

/// A placed box.
#[derive(Debug, Clone)]
pub struct PlacedBox {
    pub kind: BoxKind,
    pub x: usize,
    pub y: usize,
    pub w: usize,
    pub h: usize,
    pub highlight: bool,
    /// Index of the parent box in [`Layout::boxes`].
    pub parent: Option<usize>,
    /// Caption written into the top border (common type of a stack).
    pub caption: Option<String>,
    /// The connector into this box points up (child → parent relationship).
    pub incoming: bool,
}

impl PlacedBox {
    /// Column of the box's vertical axis (stems attach here).
    pub fn center(&self) -> usize {
        self.x + self.w / 2
    }
}

/// A connector from a parent box to a child box.
#[derive(Debug, Clone)]
pub struct PlacedEdge {
    pub parent: usize,
    pub child: usize,
    pub label: String,
    pub incoming: bool,
    pub hot: bool,
}

/// The computed diagram geometry.
#[derive(Debug, Clone, Default)]
pub struct Layout {
    pub width: usize,
    pub height: usize,
    pub boxes: Vec<PlacedBox>,
    pub edges: Vec<PlacedEdge>,
    /// True when the compact pass (one stack per parent) was used.
    pub compact: bool,
    /// Longest stack row (cells) the layout allows.
    pub row_max: usize,
}

#[derive(Debug, Clone)]
struct Item {
    kind: BoxKind,
    box_w: usize,
    box_h: usize,
    caption: Option<String>,
    highlight: bool,
    edge: String,
    incoming: bool,
    hot: bool,
    w: usize,
    c: usize,
    children: Vec<(usize, Item)>,
}

/// First line of a node box: criticality marker and label.
fn node_title(node: &GraphNode) -> (Option<(&'static str, Style)>, String) {
    let marker = node.criticality.as_deref().and_then(theme::criticality);
    (marker, text::truncate(node.display_label(), MAX_LABEL))
}

fn node_title_width(node: &GraphNode) -> usize {
    let (marker, label) = node_title(node);
    width(&label) + if marker.is_some() { 2 } else { 0 }
}

fn node_type(node: &GraphNode) -> String {
    text::truncate(node.kind.as_deref().unwrap_or(""), MAX_LABEL)
}

/// One row of a stack box: relationship prefix (mixed stacks only), criticality marker, label.
struct StackRow {
    prefix: Option<String>,
    marker: Option<(&'static str, Style)>,
    label: String,
    kind: Option<String>,
}

impl StackRow {
    /// `mixed`: members differ in relationship (rows name it); `typed`: members differ in
    /// type and the stack has no caption (rows name their type). Rows are shortened to at
    /// most `row_max` cells where possible.
    fn new(node: &GraphNode, mixed: bool, typed: bool, row_max: usize) -> StackRow {
        let marker = node.criticality.as_deref().and_then(theme::criticality);
        let marker_w = if marker.is_some() { 2 } else { 0 };
        let kind = (typed && !mixed)
            .then(|| {
                node.kind
                    .as_deref()
                    .map(|k| text::truncate(k, MAX_LABEL.min(row_max / 3).max(4)))
            })
            .flatten();
        let kind_w = kind.as_deref().map_or(0, |k| width(k) + 2);
        // The object's name has priority: the relationship prefix is shortened first.
        let label_max = MAX_LABEL
            .min(row_max.saturating_sub(marker_w + kind_w))
            .max(8);
        let label = text::truncate(node.display_label(), label_max);
        let edge_room = row_max.saturating_sub(marker_w + kind_w + width(&label) + 4);
        let prefix = mixed.then(|| {
            let edge = text::truncate(
                node.edge.as_deref().unwrap_or(""),
                MAX_EDGE.min(edge_room).max(4),
            );
            match (edge.is_empty(), node.is_incoming()) {
                (true, _) => String::new(),
                (false, true) => format!("← {edge} "),
                (false, false) => format!("{edge} → "),
            }
        });
        StackRow {
            prefix: prefix.filter(|p| !p.is_empty()),
            marker,
            label,
            kind,
        }
    }

    fn width(&self) -> usize {
        self.prefix.as_deref().map_or(0, width)
            + if self.marker.is_some() { 2 } else { 0 }
            + width(&self.label)
            + self.kind.as_deref().map_or(0, |k| width(k) + 2)
    }
}

fn stack_is_mixed(b: &GraphBlock, members: &[usize]) -> bool {
    let first = &b.nodes[members[0]];
    members.iter().any(|&m| {
        let n = &b.nodes[m];
        n.edge != first.edge || n.is_incoming() != first.is_incoming()
    })
}

fn stack_caption(b: &GraphBlock, members: &[usize]) -> Option<String> {
    let first = b.nodes[members[0]].kind.as_deref()?;
    members
        .iter()
        .all(|&m| b.nodes[m].kind.as_deref() == Some(first))
        .then(|| text::truncate(first, MAX_LABEL))
}

enum Slot {
    Node(usize),
    Stack(Vec<usize>),
}

fn stackable(b: &GraphBlock, tree: &Tree, c: usize) -> bool {
    tree.kids[c].is_empty() && !b.nodes[c].highlight
}

fn group_children(b: &GraphBlock, tree: &Tree, p: usize, compact: bool) -> Vec<Slot> {
    let kids = &tree.kids[p];
    // (relationship, incoming) → leaf children sharing it.
    type Group<'a> = ((Option<&'a str>, bool), Vec<usize>);
    let mut groups: Vec<Group<'_>> = Vec::new();
    for &c in kids.iter().filter(|&&c| stackable(b, tree, c)) {
        let key = if compact {
            (None, false)
        } else {
            (b.nodes[c].edge.as_deref(), b.nodes[c].is_incoming())
        };
        match groups.iter_mut().find(|(k, _)| *k == key) {
            Some((_, members)) => members.push(c),
            None => groups.push((key, vec![c])),
        }
    }
    let crowded = kids.len() > CROWDED;
    let stacked: Vec<Vec<usize>> = groups
        .into_iter()
        .map(|(_, m)| m)
        .filter(|m| m.len() >= 3 || ((crowded || compact) && m.len() >= 2))
        .collect();
    let mut emitted = vec![false; stacked.len()];
    let mut slots = Vec::new();
    for &c in kids {
        match stacked.iter().position(|m| m.contains(&c)) {
            Some(g) => {
                if !emitted[g] {
                    emitted[g] = true;
                    slots.push(Slot::Stack(stacked[g].clone()));
                }
            }
            None => slots.push(Slot::Node(c)),
        }
    }
    slots
}

fn node_item(
    b: &GraphBlock,
    tree: &Tree,
    i: usize,
    parent: Option<usize>,
    compact: &[bool],
    row_max: usize,
) -> Item {
    let node = &b.nodes[i];
    let inner = node_title_width(node).max(width(&node_type(node))).max(3);
    let children = group_children(b, tree, i, compact[i])
        .into_iter()
        .map(|slot| {
            let item = match slot {
                Slot::Node(c) => node_item(b, tree, c, Some(i), compact, row_max),
                Slot::Stack(members) => stack_item(b, members, row_max),
            };
            (0, item)
        })
        .collect();
    Item {
        kind: BoxKind::Node(i),
        box_w: inner + 4,
        box_h: BOX_H,
        caption: None,
        highlight: node.highlight,
        edge: text::truncate(node.edge.as_deref().unwrap_or(""), MAX_EDGE),
        incoming: node.is_incoming(),
        hot: parent.is_some_and(|p| b.nodes[p].highlight) && node.highlight,
        w: 0,
        c: 0,
        children,
    }
}

fn stack_item(b: &GraphBlock, members: Vec<usize>, row_max: usize) -> Item {
    let mixed = stack_is_mixed(b, &members);
    let caption = stack_caption(b, &members);
    let shown = members.len().min(STACK_ROWS);
    let more = members.len() - shown;
    let typed = caption.is_none();
    let mut inner = members[..shown]
        .iter()
        .map(|&m| StackRow::new(&b.nodes[m], mixed, typed, row_max).width())
        .max()
        .unwrap_or(1);
    if more > 0 {
        inner = inner.max(width(&format!("+{more} more")));
    }
    if let Some(c) = &caption {
        inner = inner.max(width(c) + 2);
    }
    let first = &b.nodes[members[0]];
    let edge = if mixed {
        format!("×{}", members.len())
    } else {
        let e = text::truncate(first.edge.as_deref().unwrap_or(""), MAX_EDGE);
        if e.is_empty() {
            format!("×{}", members.len())
        } else {
            format!("{e} ×{}", members.len())
        }
    };
    Item {
        box_h: shown + usize::from(more > 0) + 2,
        kind: BoxKind::Stack {
            members: members[..shown].to_vec(),
            more,
        },
        box_w: inner + 4,
        caption,
        highlight: false,
        incoming: !mixed && first.is_incoming(),
        edge,
        hot: false,
        w: 0,
        c: 0,
        children: Vec::new(),
    }
}

fn measure(item: &mut Item) {
    let half = item.box_w / 2;
    if item.children.is_empty() {
        item.w = item.box_w;
        item.c = half;
    } else {
        let mut x = 0;
        for (off, child) in item.children.iter_mut() {
            measure(child);
            *off = x;
            x += child.w + GAP;
        }
        let span = x - GAP;
        let first = item.children[0].0 + item.children[0].1.c;
        let last_child = item.children.last().expect("children");
        let last = last_child.0 + last_child.1.c;
        let mid = (first + last) / 2;
        let shift = half.saturating_sub(mid);
        for (off, _) in item.children.iter_mut() {
            *off += shift;
        }
        item.c = mid + shift;
        item.w = (span + shift).max(item.c - half + item.box_w);
    }
    let lw = width(&item.edge);
    if lw > 0 {
        let left_need = lw / 2 + 1;
        if item.c < left_need {
            let s = left_need - item.c;
            item.c += s;
            item.w += s;
            for (off, _) in item.children.iter_mut() {
                *off += s;
            }
        }
        let right_need = lw - lw / 2 + 1;
        item.w = item.w.max(item.c + right_need);
    }
}

fn place(item: &Item, left: usize, depth: usize, parent: Option<usize>, out: &mut Layout) {
    let center = left + item.c;
    let idx = out.boxes.len();
    out.boxes.push(PlacedBox {
        kind: item.kind.clone(),
        x: center - item.box_w / 2,
        y: depth * LEVEL_H,
        w: item.box_w,
        h: item.box_h,
        highlight: item.highlight,
        parent,
        caption: item.caption.clone(),
        incoming: parent.is_some() && item.incoming,
    });
    if let Some(p) = parent {
        out.edges.push(PlacedEdge {
            parent: p,
            child: idx,
            label: item.edge.clone(),
            incoming: item.incoming,
            hot: item.hot,
        });
    }
    for (off, child) in &item.children {
        place(child, left + off, depth + 1, Some(idx), out);
    }
}

fn layout_with(b: &GraphBlock, tree: &Tree, compact: &[bool], row_max: usize) -> Layout {
    let mut out = Layout {
        compact: compact.iter().any(|&c| c),
        row_max,
        ..Layout::default()
    };
    let mut left = 0;
    for (i, &r) in tree.roots.iter().enumerate() {
        let mut item = node_item(b, tree, r, None, compact, row_max);
        item.edge.clear();
        measure(&mut item);
        if i > 0 {
            left += ROOT_GAP;
        }
        place(&item, left, 0, None, &mut out);
        left += item.w;
    }
    out.width = left;
    out.height = out.boxes.iter().map(|bx| bx.y + bx.h).max().unwrap_or(0);
    out
}

/// Lays out the tree. While the diagram is wider than `avail`, the parent with the most
/// stackable leaves is compacted (all its leaves listed in one stack) and the layout is
/// recomputed; then stack rows are shortened. The narrowest layout seen is returned when
/// nothing more helps (the TUI scrolls it sideways).
pub fn layout(b: &GraphBlock, tree: &Tree, avail: usize) -> Layout {
    let n = b.nodes.len();
    let mut compact = vec![false; n];
    let mut best = layout_with(b, tree, &compact, usize::MAX);
    let mut current_width = best.width;
    while current_width > avail {
        let candidate = (0..n)
            .filter(|&p| !compact[p])
            .map(|p| {
                let leaves = tree.kids[p]
                    .iter()
                    .filter(|&&c| stackable(b, tree, c))
                    .count();
                (leaves, tree.kids[p].len(), p)
            })
            .filter(|&(leaves, _, _)| leaves >= 2)
            .max_by_key(|&(leaves, kids, p)| (leaves, kids, std::cmp::Reverse(p)));
        let Some((_, _, p)) = candidate else {
            break;
        };
        compact[p] = true;
        let next = layout_with(b, tree, &compact, usize::MAX);
        current_width = next.width;
        if next.width < best.width {
            best = next;
        }
    }
    for row_max in [28, 24] {
        if best.width <= avail {
            break;
        }
        let next = layout_with(b, tree, &compact, row_max);
        if next.width < best.width {
            best = next;
        }
    }
    best
}

/// Horizontal scroll offset that centers the root box (the first root) in a viewport of
/// `viewport` cells, clamped to the drawing; 0 when the drawing fits.
pub fn initial_offset(layout: &Layout, viewport: usize) -> usize {
    if layout.width <= viewport {
        return 0;
    }
    let max = layout.width - viewport;
    let center = layout.boxes.first().map_or(0, PlacedBox::center);
    center.saturating_sub(viewport / 2).min(max)
}

#[derive(Clone, Default)]
struct Cell {
    arms: u8,
    dbl: u8,
    hot: bool,
    sym: Option<String>,
    style: Style,
    cont: bool,
}

struct Canvas {
    w: usize,
    h: usize,
    cells: Vec<Cell>,
}

impl Canvas {
    fn new(w: usize, h: usize) -> Canvas {
        Canvas {
            w,
            h,
            cells: vec![Cell::default(); w * h],
        }
    }

    fn cell(&mut self, x: usize, y: usize) -> Option<&mut Cell> {
        (x < self.w && y < self.h).then(|| &mut self.cells[y * self.w + x])
    }

    fn arm(&mut self, x: usize, y: usize, dir: u8, double: bool, hot: bool) {
        if let Some(c) = self.cell(x, y) {
            c.arms |= dir;
            if double {
                c.dbl |= dir;
            }
            c.hot |= hot;
        }
    }

    fn hline(&mut self, x0: usize, x1: usize, y: usize, double: bool, hot: bool) {
        let (a, b) = (x0.min(x1), x0.max(x1));
        for x in a..=b {
            if x > a {
                self.arm(x, y, LEFT, double, hot);
            }
            if x < b {
                self.arm(x, y, RIGHT, double, hot);
            }
        }
    }

    fn vline(&mut self, x: usize, y0: usize, y1: usize, double: bool, hot: bool) {
        let (a, b) = (y0.min(y1), y0.max(y1));
        for y in a..=b {
            if y > a {
                self.arm(x, y, UP, double, hot);
            }
            if y < b {
                self.arm(x, y, DOWN, double, hot);
            }
        }
    }

    fn rect(&mut self, x: usize, y: usize, w: usize, h: usize, double: bool, hot: bool) {
        if w < 2 || h < 2 {
            return;
        }
        self.hline(x, x + w - 1, y, double, hot);
        self.hline(x, x + w - 1, y + h - 1, double, hot);
        self.vline(x, y, y + h - 1, double, hot);
        self.vline(x + w - 1, y, y + h - 1, double, hot);
    }

    fn text(&mut self, mut x: usize, y: usize, s: &str, style: Style) {
        for g in s.graphemes(true) {
            let w = grapheme_width(g);
            if w == 0 {
                continue;
            }
            if let Some(c) = self.cell(x, y) {
                c.sym = Some(g.to_string());
                c.style = style;
                c.cont = false;
            }
            for k in 1..w {
                if let Some(c) = self.cell(x + k, y) {
                    c.sym = None;
                    c.cont = true;
                }
            }
            x += w;
        }
    }

    fn rows(&self) -> Vec<Vec<Span<'static>>> {
        let line_hot = theme::bold();
        let line_dim = theme::dim();
        (0..self.h)
            .map(|y| {
                let mut spans: Vec<Span<'static>> = Vec::new();
                let mut cur = String::new();
                let mut cur_style = Style::default();
                for x in 0..self.w {
                    let c = &self.cells[y * self.w + x];
                    if c.cont {
                        continue;
                    }
                    let (sym, style) = match &c.sym {
                        Some(s) => (s.clone(), c.style),
                        None if c.arms != 0 => (
                            glyph(c.arms, c.dbl).to_string(),
                            if c.hot { line_hot } else { line_dim },
                        ),
                        None => (" ".to_string(), Style::default()),
                    };
                    if style != cur_style && !cur.is_empty() {
                        spans.push(Span::styled(std::mem::take(&mut cur), cur_style));
                    }
                    cur_style = style;
                    cur.push_str(&sym);
                }
                let trimmed = cur.trim_end().to_string();
                if !trimmed.is_empty() {
                    spans.push(Span::styled(trimmed, cur_style));
                }
                // Drop trailing all-space spans.
                while spans.last().is_some_and(|s| s.content.trim().is_empty()) {
                    spans.pop();
                }
                spans
            })
            .collect()
    }
}

/// Box-drawing glyph for a cell with the given arms. A cell can mix single and double lines
/// only per axis (all horizontal arms share one weight, all vertical arms another), which is
/// what Unicode provides glyphs for.
pub fn glyph(arms: u8, dbl: u8) -> char {
    let hd = dbl & (LEFT | RIGHT) != 0;
    let vd = dbl & (UP | DOWN) != 0;
    let pick = |ss: char, sd: char, ds: char, dd: char| match (vd, hd) {
        (false, false) => ss,
        (false, true) => sd,
        (true, false) => ds,
        (true, true) => dd,
    };
    let (u, d, l, r) = (
        arms & UP != 0,
        arms & DOWN != 0,
        arms & LEFT != 0,
        arms & RIGHT != 0,
    );
    match (u, d, l, r) {
        (false, false, false, false) => ' ',
        (_, _, false, false) => {
            if vd {
                '║'
            } else {
                '│'
            }
        }
        (false, false, _, _) => {
            if hd {
                '═'
            } else {
                '─'
            }
        }
        (false, true, false, true) => pick('┌', '╒', '╓', '╔'),
        (false, true, true, false) => pick('┐', '╕', '╖', '╗'),
        (true, false, false, true) => pick('└', '╘', '╙', '╚'),
        (true, false, true, false) => pick('┘', '╛', '╜', '╝'),
        (true, true, false, true) => pick('├', '╞', '╟', '╠'),
        (true, true, true, false) => pick('┤', '╡', '╢', '╣'),
        (false, true, true, true) => pick('┬', '╤', '╥', '╦'),
        (true, false, true, true) => pick('┴', '╧', '╨', '╩'),
        (true, true, true, true) => pick('┼', '╪', '╫', '╬'),
    }
}

/// A drawn diagram.
#[derive(Debug, Clone, Default)]
pub struct Drawing {
    pub rows: Vec<Vec<Span<'static>>>,
    /// Per-row reference when exactly one object occupies the row.
    pub row_refs: Vec<Option<String>>,
    /// Clickable areas (relative to the drawing).
    pub hotspots: Vec<Hotspot>,
    pub width: usize,
}

/// Draws a layout.
pub fn draw(b: &GraphBlock, layout: &Layout) -> Drawing {
    let mut cv = Canvas::new(layout.width.max(1), layout.height.max(1));
    let mut hotspots = Vec::new();

    // Box frames first, then connectors (their arms merge into the frames), then text.
    for bx in &layout.boxes {
        cv.rect(bx.x, bx.y, bx.w, bx.h, bx.highlight, bx.highlight);
    }
    let stem_hot: Vec<bool> = (0..layout.boxes.len())
        .map(|i| layout.edges.iter().any(|e| e.parent == i && e.hot))
        .collect();
    let mut stems_drawn = vec![false; layout.boxes.len()];
    let mut labels: Vec<(usize, usize, String, Style)> = Vec::new();
    for e in &layout.edges {
        let p = &layout.boxes[e.parent];
        let c = &layout.boxes[e.child];
        let (pc, cx) = (p.center(), c.center());
        let bus = p.y + p.h;
        if !stems_drawn[e.parent] {
            stems_drawn[e.parent] = true;
            let hot = stem_hot[e.parent];
            cv.arm(pc, p.y + p.h - 1, DOWN, hot, hot);
            cv.arm(pc, bus, UP, hot, hot);
        }
        cv.hline(pc, cx, bus, e.hot, e.hot);
        cv.arm(cx, bus, DOWN, e.hot, e.hot);
        let style = if e.hot { theme::bold() } else { theme::dim() };
        let (stem_y, label_y, arrow_y) = (bus + 1, bus + 2, bus + 3);
        if e.incoming {
            labels.push((cx, stem_y, "▲".to_string(), style));
            cv.vline(cx, arrow_y, c.y, e.hot, e.hot);
            cv.arm(cx, arrow_y, UP, e.hot, e.hot);
        } else {
            cv.arm(cx, stem_y, UP | DOWN, e.hot, e.hot);
            labels.push((cx, arrow_y, "▼".to_string(), style));
        }
        if e.label.is_empty() {
            cv.arm(cx, label_y, UP | DOWN, e.hot, e.hot);
        } else {
            let lw = width(&e.label);
            labels.push((cx - lw / 2, label_y, e.label.clone(), style));
        }
    }
    for (x, y, s, style) in labels {
        cv.text(x, y, &s, style);
    }

    for bx in &layout.boxes {
        match &bx.kind {
            BoxKind::Node(i) => {
                let node = &b.nodes[*i];
                let (marker, label) = node_title(node);
                let inner = bx.w - 4;
                let tw = width(&label) + if marker.is_some() { 2 } else { 0 };
                let mut x = bx.x + 2 + (inner.saturating_sub(tw)) / 2;
                let label_style = if bx.highlight {
                    theme::glow()
                } else {
                    theme::body()
                };
                if let Some((m, ms)) = marker {
                    cv.text(x, bx.y + 1, m, ms);
                    x += 2;
                }
                cv.text(x, bx.y + 1, &label, label_style);
                let kind = node_type(node);
                if !kind.is_empty() {
                    let kx = bx.x + 2 + (inner.saturating_sub(width(&kind))) / 2;
                    let ks = if bx.highlight {
                        theme::text()
                    } else {
                        theme::dim()
                    };
                    cv.text(kx, bx.y + 2, &kind, ks);
                }
                if !node.id.is_empty() {
                    hotspots.push(Hotspot {
                        line: bx.y,
                        height: bx.h,
                        col: bx.x,
                        width: bx.w,
                        reference: node.id.clone(),
                    });
                }
            }
            BoxKind::Stack { members, more } => {
                let mixed = stack_is_mixed(b, members);
                if let Some(c) = &bx.caption {
                    // On the top border, unless an upward connector joins it there.
                    let caption = format!(" {c} ");
                    let clash = bx.incoming && bx.x + 2 + width(&caption) >= bx.center();
                    let y = if clash { bx.y + bx.h - 1 } else { bx.y };
                    cv.text(bx.x + 2, y, &caption, theme::dim());
                }
                for (row, &m) in members.iter().enumerate() {
                    let node = &b.nodes[m];
                    let y = bx.y + 1 + row;
                    let mut x = bx.x + 2;
                    let r = StackRow::new(node, mixed, bx.caption.is_none(), layout.row_max);
                    if let Some(prefix) = &r.prefix {
                        cv.text(x, y, prefix, theme::dim());
                        x += width(prefix);
                    }
                    if let Some((mk, ms)) = r.marker {
                        cv.text(x, y, mk, ms);
                        x += 2;
                    }
                    cv.text(x, y, &r.label, theme::body());
                    if let Some(kind) = &r.kind {
                        let kx = bx.x + bx.w - 2 - width(kind);
                        cv.text(kx, y, kind, theme::dim());
                    }
                    if !node.id.is_empty() {
                        hotspots.push(Hotspot {
                            line: y,
                            height: 1,
                            col: bx.x,
                            width: bx.w,
                            reference: node.id.clone(),
                        });
                    }
                }
                if *more > 0 {
                    cv.text(
                        bx.x + 2,
                        bx.y + 1 + members.len(),
                        &format!("+{more} more"),
                        theme::dim().add_modifier(Modifier::ITALIC),
                    );
                }
            }
        }
    }

    let rows = cv.rows();
    let row_refs = (0..rows.len())
        .map(|y| {
            let mut refs = hotspots
                .iter()
                .filter(|h| y >= h.line && y < h.line + h.height)
                .map(|h| h.reference.as_str());
            match (refs.next(), refs.next()) {
                (Some(r), None) => Some(r.to_string()),
                _ => None,
            }
        })
        .collect();
    Drawing {
        rows,
        row_refs,
        hotspots,
        width: layout.width,
    }
}

/// The compact vertical layout (`v`): one line per node, indented under its parent.
pub fn vertical_lines(b: &GraphBlock, tree: &Tree) -> Vec<(Vec<Span<'static>>, Option<String>)> {
    let mut out = Vec::new();
    for &r in &tree.roots {
        vertical_node(b, tree, r, String::new(), String::new(), true, &mut out);
    }
    out
}

fn vertical_node(
    b: &GraphBlock,
    tree: &Tree,
    i: usize,
    lead: String,
    child_lead: String,
    root: bool,
    out: &mut Vec<(Vec<Span<'static>>, Option<String>)>,
) {
    let node = &b.nodes[i];
    let hot = node.highlight;
    let edge_style = if hot { theme::bold() } else { theme::dim() };
    let label_style = if hot { theme::glow() } else { theme::body() };
    let mut spans = vec![Span::styled(lead, theme::dim())];
    if !root && let Some(edge) = node.edge.as_deref() {
        if node.is_incoming() {
            spans.push(Span::styled(format!("← {edge} "), edge_style));
        } else {
            spans.push(Span::styled(format!("{edge} → "), edge_style));
        }
    }
    if let Some((m, ms)) = node.criticality.as_deref().and_then(theme::criticality) {
        spans.push(Span::styled(format!("{m} "), ms));
    }
    spans.push(Span::styled(node.display_label().to_string(), label_style));
    if let Some(kind) = &node.kind {
        spans.push(Span::styled(format!("  {kind}"), theme::dim()));
    }
    let reference = (!node.id.is_empty()).then(|| node.id.clone());
    out.push((spans, reference));
    let kids = &tree.kids[i];
    for (k, &c) in kids.iter().enumerate() {
        let last = k + 1 == kids.len();
        let hot_child = hot && b.nodes[c].highlight;
        let (conn, cont) = match (last, hot_child) {
            (true, true) => ("╚══ ", "    "),
            (true, false) => ("└── ", "    "),
            (false, true) => ("╠══ ", "│   "),
            (false, false) => ("├── ", "│   "),
        };
        vertical_node(
            b,
            tree,
            c,
            format!("{child_lead}{conn}"),
            format!("{child_lead}{cont}"),
            false,
            out,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::GraphNode;

    fn node(id: &str, parent: Option<&str>, edge: &str, hl: bool) -> GraphNode {
        GraphNode {
            id: id.to_string(),
            label: id.to_uppercase(),
            kind: Some("host".to_string()),
            criticality: None,
            highlight: hl,
            parent: parent.map(str::to_string),
            edge: (!edge.is_empty()).then(|| edge.to_string()),
            dir: Some("out".to_string()),
        }
    }

    /// root → 4 children, each → 4 grandchildren with distinct relationship labels.
    fn fanout4() -> GraphBlock {
        let mut nodes = vec![node("r", None, "", true)];
        for i in 0..4 {
            let c = format!("c{i}");
            nodes.push(node(&c, Some("r"), &format!("REL_{i}"), i == 1));
            for j in 0..4 {
                let g = format!("g{i}{j}");
                nodes.push(node(&g, Some(&c), &format!("E{j}"), i == 1 && j == 2));
            }
        }
        GraphBlock {
            root: Some("r".to_string()),
            nodes,
            links: Vec::new(),
        }
    }

    fn overlaps(a: &PlacedBox, b: &PlacedBox) -> bool {
        a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h
    }

    #[test]
    fn three_levels_fanout_four_has_no_overlap_and_centered_parents() {
        let g = fanout4();
        let tree = build_tree(&g);
        let lay = layout(&g, &tree, 10_000);
        assert_eq!(lay.boxes.len(), 21);
        assert!(!lay.compact);
        for (i, a) in lay.boxes.iter().enumerate() {
            assert!(a.x + a.w <= lay.width, "box {i} exceeds the layout width");
            assert!(a.y + a.h <= lay.height);
            for b2 in &lay.boxes[i + 1..] {
                assert!(!overlaps(a, b2), "boxes overlap: {a:?} {b2:?}");
            }
        }
        // Parents are centered above their children (within one cell).
        for (pi, p) in lay.boxes.iter().enumerate() {
            let kids: Vec<&PlacedBox> = lay
                .boxes
                .iter()
                .filter(|b2| b2.parent == Some(pi))
                .collect();
            if kids.is_empty() {
                continue;
            }
            let first = kids.first().unwrap().center();
            let last = kids.last().unwrap().center();
            let mid = (first + last) / 2;
            assert!(p.center().abs_diff(mid) <= 1, "parent {pi} not centered");
            for k in &kids {
                assert_eq!(k.y, p.y + LEVEL_H);
            }
        }
        // The drawing stays within the computed width.
        let d = draw(&g, &lay);
        for row in &d.rows {
            assert!(text::spans_width(row) <= lay.width);
        }
        assert_eq!(d.rows.len(), lay.height);
    }

    fn char_grid(d: &Drawing) -> Vec<Vec<char>> {
        d.rows
            .iter()
            .map(|r| r.iter().flat_map(|s| s.content.chars()).collect())
            .collect()
    }

    fn at(grid: &[Vec<char>], x: usize, y: usize) -> char {
        grid.get(y).and_then(|r| r.get(x)).copied().unwrap_or(' ')
    }

    #[test]
    fn highlighted_path_uses_double_lines() {
        let g = fanout4();
        let tree = build_tree(&g);
        let lay = layout(&g, &tree, 10_000);
        let d = draw(&g, &lay);
        let grid = char_grid(&d);
        let all: String = grid
            .iter()
            .map(|r| r.iter().collect::<String>() + "\n")
            .collect();
        let mut doubles = 0;
        for bx in &lay.boxes {
            let corner = at(&grid, bx.x, bx.y);
            if bx.highlight {
                doubles += 1;
                assert_eq!(corner, '╔', "{all}");
                assert_eq!(at(&grid, bx.x + bx.w - 1, bx.y + bx.h - 1), '╝', "{all}");
            } else {
                assert_eq!(corner, '┌', "{all}");
            }
        }
        // Root, c1 and g12 are highlighted.
        assert_eq!(doubles, 3);
        // The root's stem leaves its double bottom border as a double line (╦), the bus
        // towards c1 is double (═) and the stem into c1 is double (║).
        let root = &lay.boxes[0];
        assert_eq!(at(&grid, root.center(), root.y + root.h - 1), '╦', "{all}");
        let c1 = lay
            .boxes
            .iter()
            .find(|bx| bx.kind == BoxKind::Node(6))
            .expect("c1 box");
        assert_eq!(at(&grid, c1.center(), c1.y - 3), '║', "{all}");
        assert!(all.contains('═'));
        // Every child has an arrow.
        assert_eq!(all.matches('▼').count(), 20);
    }

    fn root_at(x: usize, w: usize, width: usize) -> Layout {
        Layout {
            width,
            height: BOX_H,
            boxes: vec![PlacedBox {
                kind: BoxKind::Node(0),
                x,
                y: 0,
                w,
                h: BOX_H,
                highlight: true,
                parent: None,
                caption: None,
                incoming: false,
            }],
            ..Layout::default()
        }
    }

    #[test]
    fn initial_offset_centers_the_root_and_clamps() {
        // Root box 90..110 (center 100) in a 200-wide drawing, 50-wide viewport.
        assert_eq!(initial_offset(&root_at(90, 20, 200), 50), 75);
        // Near the left edge: clamped at 0.
        assert_eq!(initial_offset(&root_at(2, 8, 200), 50), 0);
        // Near the right edge: clamped at width - viewport.
        assert_eq!(initial_offset(&root_at(185, 12, 200), 50), 150);
        // The drawing fits: no scrolling.
        assert_eq!(initial_offset(&root_at(10, 8, 40), 50), 0);
        // A real layout: the root of the fan-out fixture ends up centered.
        let g = fanout4();
        let lay = layout(&g, &build_tree(&g), 10_000);
        let off = initial_offset(&lay, 40);
        let root = &lay.boxes[0];
        assert!(off <= root.x && root.x + root.w <= off + 40);
        assert!((off + 20).abs_diff(root.center()) <= 1);
    }

    #[test]
    fn junction_glyphs() {
        assert_eq!(glyph(LEFT | RIGHT | DOWN, 0), '┬');
        assert_eq!(glyph(LEFT | RIGHT | DOWN, LEFT | RIGHT), '╤');
        assert_eq!(glyph(LEFT | RIGHT | DOWN, LEFT | RIGHT | DOWN), '╦');
        assert_eq!(glyph(LEFT | RIGHT | UP, UP), '╨');
        assert_eq!(glyph(UP | DOWN | LEFT | RIGHT, LEFT), '╪');
        assert_eq!(glyph(UP | DOWN, 0), '│');
        assert_eq!(glyph(UP, UP), '║');
        assert_eq!(glyph(RIGHT | DOWN, RIGHT | DOWN), '╔');
    }

    #[test]
    fn wide_fanout_is_stacked() {
        let mut nodes = vec![node("root", None, "", true)];
        for i in 0..12 {
            nodes.push(GraphNode {
                kind: Some("process".to_string()),
                ..node(&format!("p{i}"), Some("root"), "STARTED", false)
            });
        }
        nodes.push(node("hot", Some("root"), "LOGGED_INTO", true));
        let g = GraphBlock {
            root: Some("root".to_string()),
            nodes,
            links: Vec::new(),
        };
        let tree = build_tree(&g);
        let lay = layout(&g, &tree, 10_000);
        // root + one stack of 12 + the highlighted node.
        assert_eq!(lay.boxes.len(), 3);
        assert!(lay.width < 60, "width {}", lay.width);
        let d = draw(&g, &lay);
        let all: String = d
            .rows
            .iter()
            .map(|r| r.iter().map(|s| s.content.as_ref()).collect::<String>() + "\n")
            .collect();
        assert!(all.contains("STARTED ×12"), "{all}");
        assert!(all.contains(" process "), "{all}");
        // Each stacked row is clickable.
        assert_eq!(d.hotspots.iter().filter(|h| h.height == 1).count(), 12);
    }

    #[test]
    fn cycles_and_unknown_parents_do_not_hang() {
        let g = GraphBlock {
            root: None,
            nodes: vec![
                node("a", Some("b"), "X", false),
                node("b", Some("a"), "Y", false),
                node("c", Some("missing"), "Z", false),
                node("c", None, "", false),
            ],
            links: Vec::new(),
        };
        let tree = build_tree(&g);
        assert_eq!(tree.roots.len(), 2);
        assert_eq!(tree.dropped, 0);
        let lay = layout(&g, &tree, 200);
        assert_eq!(lay.boxes.len(), 3);
    }

    #[test]
    fn incoming_edges_point_up() {
        let mut nodes = vec![node("p", None, "", false)];
        nodes.push(GraphNode {
            dir: Some("in".to_string()),
            ..node("q", Some("p"), "CAN_ACCESS", false)
        });
        let g = GraphBlock {
            root: Some("p".to_string()),
            nodes,
            links: Vec::new(),
        };
        let tree = build_tree(&g);
        let d = draw(&g, &layout(&g, &tree, 200));
        let all: String = d
            .rows
            .iter()
            .map(|r| r.iter().map(|s| s.content.as_ref()).collect::<String>() + "\n")
            .collect();
        assert!(all.contains('▲'), "{all}");
        assert!(!all.contains('▼'), "{all}");
        assert!(all.contains('┴'), "{all}");
    }
}
