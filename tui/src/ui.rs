//! Frame layout and widgets: header, tab bar, sidebar (pages, focus, world), content panel,
//! digital-rain column, status bar, inspector popup and help overlay.
//!
//! Drawing also records the clickable regions of the frame in [`App::hit`] for the mouse.

use ratatui::Frame;
use ratatui::buffer::{Buffer, CellDiffOption};
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Clear, Widget};

use crate::app::{App, DocView, FocusTarget, Status, Viewport};
use crate::rain::Rng;
use crate::text::{self, width};
use crate::theme;

/// Smallest supported terminal.
pub const MIN_W: u16 = 80;
pub const MIN_H: u16 = 24;
const SPINNER: [char; 8] = ['⣾', '⣽', '⣻', '⢿', '⡿', '⣟', '⣯', '⣷'];

/// Bounds-checked string drawing; returns the column after the text.
pub fn put(buf: &mut Buffer, x: u16, y: u16, s: impl AsRef<str>, style: Style) -> u16 {
    let area = buf.area;
    if y < area.top() || y >= area.bottom() || x < area.left() || x >= area.right() {
        return x;
    }
    let max = (area.right() - x) as usize;
    buf.set_stringn(x, y, s.as_ref(), max, style).0
}

/// Like [`put`], limited to `max` cells.
pub fn put_n(buf: &mut Buffer, x: u16, y: u16, s: &str, max: usize, style: Style) -> u16 {
    let area = buf.area;
    if y < area.top() || y >= area.bottom() || x < area.left() || x >= area.right() || max == 0 {
        return x;
    }
    let s = text::truncate(s, max);
    let max = max.min((area.right() - x) as usize);
    buf.set_stringn(x, y, &s, max, style).0
}

fn fill(buf: &mut Buffer, area: Rect, style: Style) {
    let area = area.intersection(buf.area);
    for y in area.top()..area.bottom() {
        for x in area.left()..area.right() {
            if let Some(c) = buf.cell_mut((x, y)) {
                c.set_char(' ');
                c.set_style(style);
            }
        }
    }
}

fn spinner(frame: u64) -> char {
    SPINNER[(frame / 2) as usize % SPINNER.len()]
}

/// Draws one frame.
pub fn draw(f: &mut Frame, app: &mut App) {
    let area = f.area();
    app.hit = Default::default();
    app.term_size = (area.width, area.height);
    f.buffer_mut().set_style(area, theme::base());
    if let Some(boot) = &mut app.boot {
        boot.render(area, f.buffer_mut());
    } else if area.width < MIN_W || area.height < MIN_H {
        draw_too_small(f.buffer_mut(), area);
    } else {
        draw_main(f, app, area);
    }
    if !app.truecolor {
        theme::downsample(f.buffer_mut());
    }
    if app.full_repaint {
        app.full_repaint = false;
        for cell in &mut f.buffer_mut().content {
            cell.set_diff_option(CellDiffOption::AlwaysUpdate);
        }
    }
}

fn draw_too_small(buf: &mut Buffer, area: Rect) {
    let lines = [
        ("R$F OS".to_string(), theme::glow()),
        (String::new(), theme::text()),
        (
            "terminal too small".to_string(),
            Style::new().fg(theme::AMBER),
        ),
        (
            format!(
                "{}×{} · needs at least {MIN_W}×{MIN_H}",
                area.width, area.height
            ),
            theme::text(),
        ),
        (
            "enlarge the window, or press q to quit".to_string(),
            theme::dim(),
        ),
    ];
    let top = area.y + area.height.saturating_sub(lines.len() as u16) / 2;
    for (i, (s, style)) in lines.iter().enumerate() {
        let w = width(s) as u16;
        let x = area.x + area.width.saturating_sub(w) / 2;
        put_n(buf, x, top + i as u16, s, area.width as usize, *style);
    }
}

fn draw_main(f: &mut Frame, app: &mut App, area: Rect) {
    let [header, tabs, body, status] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .areas(area);
    draw_header(f.buffer_mut(), app, header);
    draw_tabs(f.buffer_mut(), app, tabs);
    let rain_on = app.rain_visible(area.width);
    let side_w = match area.width {
        140.. => 26,
        100.. => 24,
        _ => 22,
    };
    let rain_w = if rain_on {
        if area.width >= 160 { 16 } else { 12 }
    } else {
        0
    };
    let [side, content, rain] = Layout::horizontal([
        Constraint::Length(side_w),
        Constraint::Min(40),
        Constraint::Length(rain_w),
    ])
    .areas(body);
    draw_sidebar(f.buffer_mut(), app, side);
    draw_content(f, app, content);
    if rain_on {
        app.side_rain
            .resize(rain.width as usize, rain.height as usize);
        app.side_rain.render(rain, f.buffer_mut(), 0.85);
    }
    if !app.inspector.is_empty() {
        theme::dim_area(f.buffer_mut(), area);
        draw_inspector(f, app, area);
    }
    if app.help {
        theme::dim_area(f.buffer_mut(), area);
        draw_help(f.buffer_mut(), app, area);
    }
    draw_status(f.buffer_mut(), app, status);
}

fn bar_style() -> Style {
    Style::new().bg(theme::ABYSS).fg(theme::GREEN)
}

fn draw_header(buf: &mut Buffer, app: &App, area: Rect) {
    let bg = bar_style();
    fill(buf, area, bg);
    let y = area.y;
    let clock = format!(" {} UTC ", text::utc_timestamp(unix_secs()));
    let clock_x = area.right().saturating_sub(width(&clock) as u16);
    put(
        buf,
        clock_x,
        y,
        &clock,
        bg.fg(theme::GLOW).add_modifier(Modifier::BOLD),
    );
    let limit = clock_x.saturating_sub(1);

    let mut x = area.x;
    x = put(
        buf,
        x,
        y,
        " R$F OS ",
        Style::new()
            .bg(theme::GREEN)
            .fg(theme::BLACK)
            .add_modifier(Modifier::BOLD),
    );
    let version = app
        .meta
        .as_ref()
        .and_then(|m| m.system.version.clone())
        .map(|v| format!(" v{v} "))
        .unwrap_or_else(|| format!(" v{} ", crate::VERSION));
    let workspace = app
        .meta
        .as_ref()
        .and_then(|m| m.system.workspace.clone())
        .or_else(|| app.opts.api.workspace.clone())
        .unwrap_or_else(|| "default".to_string());
    let (dot, state, state_style) = match app.online {
        Some(true) => (
            "●",
            "ONLINE",
            bg.fg(theme::GREEN).add_modifier(Modifier::BOLD),
        ),
        Some(false) => (
            "●",
            "OFFLINE",
            bg.fg(theme::RED).add_modifier(Modifier::BOLD),
        ),
        None => ("◌", "CONNECTING", bg.fg(theme::AMBER)),
    };
    let latency = match (app.online, app.latency) {
        (Some(true), Some(l)) => format!(" {}ms", l.as_millis()),
        _ => String::new(),
    };
    let sep = bg.fg(theme::DEEP);
    let segments: Vec<Vec<(String, Style)>> = vec![
        vec![(version, bg.fg(theme::DIM))],
        vec![
            ("│ ".to_string(), sep),
            ("workspace ".to_string(), bg.fg(theme::DIM)),
            (workspace, bg.fg(theme::GLOW)),
            (" ".to_string(), bg),
        ],
        vec![
            ("│ ".to_string(), sep),
            (format!("{dot} {state}"), state_style),
            (latency, bg.fg(theme::DIM)),
            (" ".to_string(), bg),
        ],
        vec![
            ("│ ".to_string(), sep),
            ("api ".to_string(), bg.fg(theme::DIM)),
            (app.opts.api.authority().to_string(), bg.fg(theme::DIM)),
            (" ".to_string(), bg),
        ],
    ];
    for seg in segments {
        let w: usize = seg.iter().map(|(s, _)| width(s)).sum();
        if x as usize + w > limit as usize {
            break;
        }
        for (s, style) in seg {
            x = put(buf, x, y, &s, style);
        }
    }
    if app.loading() && x + 3 < limit {
        put(
            buf,
            x,
            y,
            format!("│ {} ", spinner(app.frame)),
            bg.fg(theme::AMBER),
        );
    }
}

fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn draw_tabs(buf: &mut Buffer, app: &mut App, area: Rect) {
    fill(buf, area, theme::base());
    let n = app.pages.len();
    if n == 0 {
        return;
    }
    let labels: Vec<String> = app
        .pages
        .iter()
        .map(|p| format!(" {} ", text::truncate(&p.display_title(), 16)))
        .collect();
    let widths: Vec<usize> = labels.iter().map(|l| width(l)).collect();
    let avail = (area.width as usize).saturating_sub(4);
    let cur = app.current.min(n - 1);
    let (mut start, mut end) = (cur, cur + 1);
    let mut used = widths[cur];
    loop {
        let mut grew = false;
        if end < n && used + 1 + widths[end] <= avail {
            used += 1 + widths[end];
            end += 1;
            grew = true;
        }
        if start > 0 && used + 1 + widths[start - 1] <= avail {
            used += 1 + widths[start - 1];
            start -= 1;
            grew = true;
        }
        if !grew {
            break;
        }
    }
    let y = area.y;
    let mut x = area.x + 1;
    if start > 0 {
        put(buf, area.x, y, "◀", theme::dim());
    }
    for i in start..end {
        let active = i == cur;
        let failed = matches!(app.panes[i].status, Status::Failed(_));
        let style = if active {
            Style::new()
                .bg(theme::GREEN)
                .fg(theme::BLACK)
                .add_modifier(Modifier::BOLD)
        } else if failed {
            Style::new().fg(theme::RED)
        } else {
            theme::dim()
        };
        let w = widths[i] as u16;
        app.hit.tabs.push((Rect::new(x, y, w, 1), i));
        put(buf, x, y, &labels[i], style);
        x += w + 1;
    }
    if end < n {
        put(buf, area.right().saturating_sub(2), y, "▶", theme::dim());
    }
    // A faint rule completes the strip.
    let rule_end = if end < n {
        area.right().saturating_sub(3)
    } else {
        area.right()
    };
    if x < rule_end {
        let rule: String = "─".repeat((rule_end - x) as usize);
        put(buf, x, y, rule, theme::deep());
    }
}

fn panel(title: &str, active: bool) -> Block<'static> {
    let (border, title_style) = if active {
        (theme::dim(), theme::glow())
    } else {
        (theme::deep(), theme::dim().add_modifier(Modifier::BOLD))
    };
    Block::bordered()
        .border_type(BorderType::Plain)
        .border_style(border)
        .title(Span::styled(format!(" {title} "), title_style))
}

fn draw_sidebar(buf: &mut Buffer, app: &mut App, area: Rect) {
    let n = app.pages.len() as u16;
    let mut focus: Vec<(&str, String, FocusTarget)> = app
        .meta
        .as_ref()
        .map(|m| {
            let f = &m.focus;
            let mut v = Vec::new();
            if let Some(i) = &f.incident {
                let id = f.incident_id.clone().unwrap_or_else(|| i.clone());
                v.push(("⚑", i.clone(), FocusTarget::Inspect(id)));
            }
            if let Some(s) = &f.subject {
                let id = f.subject_id.clone().unwrap_or_else(|| s.clone());
                v.push(("◉", s.clone(), FocusTarget::Inspect(id)));
            }
            if let Some(t) = &f.target {
                let id = f.target_id.clone().unwrap_or_else(|| t.clone());
                v.push(("◎", t.clone(), FocusTarget::Inspect(id)));
            }
            v
        })
        .unwrap_or_default();
    // The current page's parameter, below the story focus.
    if let Some(page) = app.pages.get(app.current)
        && page.param.is_some()
    {
        let value = app
            .param_value(app.current)
            .unwrap_or_else(|| "(default)".to_string());
        focus.push(("❯", value, FocusTarget::EditParam));
    }
    let stats: Vec<(&str, u64)> = app
        .meta
        .as_ref()
        .map(|m| {
            let s = &m.stats;
            [
                ("objects", s.objects),
                ("relationships", s.relationships),
                ("events", s.events),
                ("open findings", s.findings_open),
                ("incidents", s.incidents),
            ]
            .into_iter()
            .filter_map(|(k, v)| v.map(|v| (k, v)))
            .collect()
        })
        .unwrap_or_default();

    let pages_h = (n + 2).min(area.height);
    let mut rest = area.height - pages_h;
    let focus_h = if !focus.is_empty() && rest >= focus.len() as u16 + 2 {
        focus.len() as u16 + 2
    } else {
        0
    };
    rest -= focus_h;
    let stats_h = if !stats.is_empty() && rest >= stats.len() as u16 + 2 {
        stats.len() as u16 + 2
    } else {
        0
    };
    rest -= stats_h;
    let signal_rows = (app.signal.len() as u16).min(rest.saturating_sub(2));
    let signal_h = if signal_rows > 0 { signal_rows + 2 } else { 0 };

    // PAGES
    let pages_area = Rect::new(area.x, area.y, area.width, pages_h);
    let block = panel("◢ PAGES", true);
    let inner = block.inner(pages_area);
    block.render(pages_area, buf);
    let visible = inner.height as usize;
    let offset = (app.current + 1).saturating_sub(visible);
    for (row, i) in (offset..app.pages.len()).take(visible).enumerate() {
        let y = inner.y + row as u16;
        let active = i == app.current;
        let line = Rect::new(inner.x, y, inner.width, 1);
        if active {
            fill(buf, line, Style::new().bg(theme::CURSOR_BG));
        }
        let key = match i {
            0..=8 => char::from(b'1' + i as u8),
            9 => '0',
            _ => ' ',
        };
        let bg = if active {
            Style::new().bg(theme::CURSOR_BG)
        } else {
            Style::new()
        };
        let mut x = inner.x;
        x = put(
            buf,
            x,
            y,
            if active { "▶" } else { " " },
            bg.fg(theme::GREEN).add_modifier(Modifier::BOLD),
        );
        x = put(buf, x, y, format!("{key}  "), bg.fg(theme::DIM));
        let title_style = if active {
            bg.fg(theme::GLOW).add_modifier(Modifier::BOLD)
        } else {
            bg.fg(theme::SOFT)
        };
        let title = app.pages[i].display_title();
        put_n(
            buf,
            x,
            y,
            &title,
            (inner.right() - x).saturating_sub(2) as usize,
            title_style,
        );
        let status = match &app.panes[i].status {
            Status::Loading(_) => Some((spinner(app.frame).to_string(), bg.fg(theme::AMBER))),
            Status::Failed(_) => Some(("✖".to_string(), bg.fg(theme::RED))),
            _ => None,
        };
        if let Some((s, style)) = status {
            put(buf, inner.right().saturating_sub(1), y, s, style);
        }
        app.hit.sidebar.push((line, i));
    }

    let mut y = area.y + pages_h;
    if focus_h > 0 {
        let a = Rect::new(area.x, y, area.width, focus_h);
        let block = panel("FOCUS", false);
        let inner = block.inner(a);
        block.render(a, buf);
        for (row, (glyph, label, target)) in focus.into_iter().enumerate() {
            let ly = inner.y + row as u16;
            let glyph_style = match glyph {
                "⚑" => Style::new().fg(theme::AMBER),
                "◎" => Style::new().fg(theme::RED),
                "❯" => theme::bold(),
                _ => theme::text(),
            };
            let x = put(buf, inner.x + 1, ly, format!("{glyph} "), glyph_style);
            put_n(
                buf,
                x,
                ly,
                &label,
                (inner.right() - x) as usize,
                theme::text(),
            );
            app.hit
                .focus
                .push((Rect::new(inner.x, ly, inner.width, 1), target));
        }
        y += focus_h;
    }
    if stats_h > 0 {
        let a = Rect::new(area.x, y, area.width, stats_h);
        let block = panel("WORLD", false);
        let inner = block.inner(a);
        block.render(a, buf);
        for (row, (k, v)) in stats.into_iter().enumerate() {
            let ly = inner.y + row as u16;
            put_n(buf, inner.x + 1, ly, k, inner.width as usize, theme::dim());
            let val = v.to_string();
            let vx = inner.right().saturating_sub(width(&val) as u16 + 1);
            put(buf, vx, ly, &val, theme::glow());
        }
        y += stats_h;
    }
    if signal_h > 0 {
        let a = Rect::new(area.x, y, area.width, signal_h);
        let block = panel("SIGNAL", false);
        let inner = block.inner(a);
        block.render(a, buf);
        for (row, sig) in app.signal.iter().take(signal_rows as usize).enumerate() {
            let ly = inner.y + row as u16;
            let (mark, mark_style) = if sig.ok {
                ("✔", theme::text())
            } else {
                ("✖", Style::new().fg(theme::RED))
            };
            let x = put(buf, inner.x + 1, ly, format!("{mark} "), mark_style);
            let detail_w = width(&sig.detail) as u16;
            let dx = inner.right().saturating_sub(detail_w + 1);
            put_n(
                buf,
                x,
                ly,
                &sig.label,
                dx.saturating_sub(x + 1) as usize,
                theme::body(),
            );
            let detail_style = if sig.ok {
                theme::dim()
            } else {
                Style::new().fg(theme::AMBER)
            };
            put(buf, dx, ly, &sig.detail, detail_style);
        }
    }
}

/// Draws a document viewport: gutter (cursor `▌`, clickable `›`), text, scrollbar.
pub fn draw_doc(buf: &mut Buffer, area: Rect, view: &DocView, show_cursor: bool) -> Viewport {
    let text_area = Rect::new(
        area.x + 1,
        area.y,
        area.width.saturating_sub(3),
        area.height,
    );
    let Some(doc) = &view.doc else {
        return Viewport {
            text: text_area,
            scrollbar: None,
        };
    };
    let h = area.height as usize;
    for row in 0..h {
        let i = view.scroll + row;
        if i >= doc.len() {
            break;
        }
        let y = area.y + row as u16;
        let dl = &doc.lines[i];
        if show_cursor && i == view.cursor {
            let band = Rect::new(area.x, y, area.width.saturating_sub(1), 1);
            buf.set_style(band, Style::new().bg(theme::CURSOR_BG));
            put(buf, area.x, y, "▌", theme::bold().bg(theme::CURSOR_BG));
        } else if doc.is_clickable(i) {
            put(buf, area.x, y, "›", theme::dim());
        }
        let line = if dl.wide {
            Line::from(text::slice_spans(
                &dl.line.spans,
                view.hscroll,
                text_area.width as usize,
            ))
        } else {
            dl.line.clone()
        };
        buf.set_line(text_area.x, y, &line, text_area.width);
    }
    let scrollbar = (doc.len() > h && h > 0).then(|| {
        let bar = Rect::new(area.right().saturating_sub(1), area.y, 1, area.height);
        let len = doc.len();
        let thumb = (h * h / len).clamp(1, h);
        let max_scroll = len - h;
        let pos = (view.scroll.min(max_scroll) * (h - thumb))
            .checked_div(max_scroll)
            .unwrap_or(0);
        for row in 0..h {
            let (ch, style) = if row >= pos && row < pos + thumb {
                ("┃", theme::text())
            } else {
                ("│", theme::deep())
            };
            put(buf, bar.x, bar.y + row as u16, ch, style);
        }
        bar
    });
    Viewport {
        text: text_area,
        scrollbar,
    }
}

fn draw_loading(buf: &mut Buffer, area: Rect, what: &str, frame: u64) {
    if area.height == 0 || area.width < 10 {
        return;
    }
    let line = format!("{}  DECRYPTING {} …", spinner(frame), what.to_uppercase());
    let y = area.y + area.height.saturating_sub(3) / 2;
    let x = area.x + area.width.saturating_sub(width(&line) as u16) / 2;
    put_n(buf, x, y, &line, area.width as usize, theme::glow());
    let mut rng = Rng::new(frame / 2 + 1);
    let n = ((area.width as usize).saturating_sub(4) / 3).min(16);
    let hex: Vec<String> = (0..n).map(|_| format!("{:02X}", rng.below(256))).collect();
    let hex = hex.join(" ");
    let hx = area.x + area.width.saturating_sub(width(&hex) as u16) / 2;
    put(buf, hx, y + 2, &hex, theme::dim());
}

fn draw_content(f: &mut Frame, app: &mut App, area: Rect) {
    let idx = app.current.min(app.pages.len().saturating_sub(1));
    let page = app.pages[idx].clone();
    let probe = panel("", true);
    let inner = probe.inner(area);
    let mut doc_area = inner;
    let param_row = page.param.is_some() && inner.height > 3;
    if param_row {
        doc_area = Rect::new(inner.x, inner.y + 1, inner.width, inner.height - 1);
    }
    let text_w = doc_area.width.saturating_sub(3) as usize;
    let height = doc_area.height as usize;
    app.content_height = height.max(1);
    app.content_width = text_w.max(1);
    let vertical = app.graph_vertical;
    let frame = app.frame;
    let pane = &mut app.panes[idx];
    let has_doc = pane.ensure_doc(text_w.max(crate::render::MIN_WIDTH), vertical, height);

    // Frame titles: page name; position; cursor reference and horizontal scroll.
    let mut block = panel(&format!("◈ {}", page.display_title()), true);
    if has_doc && let Some(doc) = &pane.view.doc {
        let pos = format!(" {}/{} ", pane.view.cursor + 1, doc.len());
        block = block.title(Line::from(Span::styled(pos, theme::dim())).right_aligned());
        if let Some(r) = doc.reference(pane.view.cursor) {
            let r = text::truncate(r, (area.width as usize).saturating_sub(30));
            block = block.title_bottom(Line::from(vec![
                Span::styled(" ⏎ ", theme::text()),
                Span::styled(r, theme::citation()),
                Span::raw(" "),
            ]));
        }
        let wide = doc.wide_width();
        if wide > text_w {
            let first = pane.view.hscroll + 1;
            let last = (pane.view.hscroll + text_w).min(wide);
            let left = if pane.view.hscroll > 0 { "◀" } else { " " };
            let right = if last < wide { "▶" } else { " " };
            block = block.title_bottom(
                Line::from(Span::styled(
                    format!(" {left} cols {first}–{last} of {wide} {right} [ ] "),
                    Style::new().fg(theme::AMBER),
                ))
                .right_aligned(),
            );
        }
    } else if let Status::Loading(_) = pane.status {
        block = block.title(
            Line::from(Span::styled(
                format!(" {} ", spinner(frame)),
                Style::new().fg(theme::AMBER),
            ))
            .right_aligned(),
        );
    }
    block.render(area, f.buffer_mut());

    if param_row {
        let bar = Rect::new(inner.x, inner.y, inner.width, 1);
        draw_param_bar(f, app, idx, bar);
    }
    let pane = &app.panes[idx];
    if has_doc {
        let vp = draw_doc(
            f.buffer_mut(),
            doc_area,
            &pane.view,
            app.inspector.is_empty(),
        );
        app.hit.content = Some(vp);
    } else {
        draw_loading(f.buffer_mut(), doc_area, &page.display_title(), frame);
    }
}

fn draw_param_bar(f: &mut Frame, app: &mut App, idx: usize, area: Rect) {
    let Some(spec) = app.pages[idx].param.clone() else {
        return;
    };
    let editing = app.input.as_ref().filter(|i| i.page == idx).cloned();
    let bg = if editing.is_some() {
        theme::CURSOR_BG
    } else {
        theme::ABYSS
    };
    let base = Style::new().bg(bg);
    fill(f.buffer_mut(), area, base.fg(theme::GREEN));
    let y = area.y;
    let label = spec.label.clone().unwrap_or_else(|| spec.name.clone());
    let label = text::truncate(&label, (area.width as usize) / 3);
    let mut x = put(
        f.buffer_mut(),
        area.x,
        y,
        format!(" {label} "),
        base.fg(theme::DIM),
    );
    x = put(
        f.buffer_mut(),
        x,
        y,
        "❯ ",
        base.fg(theme::GREEN).add_modifier(Modifier::BOLD),
    );
    let hint = if editing.is_some() {
        " ⏎ load · esc cancel "
    } else {
        " / edit "
    };
    let hint_x = area.right().saturating_sub(width(hint) as u16);
    put(f.buffer_mut(), hint_x, y, hint, base.fg(theme::DIM));
    let avail = hint_x.saturating_sub(x + 1) as usize;
    app.hit.param = Some(area);
    app.hit.param_text_x = x;
    match editing {
        Some(input) => {
            let col = input.cursor_col();
            let avail = avail.max(1);
            let offset = (col + 1).saturating_sub(avail);
            let value: String = input.value();
            let visible = text::slice_spans(&[Span::raw(value)], offset, avail);
            let line = Line::from(visible).style(base.fg(theme::GLOW));
            f.buffer_mut().set_line(x, y, &line, avail as u16);
            let cx = x + col.saturating_sub(offset) as u16;
            if let Some(cell) = f.buffer_mut().cell_mut((cx, y)) {
                cell.set_style(Style::new().add_modifier(Modifier::REVERSED));
            }
            f.set_cursor_position(Position::new(cx, y));
        }
        None => match app.param_value(idx) {
            Some(v) => {
                put_n(
                    f.buffer_mut(),
                    x,
                    y,
                    &v,
                    avail,
                    base.fg(theme::GLOW).add_modifier(Modifier::BOLD),
                );
            }
            None => {
                put_n(
                    f.buffer_mut(),
                    x,
                    y,
                    "(default)",
                    avail,
                    base.fg(theme::DIM).add_modifier(Modifier::ITALIC),
                );
            }
        },
    }
}

fn draw_inspector(f: &mut Frame, app: &mut App, area: Rect) {
    let w = (area.width * 7 / 10)
        .max(60)
        .min(area.width.saturating_sub(2));
    let h = (area.height * 7 / 10)
        .max(16)
        .min(area.height.saturating_sub(2));
    let popup = Rect::new(
        area.x + (area.width - w) / 2,
        area.y + (area.height - h) / 2,
        w,
        h,
    );
    Clear.render(popup, f.buffer_mut());
    fill(f.buffer_mut(), popup, theme::base());
    let crumbs: Vec<String> = app.inspector.iter().map(|e| e.reference.clone()).collect();
    let mut trail = crumbs.join(" ▸ ");
    let room = (w as usize).saturating_sub(20);
    if width(&trail) > room {
        let last = crumbs.last().cloned().unwrap_or_default();
        trail = format!("… ▸ {}", text::truncate(&last, room.saturating_sub(4)));
    }
    let mut block = Block::bordered()
        .border_type(BorderType::Double)
        .border_style(theme::bold())
        .title(Line::from(vec![
            Span::styled(" ◈ INSPECT ", theme::glow()),
            Span::styled("▸ ", theme::text()),
            Span::styled(trail, theme::citation()),
            Span::raw(" "),
        ]))
        .title_bottom(Line::from(vec![
            Span::styled(" g", theme::glow()),
            Span::styled(" graph · ", theme::dim()),
            Span::styled("b", theme::glow()),
            Span::styled(" blast · ", theme::dim()),
            Span::styled("t", theme::glow()),
            Span::styled(" timeline · ", theme::dim()),
            Span::styled("I", theme::glow()),
            Span::styled(" iam · ", theme::dim()),
            Span::styled("⌫", theme::glow()),
            Span::styled(" back · ", theme::dim()),
            Span::styled("esc", theme::glow()),
            Span::styled(" close ", theme::dim()),
        ]));
    let inner = block.inner(popup);
    let text_w = inner.width.saturating_sub(3) as usize;
    app.popup_height = (inner.height as usize).max(1);
    app.popup_width = text_w.max(1);
    let vertical = app.graph_vertical;
    let frame = app.frame;
    let Some(top) = app.inspector.last_mut() else {
        return;
    };
    let has_doc = top.pane.ensure_doc(
        text_w.max(crate::render::MIN_WIDTH),
        vertical,
        inner.height as usize,
    );
    if let Some(doc) = top.pane.view.doc.as_ref().filter(|_| has_doc) {
        let pos = format!(" {}/{} ", top.pane.view.cursor + 1, doc.len());
        block = block.title(Line::from(Span::styled(pos, theme::dim())).right_aligned());
    }
    block.render(popup, f.buffer_mut());
    if has_doc {
        let vp = draw_doc(f.buffer_mut(), inner, &top.pane.view, true);
        app.hit.popup_view = Some(vp);
    } else {
        let reference = top.reference.clone();
        draw_loading(f.buffer_mut(), inner, &reference, frame);
    }
    app.hit.popup = Some(popup);
}

/// Help overlay content: (key, description); empty key = section title.
pub const HELP: &[(&str, &str)] = &[
    ("", "NAVIGATION"),
    ("← →  h l  Tab ⇧Tab", "previous / next page"),
    ("1 … 9  0", "jump to page"),
    ("↑ ↓  j k", "move the line cursor"),
    ("PgUp PgDn  Home End  g G", "page / top / bottom"),
    ("[  ]", "scroll wide diagrams sideways"),
    ("n  N", "next / previous reference"),
    ("", "ACTIONS"),
    ("⏎  i", "inspect the reference on the cursor line (›)"),
    ("/  s", "edit the page parameter (⏎ load, esc cancel)"),
    ("r", "reload (bypasses the cache)"),
    ("v", "graph: layered diagram ⇄ list"),
    ("m", "digital rain on / off"),
    ("?", "this help"),
    ("q  Esc  Ctrl-C", "quit"),
    ("", "INSPECTOR"),
    (
        "g  b  t  I",
        "open GRAPH / BLAST / TIMELINE / IAM for the object",
    ),
    ("⌫  ←", "back"),
    ("Esc  q", "close"),
    ("", "MOUSE"),
    ("click", "tab or page: switch · line: move the cursor"),
    ("click ›", "open the inspector (graph boxes too)"),
    ("wheel  ⇧wheel", "scroll · scroll sideways"),
    (
        "click parameter",
        "edit it · click outside a popup: close it",
    ),
];

fn draw_help(buf: &mut Buffer, app: &mut App, area: Rect) {
    let key_w = HELP.iter().map(|(k, _)| width(k)).max().unwrap_or(0) + 3;
    let desc_w = HELP.iter().map(|(_, d)| width(d)).max().unwrap_or(0);
    let w = ((key_w + desc_w + 6) as u16).min(area.width.saturating_sub(2));
    let h = ((HELP.len() + 4) as u16).min(area.height.saturating_sub(2));
    let popup = Rect::new(
        area.x + (area.width - w) / 2,
        area.y + (area.height - h) / 2,
        w,
        h,
    );
    Clear.render(popup, buf);
    fill(buf, popup, theme::base());
    let block = Block::bordered()
        .border_type(BorderType::Double)
        .border_style(theme::bold())
        .title(Span::styled(" ◈ R$F OS · CONTROLS ", theme::glow()))
        .title_bottom(Line::from(Span::styled(" any key closes ", theme::dim())).right_aligned());
    let inner = block.inner(popup);
    block.render(popup, buf);
    for (y, (k, d)) in (inner.y + 1..).zip(HELP.iter()) {
        if y >= inner.bottom() {
            break;
        }
        if k.is_empty() {
            put(buf, inner.x + 2, y, *d, theme::section());
        } else {
            put(buf, inner.x + 2, y, *k, theme::glow());
            put_n(
                buf,
                inner.x + 2 + key_w as u16,
                y,
                d,
                (inner.width as usize).saturating_sub(key_w + 3),
                theme::body(),
            );
        }
    }
    app.hit.help = Some(popup);
}

fn draw_status(buf: &mut Buffer, app: &App, area: Rect) {
    let bg = bar_style();
    fill(buf, area, bg);
    let y = area.y;
    // Right: activity and position.
    let mut right = format!(" {}/{} ", app.current + 1, app.pages.len());
    if app.loading() {
        right = format!(" {} decrypting… │{right}", spinner(app.frame));
    }
    let rx = area.right().saturating_sub(width(&right) as u16);
    put(
        buf,
        rx,
        y,
        &right,
        bg.fg(if app.loading() {
            theme::AMBER
        } else {
            theme::DIM
        }),
    );
    let limit = rx.saturating_sub(1) as usize;

    let mut x = area.x + 1;
    if let Some(msg) = app.message.as_ref().filter(|_| app.input.is_none()) {
        let style = if msg.error {
            bg.fg(theme::AMBER).add_modifier(Modifier::BOLD)
        } else {
            bg.fg(theme::GLOW)
        };
        put_n(
            buf,
            x,
            y,
            &msg.text,
            limit.saturating_sub(x as usize),
            style,
        );
        return;
    }
    let hints: &[(&str, &str)] = if app.help {
        &[("any key", "closes the help")]
    } else if app.input.is_some() {
        &[
            ("⏎", "load"),
            ("esc", "cancel"),
            ("←→", "move"),
            ("⌫", "delete"),
            ("^U", "clear"),
        ]
    } else if !app.inspector.is_empty() {
        &[
            ("↑↓", "line"),
            ("⏎", "open"),
            ("⌫", "back"),
            ("g", "graph"),
            ("b", "blast"),
            ("t", "timeline"),
            ("I", "iam"),
            ("esc", "close"),
        ]
    } else {
        &[
            ("←→", "pages"),
            ("↑↓", "line"),
            ("⏎", "inspect"),
            ("/", "param"),
            ("r", "reload"),
            ("v", "graph"),
            ("m", "rain"),
            ("?", "help"),
            ("q", "quit"),
        ]
    };
    for (k, d) in hints {
        let w = width(k) + width(d) + 3;
        if x as usize + w > limit {
            break;
        }
        x = put(
            buf,
            x,
            y,
            *k,
            bg.fg(theme::GLOW).add_modifier(Modifier::BOLD),
        );
        x = put(buf, x, y, format!(" {d}  "), bg.fg(theme::DIM));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::tests_support::{serve_all, test_app};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn frame_text(terminal: &Terminal<TestBackend>) -> String {
        let buf = terminal.backend().buffer();
        let mut out = String::new();
        for y in 0..buf.area.height {
            let mut line = String::new();
            let mut skip = 0;
            for x in 0..buf.area.width {
                if skip > 0 {
                    skip -= 1;
                    continue;
                }
                let sym = buf[(x, y)].symbol();
                skip = width(sym).saturating_sub(1);
                line.push_str(sym);
            }
            out.push_str(line.trim_end());
            out.push('\n');
        }
        out
    }

    fn render(app: &mut App, w: u16, h: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| draw(f, app)).unwrap();
        frame_text(&terminal)
    }

    #[test]
    fn main_layout_at_several_sizes() {
        for (w, h) in [(80, 24), (120, 40), (200, 60)] {
            let mut app = test_app();
            serve_all(&mut app);
            let text = render(&mut app, w, h);
            assert!(text.contains(" R$F OS "), "{text}");
            assert!(text.contains("HOME"), "{text}");
            assert!(text.contains("PAGES"), "{text}");
            assert!(text.contains("Every security capability"), "{text}");
            assert!(text.contains("←→ pages"), "{text}");
            assert!(app.hit.content.is_some());
            assert!(!app.hit.tabs.is_empty());
            assert_eq!(app.hit.sidebar.len().min(12), app.hit.sidebar.len());
        }
    }

    #[test]
    fn focus_incident_inspects_by_id() {
        let mut app = test_app();
        serve_all(&mut app);
        let _ = render(&mut app, 120, 40);
        let targets: Vec<FocusTarget> = app.hit.focus.iter().map(|(_, t)| t.clone()).collect();
        assert!(
            targets.contains(&FocusTarget::Inspect("incident:inc-001".into())),
            "{targets:?}"
        );
        assert!(targets.contains(&FocusTarget::Inspect("user:bob".into())));
        assert!(targets.contains(&FocusTarget::Inspect("cloud_resource:production".into())));
    }

    #[test]
    fn too_small_terminal() {
        let mut app = test_app();
        let text = render(&mut app, 60, 20);
        assert!(text.contains("terminal too small"), "{text}");
        assert!(text.contains("60×20"), "{text}");
    }

    #[test]
    fn every_page_inspector_and_help_render() {
        let mut app = test_app();
        serve_all(&mut app);
        for i in 0..app.pages.len() {
            app.switch_page(i);
            serve_all(&mut app);
            let text = render(&mut app, 140, 45);
            let title = app.pages[i].display_title();
            assert!(text.contains(&format!("◈ {title}")), "{title}:\n{text}");
        }
        app.inspect("host:dev-01");
        serve_all(&mut app);
        let text = render(&mut app, 140, 45);
        assert!(text.contains("INSPECT"), "{text}");
        assert!(text.contains("HOST DEV-01"), "{text}");
        assert!(app.hit.popup.is_some());
        app.help = true;
        let text = render(&mut app, 140, 45);
        assert!(text.contains("CONTROLS"), "{text}");
    }

    #[test]
    fn loading_and_error_states_render() {
        let mut app = test_app();
        let text = render(&mut app, 100, 30);
        assert!(text.contains("DECRYPTING HOME"), "{text}");
        app.handle(crate::app::AppEvent::Api(Box::new(crate::api::Response {
            id: 2,
            request: crate::api::Request::Screen {
                page: "home".into(),
                param: None,
            },
            result: Err(crate::api::ApiError::Unreachable {
                url: "http://127.0.0.1:9/api/v1".into(),
                detail: "connection refused".into(),
            }),
            elapsed: std::time::Duration::from_millis(1),
        })));
        let text = render(&mut app, 100, 30);
        assert!(text.contains("R$F API UNREACHABLE"), "{text}");
        assert!(text.contains("OFFLINE"), "{text}");
    }

    /// Prints frames for eyeballing: `cargo test preview -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn preview() {
        let mut app = test_app();
        serve_all(&mut app);
        let (w, h) = (
            std::env::var("W")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(120),
            std::env::var("H")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(36),
        );
        let page = std::env::var("PAGE").unwrap_or_else(|_| "home".into());
        let idx = app.pages.iter().position(|p| p.id == page).unwrap_or(0);
        app.switch_page(idx);
        serve_all(&mut app);
        for _ in 0..std::env::var("DOWN")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
        {
            app.on_key(ratatui::crossterm::event::KeyEvent::from(
                ratatui::crossterm::event::KeyCode::Down,
            ));
        }
        if std::env::var("INSPECT").is_ok() {
            app.inspect("host:dev-01");
            serve_all(&mut app);
        }
        if std::env::var("HELP").is_ok() {
            app.help = true;
        }
        if std::env::var("EDIT").is_ok() {
            app.on_key(ratatui::crossterm::event::KeyEvent::from(
                ratatui::crossterm::event::KeyCode::Char('/'),
            ));
        }
        let _ = render(&mut app, w, h);
        println!("{}", render(&mut app, w, h));
    }

    #[test]
    fn put_never_panics_out_of_bounds() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 10, 2));
        assert_eq!(put(&mut buf, 3, 5, "x", theme::text()), 3);
        assert_eq!(put(&mut buf, 30, 0, "x", theme::text()), 30);
        assert_eq!(put(&mut buf, 8, 1, "abcdef", theme::text()), 10);
        assert_eq!(put_n(&mut buf, 0, 0, "abcdef", 3, theme::text()), 3);
    }
}
