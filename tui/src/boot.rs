//! The boot sequence: full-screen digital rain, the "R$F OS" logo resolving out of random
//! glyphs, then a boot log built from `/tui/pages` (`[ OK ]`, or `[FAIL]` with the reason when
//! the API is unreachable). Any key or click skips it.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};

use crate::api::ApiError;
use crate::model::PagesDoc;
use crate::rain::{Rain, Rng, glyph};
use crate::text::{self, width};
use crate::theme;
use crate::ui::put;

/// The big logo (ANSI Shadow letters; the `$` is an S with a stroke).
pub const LOGO: [&str; 8] = [
    "           ▄▄",
    "██████╗ ███████╗███████╗     ██████╗ ███████╗",
    "██╔══██╗██╔════╝██╔════╝    ██╔═══██╗██╔════╝",
    "██████╔╝███████╗█████╗      ██║   ██║███████╗",
    "██╔══██╗╚════██║██╔══╝      ██║   ██║╚════██║",
    "██║  ██║███████║██║         ╚██████╔╝███████║",
    "╚═╝  ╚═╝╚══════╝╚═╝          ╚═════╝ ╚══════╝",
    "           ▀▀",
];

const TAGLINE: &str = "EVERY SECURITY CAPABILITY · ONE COMMAND AWAY";
const SPINNER: [char; 8] = ['⣾', '⣽', '⣻', '⢿', '⡿', '⣟', '⣯', '⣷'];

const LOGO_START: f32 = 0.35;
const LOGO_SWEEP: f32 = 0.75;
const LINES_START: f32 = 1.45;
const LINE_GAP: f32 = 0.13;
const TYPE_TIME: f32 = 0.16;
const HOLD: f32 = 1.1;
const GIVE_UP: f32 = 8.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineKind {
    Header,
    Ok,
    Fail,
    Warn,
    Wait,
    Final,
}

#[derive(Debug, Clone)]
pub struct BootLine {
    pub kind: LineKind,
    pub label: String,
    pub value: String,
    start: Option<f32>,
}

impl BootLine {
    fn new(kind: LineKind, label: &str, value: impl Into<String>) -> BootLine {
        BootLine {
            kind,
            label: label.to_string(),
            value: value.into(),
            start: None,
        }
    }

    /// Plain text of the line (as it reads once fully typed).
    pub fn plain(&self) -> String {
        match self.kind {
            LineKind::Header | LineKind::Final => self.value.clone(),
            _ => format!(
                "{} {} {}",
                tag(self.kind),
                dotted(&self.label, LABEL_W),
                self.value
            ),
        }
    }
}

const LABEL_W: usize = 23;

fn tag(kind: LineKind) -> &'static str {
    match kind {
        LineKind::Ok => "[ OK ]",
        LineKind::Fail => "[FAIL]",
        LineKind::Warn => "[WARN]",
        LineKind::Wait => "[ .. ]",
        LineKind::Header | LineKind::Final => "",
    }
}

fn dotted(label: &str, w: usize) -> String {
    let label = text::truncate(label, w.saturating_sub(2));
    let dots = w.saturating_sub(width(&label) + 1);
    format!("{label} {}", "·".repeat(dots))
}

struct LogoCell {
    x: u16,
    y: u16,
    ch: char,
    reveal: f32,
}

/// Boot sequence state.
pub struct Boot {
    rain: Rain,
    rng: Rng,
    logo: Vec<LogoCell>,
    pub lines: Vec<BootLine>,
    revealed: usize,
    next_at: f32,
    has_data: bool,
    done_at: Option<f32>,
    skipped: bool,
    steps: u64,
    now: f32,
}

impl Boot {
    /// `api` is shown in the API link line; `terminal` describes the terminal (size, colors).
    pub fn new(api: &str, terminal: &str) -> Boot {
        let mut rng = Rng::new(0x52_24_46);
        let logo_w = LOGO.iter().map(|l| width(l)).max().unwrap_or(1) as f32;
        let mut logo = Vec::new();
        for (y, row) in LOGO.iter().enumerate() {
            for (x, ch) in row.chars().enumerate() {
                if ch != ' ' {
                    let sweep = x as f32 / logo_w * LOGO_SWEEP;
                    logo.push(LogoCell {
                        x: x as u16,
                        y: y as u16,
                        ch,
                        reveal: LOGO_START + sweep + rng.range(0.0, 0.3),
                    });
                }
            }
        }
        let lines = vec![
            BootLine::new(
                LineKind::Header,
                "",
                format!(
                    "R$F OS {} · security operations console · defensive use only",
                    crate::VERSION
                ),
            ),
            BootLine::new(LineKind::Ok, "Terminal", terminal),
            BootLine::new(LineKind::Wait, "Kernel link", api),
        ];
        Boot {
            rain: Rain::new(0xF00D),
            rng,
            logo,
            lines,
            revealed: 0,
            next_at: LINES_START,
            has_data: false,
            done_at: None,
            skipped: false,
            steps: 0,
            now: 0.0,
        }
    }

    /// Feeds the `/tui/pages` result into the boot log.
    pub fn set_pages(&mut self, result: Result<&PagesDoc, &ApiError>) {
        if self.has_data {
            return;
        }
        self.has_data = true;
        let link = self
            .lines
            .iter_mut()
            .find(|l| l.label == "Kernel link")
            .expect("link line");
        match result {
            Ok(doc) => {
                link.kind = LineKind::Ok;
                let mut add = |kind, label: &str, value: String| {
                    self.lines.push(BootLine::new(kind, label, value));
                };
                if let Some(ws) = &doc.system.workspace {
                    add(LineKind::Ok, "Workspace", ws.clone());
                }
                let s = &doc.stats;
                let fmt = |v: Option<u64>| v.map_or("?".to_string(), |v| v.to_string());
                add(
                    LineKind::Ok,
                    "Security world model",
                    format!(
                        "{} objects · {} relationships · {} events",
                        fmt(s.objects),
                        fmt(s.relationships),
                        fmt(s.events)
                    ),
                );
                if let (Some(avail), Some(total)) = (doc.system.available, doc.system.products) {
                    let kind = if avail >= total {
                        LineKind::Ok
                    } else {
                        LineKind::Warn
                    };
                    add(kind, "Products", format!("{avail}/{total} online"));
                }
                if s.findings_open.is_some() || s.incidents.is_some() {
                    let plural = if s.incidents == Some(1) { "" } else { "s" };
                    add(
                        LineKind::Ok,
                        "Findings",
                        format!(
                            "{} open · {} incident{plural}",
                            fmt(s.findings_open),
                            fmt(s.incidents)
                        ),
                    );
                }
                if let Some(oracle) = &doc.system.oracle {
                    add(LineKind::Ok, "Oracle", format!("{oracle} reasoner"));
                }
                let f = &doc.focus;
                let mut focus = Vec::new();
                if let Some(i) = &f.incident {
                    focus.push(i.clone());
                }
                match (&f.subject, &f.target) {
                    (Some(s), Some(t)) => focus.push(format!("{s} → {t}")),
                    (Some(s), None) => focus.push(s.clone()),
                    (None, Some(t)) => focus.push(t.clone()),
                    (None, None) => {}
                }
                if !focus.is_empty() {
                    add(LineKind::Ok, "Focus", focus.join(" · "));
                }
                let n = doc.pages.len();
                add(
                    LineKind::Ok,
                    "Screens",
                    format!("{n} page{}", if n == 1 { "" } else { "s" }),
                );
                add(LineKind::Final, "", "ACCESS GRANTED".to_string());
            }
            Err(err) => {
                link.kind = LineKind::Fail;
                link.value = err.summary();
                self.lines.push(BootLine::new(
                    LineKind::Warn,
                    "Offline mode",
                    "the console opens anyway · press r to retry",
                ));
                self.lines.push(BootLine::new(
                    LineKind::Final,
                    "",
                    "ENTERING OFFLINE MODE".to_string(),
                ));
            }
        }
    }

    /// Ends the sequence now.
    pub fn skip(&mut self) {
        self.skipped = true;
    }

    /// True once the sequence is over (or skipped).
    pub fn finished(&self) -> bool {
        self.skipped || self.done_at.is_some_and(|d| self.now >= d)
    }

    /// Advances to `t` seconds after the start.
    pub fn tick(&mut self, t: f32) {
        self.now = t;
        // Rain at 20 steps per second.
        let target = (t * 20.0) as u64;
        let mut budget = 4;
        while self.steps < target && budget > 0 {
            self.rain.step();
            self.steps += 1;
            budget -= 1;
        }
        self.steps = self.steps.max(target.saturating_sub(1));
        // Reveal log lines one by one; nothing passes the API line until data arrived.
        while self.revealed < self.lines.len() && t >= self.next_at {
            let blocked = self.lines[..self.revealed]
                .iter()
                .any(|l| l.kind == LineKind::Wait);
            if blocked && !self.has_data {
                break;
            }
            self.lines[self.revealed].start = Some(self.next_at.max(t - 0.05));
            self.revealed += 1;
            self.next_at = t.max(self.next_at) + LINE_GAP;
        }
        if !self.has_data && t >= GIVE_UP {
            self.has_data = true;
            if let Some(link) = self.lines.iter_mut().find(|l| l.kind == LineKind::Wait) {
                link.kind = LineKind::Warn;
                link.value = format!("{} · still connecting", link.value);
            }
        }
        if self.done_at.is_none() && self.has_data && self.revealed == self.lines.len() {
            self.done_at = Some(t + HOLD);
        }
    }

    /// Draws the boot screen.
    pub fn render(&mut self, area: Rect, buf: &mut Buffer) {
        let t = self.now;
        self.rain.resize(area.width as usize, area.height as usize);
        let fade_in = (t / 0.4).clamp(0.0, 1.0);
        self.rain.render(area, buf, 0.35 + 0.65 * fade_in);
        if area.width < 24 || area.height < 8 {
            return;
        }

        let logo_w = LOGO.iter().map(|l| width(l)).max().unwrap_or(0) as u16;
        let panel_w = (logo_w + 8).max(86).min(area.width.saturating_sub(4));
        // Room for the full log (header, terminal, link, eight data lines, final line).
        let log_rows = self.lines.len().max(13) as u16;
        let show_logo = area.height >= 26 && area.width >= 60;
        let logo_h = if show_logo { LOGO.len() as u16 + 3 } else { 0 };
        let panel_h = (logo_h + log_rows + 2).min(area.height);
        let px = area.x + (area.width - panel_w) / 2;
        let py = area.y + area.height.saturating_sub(panel_h) / 3;
        let panel = Rect::new(px, py, panel_w, panel_h);

        if t >= 0.25 {
            // Clear the panel and give it a faint frame.
            for y in panel.top()..panel.bottom() {
                for x in panel.left()..panel.right() {
                    if let Some(c) = buf.cell_mut((x, y)) {
                        c.set_char(' ');
                        c.set_style(theme::base());
                    }
                }
            }
            let frame = Style::new().fg(theme::DEEP);
            for x in panel.left()..panel.right() {
                set(buf, x, panel.top(), '─', frame);
                set(buf, x, panel.bottom() - 1, '─', frame);
            }
            for y in panel.top()..panel.bottom() {
                set(buf, panel.left(), y, '│', frame);
                set(buf, panel.right() - 1, y, '│', frame);
            }
            set(buf, panel.left(), panel.top(), '┌', frame);
            set(buf, panel.right() - 1, panel.top(), '┐', frame);
            set(buf, panel.left(), panel.bottom() - 1, '└', frame);
            set(buf, panel.right() - 1, panel.bottom() - 1, '┘', frame);
        }

        let mut y = py + 1;
        if show_logo {
            let lx = px + (panel_w.saturating_sub(logo_w)) / 2;
            for cell in &self.logo {
                let (x, cy) = (lx + cell.x, y + cell.y);
                if t >= cell.reveal {
                    let flash = t - cell.reveal < 0.09;
                    let style = if flash {
                        Style::new().fg(theme::GLOW).add_modifier(Modifier::BOLD)
                    } else {
                        Style::new().fg(theme::GREEN).add_modifier(Modifier::BOLD)
                    };
                    set(buf, x, cy, cell.ch, style);
                } else if t >= cell.reveal - 0.55 && t >= 0.25 {
                    let g = glyph(&mut self.rng);
                    let style = Style::new().fg(theme::mix(theme::DEEP, theme::GREEN, 0.6));
                    set(buf, x, cy, g, style);
                }
            }
            y += LOGO.len() as u16 + 1;
            let logo_done = LOGO_START + LOGO_SWEEP + 0.3;
            if t >= logo_done {
                let n = (((t - logo_done) / 0.5) * TAGLINE.chars().count() as f32) as usize;
                let shown: String = TAGLINE.chars().take(n).collect();
                let tx = px + (panel_w.saturating_sub(width(TAGLINE) as u16)) / 2;
                put(buf, tx, y, shown, theme::dim());
            }
            y += 2;
        }

        let lx = px + 3;
        let max_w = panel_w.saturating_sub(6) as usize;
        let spin = SPINNER[(t * 12.0) as usize % SPINNER.len()];
        for line in self.lines.iter().take(self.revealed) {
            if y >= panel.bottom().saturating_sub(1) {
                break;
            }
            let start = line.start.unwrap_or(t);
            let full = line.plain();
            let total = full.chars().count().max(1);
            let shown = (((t - start) / TYPE_TIME).clamp(0.0, 1.0) * total as f32) as usize;
            let visible: String = full.chars().take(shown.max(1)).collect();
            let visible = text::truncate(&visible, max_w);
            match line.kind {
                LineKind::Header => {
                    put(buf, lx, y, visible, theme::glow());
                }
                LineKind::Final => {
                    let blink = ((t * 3.0) as u32).is_multiple_of(2) || t - start < 0.6;
                    let style = if line.value.starts_with("ACCESS") {
                        theme::glow()
                    } else {
                        Style::new().fg(theme::AMBER).add_modifier(Modifier::BOLD)
                    };
                    if blink {
                        put(buf, lx + 7, y + 1, visible, style);
                    }
                    y += 1;
                }
                kind => {
                    let segments = segments(line, kind, spin);
                    draw_typed(buf, lx, y, &segments, shown.max(1), max_w);
                }
            }
            y += 1;
        }

        let hint = "press any key to skip";
        let hx = area.x + area.width.saturating_sub(width(hint) as u16) / 2;
        if area.height > 2 {
            put(buf, hx, area.bottom() - 2, hint, theme::dim());
        }
    }
}

/// Colored parts of a status line: tag, label, dotted leader, value. Their text adds up to
/// [`BootLine::plain`] (character for character), so typing can stop anywhere.
fn segments(line: &BootLine, kind: LineKind, spin: char) -> Vec<(String, Style)> {
    let amber = Style::new().fg(theme::AMBER).add_modifier(Modifier::BOLD);
    let tag_style = match kind {
        LineKind::Ok => theme::bold(),
        LineKind::Fail => Style::new().fg(theme::RED).add_modifier(Modifier::BOLD),
        _ => amber,
    };
    let tag_text = if kind == LineKind::Wait {
        format!("[ {spin}  ]")
    } else {
        tag(kind).to_string()
    };
    let leader = dotted(&line.label, LABEL_W);
    let (name, dots) = leader.split_at(leader.find('·').unwrap_or(leader.len()));
    let value_style = match kind {
        LineKind::Fail => Style::new().fg(theme::RED),
        LineKind::Warn | LineKind::Wait => Style::new().fg(theme::AMBER),
        _ => theme::glow(),
    };
    vec![
        (tag_text, tag_style),
        (" ".to_string(), theme::text()),
        (name.to_string(), theme::text()),
        (dots.to_string(), theme::deep()),
        (" ".to_string(), theme::text()),
        (line.value.clone(), value_style),
    ]
}

/// Draws the first `chars` characters of `segments`, at most `max_w` cells wide.
fn draw_typed(
    buf: &mut Buffer,
    x: u16,
    y: u16,
    segments: &[(String, Style)],
    chars: usize,
    max_w: usize,
) {
    let mut x = x;
    let mut left_chars = chars;
    let mut left_w = max_w;
    for (s, style) in segments {
        if left_chars == 0 || left_w == 0 {
            break;
        }
        let part: String = s.chars().take(left_chars).collect();
        left_chars -= part.chars().count();
        let part = if width(&part) > left_w {
            text::truncate(&part, left_w)
        } else {
            part
        };
        let w = width(&part);
        put(buf, x, y, &part, *style);
        x += w as u16;
        left_w -= w;
    }
}

fn set(buf: &mut Buffer, x: u16, y: u16, ch: char, style: Style) {
    if let Some(c) = buf.cell_mut((x, y)) {
        c.set_char(ch);
        c.set_style(style);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pages() -> PagesDoc {
        serde_json::from_str(
            r#"{"system":{"version":"0.1.0","workspace":"default","products":20,"available":20,"oracle":"builtin"},
                "stats":{"objects":426,"relationships":849,"events":562,"findings_open":42,"incidents":1},
                "focus":{"incident":"INC-001","subject":"bob","subject_id":"user:bob","target":"production","target_id":"cloud_resource:production"},
                "pages":[{"id":"home","title":"HOME","param":null}]}"#,
        )
        .unwrap()
    }

    #[test]
    fn logo_rows_share_a_width() {
        let w: Vec<usize> = LOGO[1..7].iter().map(|l| width(l)).collect();
        assert!(w.iter().all(|&x| x == 45), "{w:?}");
    }

    #[test]
    fn boot_log_from_pages() {
        let mut boot = Boot::new("127.0.0.1:41234", "160×48 · truecolor · mouse");
        boot.set_pages(Ok(&pages()));
        let text: Vec<String> = boot.lines.iter().map(BootLine::plain).collect();
        assert!(
            text.iter()
                .any(|l| l.starts_with("[ OK ] Security world model")
                    && l.ends_with("426 objects · 849 relationships · 562 events")),
            "{text:#?}"
        );
        assert!(text.iter().any(|l| l.ends_with("20/20 online")));
        assert!(
            text.iter()
                .any(|l| l.ends_with("INC-001 · bob → production"))
        );
        assert_eq!(text.last().unwrap(), "ACCESS GRANTED");
        // Runs to completion.
        let mut t = 0.0;
        while !boot.finished() && t < 10.0 {
            t += 0.05;
            boot.tick(t);
            let area = Rect::new(0, 0, 120, 40);
            let mut buf = Buffer::empty(area);
            boot.render(area, &mut buf);
        }
        assert!(boot.finished(), "boot did not finish");
        assert!(t < 5.0, "boot took {t}s");
    }

    #[test]
    fn boot_log_reports_failure() {
        let mut boot = Boot::new("127.0.0.1:9", "80×24");
        let err = ApiError::Unreachable {
            url: "http://127.0.0.1:9/api/v1".into(),
            detail: "connection refused".into(),
        };
        boot.set_pages(Err(&err));
        let text: Vec<String> = boot.lines.iter().map(BootLine::plain).collect();
        assert!(
            text.iter().any(|l| l.starts_with("[FAIL] Kernel link")
                && l.ends_with("R$F API unreachable: connection refused")),
            "{text:#?}"
        );
        assert_eq!(text.last().unwrap(), "ENTERING OFFLINE MODE");
    }

    #[test]
    fn boot_gives_up_waiting_and_skips() {
        let mut boot = Boot::new("x", "y");
        let mut t = 0.0;
        while !boot.finished() && t < 12.0 {
            t += 0.1;
            boot.tick(t);
        }
        assert!(boot.finished());
        assert!(
            boot.lines
                .iter()
                .any(|l| l.value.ends_with("still connecting"))
        );
        let mut b2 = Boot::new("x", "y");
        b2.skip();
        assert!(b2.finished());
    }

    /// `cargo test boot_preview -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn boot_preview() {
        let t_end: f32 = std::env::var("T")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(2.6);
        let mut boot = Boot::new("127.0.0.1:41234", "160×48 · truecolor · mouse");
        let area = Rect::new(0, 0, 110, 34);
        let mut t = 0.0;
        while t < t_end {
            t += 0.05;
            if t > 0.9 && !boot.has_data {
                if std::env::var("FAIL").is_ok() {
                    let err = ApiError::Unreachable {
                        url: "http://127.0.0.1:41234/api/v1".into(),
                        detail: "connection refused".into(),
                    };
                    boot.set_pages(Err(&err));
                } else {
                    boot.set_pages(Ok(&pages()));
                }
            }
            boot.tick(t);
            let mut scratch = Buffer::empty(area);
            boot.render(area, &mut scratch);
        }
        let mut buf = Buffer::empty(area);
        boot.render(area, &mut buf);
        for y in 0..area.height {
            let mut line = String::new();
            for x in 0..area.width {
                line.push_str(buf[(x, y)].symbol());
            }
            println!("{}", line.trim_end());
        }
    }

    #[test]
    fn small_terminals_render_without_panicking() {
        let mut boot = Boot::new("x", "y");
        boot.set_pages(Ok(&pages()));
        for (w, h) in [(1, 1), (20, 5), (59, 25), (80, 24), (300, 100)] {
            for t in [0.0, 0.5, 1.5, 3.0] {
                boot.tick(t);
                let area = Rect::new(0, 0, w, h);
                let mut buf = Buffer::empty(area);
                boot.render(area, &mut buf);
            }
        }
    }
}
