//! The R$F OS palette: phosphor green on black, with severity colors.
//!
//! All colors are 24-bit. On terminals that do not advertise truecolor (`COLORTERM`), the
//! finished frame is mapped to the xterm 256-color palette ([`downsample`]).

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};

use crate::model::{Severity, StyleName};

/// Background of everything.
pub const BLACK: Color = Color::Rgb(0x00, 0x00, 0x00);
/// Phosphor green: primary text.
pub const GREEN: Color = Color::Rgb(0x00, 0xFF, 0x41);
/// Body text: a slightly softer green for long paragraphs.
pub const SOFT: Color = Color::Rgb(0x3D, 0xE8, 0x6A);
/// Dim green: labels, rules, secondary text.
pub const DIM: Color = Color::Rgb(0x00, 0x8F, 0x11);
/// Deep green: inactive borders, tracks.
pub const DEEP: Color = Color::Rgb(0x00, 0x3B, 0x00);
/// Darkest rain trail color (just above black).
pub const DEEP_RAIN: Color = Color::Rgb(0x00, 0x1E, 0x06);
/// Near-black green: bars and panels.
pub const ABYSS: Color = Color::Rgb(0x00, 0x16, 0x05);
/// Background of the cursor line.
pub const CURSOR_BG: Color = Color::Rgb(0x00, 0x2E, 0x0B);
/// White-green highlight: titles, active elements.
pub const GLOW: Color = Color::Rgb(0xC8, 0xFF, 0xC8);
/// LOW severity / info style.
pub const CYAN: Color = Color::Rgb(0x00, 0xD7, 0xFF);
/// MEDIUM severity / warnings.
pub const AMBER: Color = Color::Rgb(0xFF, 0xB0, 0x00);
/// HIGH severity / danger.
pub const RED: Color = Color::Rgb(0xFF, 0x3B, 0x3B);
/// CRITICAL severity.
pub const MAGENTA: Color = Color::Rgb(0xFF, 0x2D, 0x78);

pub fn base() -> Style {
    Style::new().fg(GREEN).bg(BLACK)
}
pub fn text() -> Style {
    Style::new().fg(GREEN)
}
pub fn body() -> Style {
    Style::new().fg(SOFT)
}
pub fn dim() -> Style {
    Style::new().fg(DIM)
}
pub fn deep() -> Style {
    Style::new().fg(DEEP)
}
pub fn glow() -> Style {
    Style::new().fg(GLOW).add_modifier(Modifier::BOLD)
}
pub fn bold() -> Style {
    Style::new().fg(GREEN).add_modifier(Modifier::BOLD)
}
/// Screen title.
pub fn title() -> Style {
    glow()
}
/// The heavy rule under a screen title.
pub fn title_rule() -> Style {
    Style::new().fg(GREEN)
}
/// Section heading.
pub fn section() -> Style {
    Style::new().fg(GREEN).add_modifier(Modifier::BOLD)
}
/// Thin rules under sections and table headers.
pub fn rule() -> Style {
    Style::new().fg(DIM)
}
/// Key/value labels.
pub fn label() -> Style {
    Style::new().fg(DIM)
}
/// Inline references (e.g. `[host:dev-01]` in Oracle answers).
pub fn citation() -> Style {
    Style::new().fg(CYAN)
}

/// Style for a named block style.
pub fn named(name: StyleName) -> Style {
    match name {
        StyleName::Normal => body(),
        StyleName::Dim => dim(),
        StyleName::Accent => glow(),
        StyleName::Ok => bold(),
        StyleName::Info => Style::new().fg(CYAN),
        StyleName::Warn => Style::new().fg(AMBER),
        StyleName::Danger => Style::new().fg(RED),
        StyleName::Note => Style::new().fg(DIM).add_modifier(Modifier::ITALIC),
    }
}

/// Like [`named`], but `Normal` maps to the primary green (for short values).
pub fn value(name: StyleName) -> Style {
    match name {
        StyleName::Normal => text(),
        other => named(other),
    }
}

/// Color of a severity level.
pub fn severity_color(sev: Severity) -> Color {
    match sev {
        Severity::Info => DIM,
        Severity::Low => CYAN,
        Severity::Medium => AMBER,
        Severity::High => RED,
        Severity::Critical => MAGENTA,
    }
}

/// Style of a severity word (always bold).
pub fn severity(sev: Severity) -> Style {
    Style::new()
        .fg(severity_color(sev))
        .add_modifier(Modifier::BOLD)
}

/// Marker and style for a node criticality (`critical`, `high`, `medium`).
pub fn criticality(c: &str) -> Option<(&'static str, Style)> {
    match c.trim().to_ascii_lowercase().as_str() {
        "critical" => Some(("◆", severity(Severity::Critical))),
        "high" => Some(("▲", severity(Severity::High))),
        "medium" => Some(("■", severity(Severity::Medium))),
        _ => None,
    }
}

/// Mixes two RGB colors (`t` = 0 gives `a`, 1 gives `b`).
pub fn mix(a: Color, b: Color, t: f32) -> Color {
    match (a, b) {
        (Color::Rgb(r1, g1, b1), Color::Rgb(r2, g2, b2)) => {
            let t = t.clamp(0.0, 1.0);
            let f = |x: u8, y: u8| (f32::from(x) + (f32::from(y) - f32::from(x)) * t).round() as u8;
            Color::Rgb(f(r1, r2), f(g1, g2), f(b1, b2))
        }
        _ => {
            if t < 0.5 {
                a
            } else {
                b
            }
        }
    }
}

/// True when the terminal advertises 24-bit color.
pub fn truecolor_supported() -> bool {
    if let Ok(v) = std::env::var("RAF_OS_COLOR") {
        return !matches!(v.as_str(), "256" | "ansi256");
    }
    matches!(
        std::env::var("COLORTERM").as_deref(),
        Ok("truecolor") | Ok("24bit")
    )
}

/// Nearest xterm 256-color index for an RGB color.
pub fn ansi256(r: u8, g: u8, b: u8) -> u8 {
    fn q(x: u8) -> u8 {
        match x {
            0..=47 => 0,
            48..=114 => 1,
            _ => (x - 35) / 40,
        }
    }
    const LEVELS: [u8; 6] = [0, 95, 135, 175, 215, 255];
    let (qr, qg, qb) = (q(r), q(g), q(b));
    let cube = 16 + 36 * qr + 6 * qg + qb;
    let cube_rgb = (
        LEVELS[qr as usize],
        LEVELS[qg as usize],
        LEVELS[qb as usize],
    );
    let avg = (u16::from(r) + u16::from(g) + u16::from(b)) / 3;
    let gray_idx = if avg < 8 {
        0
    } else {
        ((avg - 8) / 10).min(23) as u8
    };
    let gray_level = 8 + 10 * gray_idx;
    let dist = |(a, b2, c): (u8, u8, u8)| {
        let d = |x: u8, y: u8| (i32::from(x) - i32::from(y)).pow(2);
        d(a, r) + d(b2, g) + d(c, b)
    };
    if dist((gray_level, gray_level, gray_level)) < dist(cube_rgb) {
        232 + gray_idx
    } else {
        cube
    }
}

fn to_indexed(c: Color) -> Color {
    match c {
        Color::Rgb(r, g, b) => Color::Indexed(ansi256(r, g, b)),
        other => other,
    }
}

/// Maps every 24-bit color in the buffer to the 256-color palette.
pub fn downsample(buf: &mut Buffer) {
    for cell in &mut buf.content {
        cell.fg = to_indexed(cell.fg);
        cell.bg = to_indexed(cell.bg);
    }
}

fn darken(c: Color, f: f32) -> Color {
    match c {
        Color::Rgb(r, g, b) => {
            let s = |x: u8| (f32::from(x) * f).round() as u8;
            Color::Rgb(s(r), s(g), s(b))
        }
        Color::Reset => Color::Reset,
        _ => DEEP,
    }
}

/// Dims an area (used behind modal popups).
pub fn dim_area(buf: &mut Buffer, area: Rect) {
    let area = area.intersection(buf.area);
    for y in area.top()..area.bottom() {
        for x in area.left()..area.right() {
            if let Some(cell) = buf.cell_mut((x, y)) {
                cell.fg = darken(cell.fg, 0.32);
                cell.bg = darken(cell.bg, 0.5);
                cell.modifier.remove(Modifier::BOLD);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ansi256_maps_palette() {
        assert_eq!(ansi256(0, 0, 0), 16);
        assert_eq!(ansi256(255, 255, 255), 231);
        // Phosphor green lands in the green column of the cube.
        let g = ansi256(0x00, 0xFF, 0x41);
        assert!((16..232).contains(&g));
        assert_eq!(ansi256(0x80, 0x80, 0x80), 244);
    }

    #[test]
    fn mix_interpolates() {
        assert_eq!(
            mix(BLACK, Color::Rgb(200, 100, 0), 0.5),
            Color::Rgb(100, 50, 0)
        );
        assert_eq!(mix(BLACK, GREEN, 0.0), BLACK);
        assert_eq!(mix(BLACK, GREEN, 1.0), GREEN);
    }

    #[test]
    fn criticality_markers() {
        assert_eq!(criticality("critical").map(|c| c.0), Some("◆"));
        assert_eq!(criticality("HIGH").map(|c| c.0), Some("▲"));
        assert_eq!(criticality("medium").map(|c| c.0), Some("■"));
        assert_eq!(criticality("low"), None);
    }
}
