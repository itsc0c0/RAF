//! Text helpers: sanitizing untrusted strings, display widths, truncation, padding, word
//! wrapping and column slicing of styled spans.
//!
//! Widths follow ratatui's own rules (`unicode-width` per grapheme cluster, halfwidth katakana
//! sound marks counted as one cell) so that what we measure is what the buffer draws.

use std::borrow::Cow;

use ratatui::style::Style;
use ratatui::text::{Line, Span};
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

/// Replacement for characters that must never reach the terminal.
pub const REPLACEMENT: char = '\u{FFFD}';
/// Marker appended to truncated text.
pub const ELLIPSIS: &str = "…";

/// True for characters that are never written to the terminal verbatim: C0 and C1 control
/// characters (including ESC, TAB and newlines), DEL, bidirectional embeddings, overrides and
/// isolates, and invisible zero-width or format characters that could disguise text.
pub fn is_forbidden(c: char) -> bool {
    matches!(
        c,
        '\u{0000}'..='\u{001F}'          // C0 controls (ESC, TAB, CR, LF, ...)
            | '\u{007F}'..='\u{009F}'    // DEL and C1 controls (CSI, OSC, ...)
            | '\u{00AD}'                 // soft hyphen
            | '\u{034F}'                 // combining grapheme joiner
            | '\u{061C}'                 // Arabic letter mark
            | '\u{115F}' | '\u{1160}'    // Hangul fillers
            | '\u{17B4}' | '\u{17B5}'    // Khmer inherent vowels
            | '\u{180B}'..='\u{180F}'    // Mongolian variation selectors and vowel separator
            | '\u{200B}'..='\u{200F}'    // zero-width space/non-joiner/joiner, LRM, RLM
            | '\u{2028}' | '\u{2029}'    // line and paragraph separators
            | '\u{202A}'..='\u{202E}'    // bidi embeddings and overrides
            | '\u{2060}'..='\u{2064}'    // word joiner, invisible operators
            | '\u{2066}'..='\u{2069}'    // bidi isolates
            | '\u{206A}'..='\u{206F}'    // deprecated format characters
            | '\u{3164}'                 // Hangul filler
            | '\u{FEFF}'                 // zero-width no-break space (BOM)
            | '\u{FFA0}'                 // halfwidth Hangul filler
            | '\u{FFF9}'..='\u{FFFB}'    // interlinear annotation controls
            | '\u{1D173}'..='\u{1D17A}'  // musical formatting controls
            | '\u{E0000}'..='\u{E007F}' // tag characters
    )
}

/// Replaces every forbidden character (see [`is_forbidden`]) with U+FFFD. Borrows when the
/// input is already clean.
pub fn sanitize(s: &str) -> Cow<'_, str> {
    if !s.chars().any(is_forbidden) {
        return Cow::Borrowed(s);
    }
    Cow::Owned(
        s.chars()
            .map(|c| if is_forbidden(c) { REPLACEMENT } else { c })
            .collect(),
    )
}

/// Owned, sanitized copy of `s`.
pub fn clean(s: &str) -> String {
    sanitize(s).into_owned()
}

/// Display width of one grapheme cluster, exactly as ratatui's buffer measures it.
pub fn grapheme_width(g: &str) -> usize {
    if g.len() == 1 {
        return usize::from(!g.as_bytes()[0].is_ascii_control());
    }
    let marks = g
        .chars()
        .filter(|c| matches!(c, '\u{FF9E}' | '\u{FF9F}'))
        .count();
    g.width() + marks
}

/// Display width of a string in terminal cells.
pub fn width(s: &str) -> usize {
    if s.is_ascii() {
        return s.bytes().filter(|b| !b.is_ascii_control()).count();
    }
    s.graphemes(true).map(grapheme_width).sum()
}

/// Display width of a sequence of spans.
pub fn spans_width(spans: &[Span<'_>]) -> usize {
    spans.iter().map(|s| width(&s.content)).sum()
}

/// Display width of a line.
pub fn line_width(line: &Line<'_>) -> usize {
    spans_width(&line.spans)
}

/// Shortens `s` to at most `max` cells, ending with `…` when something was cut.
pub fn truncate(s: &str, max: usize) -> String {
    if width(s) <= max {
        return s.to_string();
    }
    if max == 0 {
        return String::new();
    }
    let mut out = String::new();
    let mut used = 0;
    for g in s.graphemes(true) {
        let w = grapheme_width(g);
        if used + w > max - 1 {
            break;
        }
        out.push_str(g);
        used += w;
    }
    let kept = out.trim_end().len();
    out.truncate(kept);
    out.push_str(ELLIPSIS);
    out
}

/// Shortens `s` to at most `max` cells without an ellipsis (hard clip).
pub fn clip(s: &str, max: usize) -> String {
    let mut out = String::new();
    let mut used = 0;
    for g in s.graphemes(true) {
        let w = grapheme_width(g);
        if used + w > max {
            break;
        }
        out.push_str(g);
        used += w;
    }
    out
}

/// Pads `s` with spaces on the right to `w` cells (never truncates).
pub fn pad(s: &str, w: usize) -> String {
    let sw = width(s);
    if sw >= w {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + w - sw);
    out.push_str(s);
    out.extend(std::iter::repeat_n(' ', w - sw));
    out
}

/// Pads `s` with spaces on the left to `w` cells (never truncates).
pub fn pad_left(s: &str, w: usize) -> String {
    let sw = width(s);
    if sw >= w {
        return s.to_string();
    }
    let mut out = " ".repeat(w - sw);
    out.push_str(s);
    out
}

/// Centers `s` in `w` cells (extra space goes to the right).
pub fn center(s: &str, w: usize) -> String {
    let sw = width(s);
    if sw >= w {
        return s.to_string();
    }
    let left = (w - sw) / 2;
    let mut out = " ".repeat(left);
    out.push_str(s);
    out.extend(std::iter::repeat_n(' ', w - sw - left));
    out
}

/// Truncates to `w` cells (with `…`) and pads to exactly `w` cells.
pub fn fit(s: &str, w: usize) -> String {
    pad(&truncate(s, w), w)
}

/// `n` spaces.
pub fn spaces(n: usize) -> String {
    " ".repeat(n)
}

struct Piece<'a> {
    g: &'a str,
    style: Style,
    w: usize,
}

fn pieces<'a>(spans: &'a [Span<'_>]) -> Vec<Piece<'a>> {
    spans
        .iter()
        .flat_map(|s| {
            let style = s.style;
            s.content.graphemes(true).map(move |g| Piece {
                g,
                style,
                w: grapheme_width(g),
            })
        })
        .collect()
}

fn collect_spans(pieces: &[Piece<'_>]) -> Vec<Span<'static>> {
    let mut out: Vec<Span<'static>> = Vec::new();
    let mut cur = String::new();
    let mut cur_style: Option<Style> = None;
    for p in pieces {
        if cur_style != Some(p.style) {
            if let Some(style) = cur_style
                && !cur.is_empty()
            {
                out.push(Span::styled(std::mem::take(&mut cur), style));
            }
            cur_style = Some(p.style);
        }
        cur.push_str(p.g);
    }
    if let Some(style) = cur_style
        && !cur.is_empty()
    {
        out.push(Span::styled(cur, style));
    }
    out
}

/// Word-wraps styled spans. The first output line may hold `first_width` cells, the following
/// lines `rest_width` cells. Runs of spaces inside a line are preserved (alignment survives),
/// spaces at a break are dropped, and words longer than a line are broken between graphemes.
/// Always returns at least one (possibly empty) line.
pub fn wrap_spans(
    spans: &[Span<'_>],
    first_width: usize,
    rest_width: usize,
) -> Vec<Vec<Span<'static>>> {
    let first_width = first_width.max(1);
    let rest_width = rest_width.max(1);
    let ps = pieces(spans);
    // Tokens: maximal runs of spaces or of non-spaces, as (start, end, is_space, width).
    let mut tokens: Vec<(usize, usize, bool, usize)> = Vec::new();
    let mut i = 0;
    while i < ps.len() {
        let space = ps[i].g == " ";
        let start = i;
        let mut w = 0;
        while i < ps.len() && (ps[i].g == " ") == space {
            w += ps[i].w;
            i += 1;
        }
        tokens.push((start, i, space, w));
    }

    let limit = |line: usize| if line == 0 { first_width } else { rest_width };
    let mut lines: Vec<Vec<(usize, usize)>> = vec![Vec::new()];
    let mut used = 0usize;

    fn trim_trailing_spaces(line: &mut Vec<(usize, usize)>, ps: &[Piece<'_>]) {
        while let Some(&(s, e)) = line.last() {
            let mut e2 = e;
            while e2 > s && ps[e2 - 1].g == " " {
                e2 -= 1;
            }
            if e2 == e {
                break;
            }
            line.pop();
            if e2 > s {
                line.push((s, e2));
                break;
            }
        }
    }

    for (start, end, space, w) in tokens {
        let lim = limit(lines.len() - 1);
        if space {
            if used == 0 && lines.len() > 1 {
                continue; // no leading spaces on continuation lines
            }
            if used + w <= lim {
                lines.last_mut().expect("line").push((start, end));
                used += w;
            } else {
                lines.push(Vec::new());
                used = 0;
            }
            continue;
        }
        if used + w <= lim {
            lines.last_mut().expect("line").push((start, end));
            used += w;
            continue;
        }
        if used > 0 {
            trim_trailing_spaces(lines.last_mut().expect("line"), &ps);
            lines.push(Vec::new());
            used = 0;
        }
        let lim = limit(lines.len() - 1);
        if w <= lim {
            lines.last_mut().expect("line").push((start, end));
            used = w;
            continue;
        }
        // Hard-break a word that is wider than a whole line.
        let mut s = start;
        while s < end {
            let lim = limit(lines.len() - 1);
            let mut e = s;
            let mut ww = 0;
            while e < end && (used + ww + ps[e].w <= lim || (used == 0 && ww == 0)) {
                ww += ps[e].w;
                e += 1;
            }
            lines.last_mut().expect("line").push((s, e));
            used += ww;
            s = e;
            if s < end {
                lines.push(Vec::new());
                used = 0;
            }
        }
    }
    if let Some(last) = lines.last_mut() {
        trim_trailing_spaces(last, &ps);
    }

    lines
        .into_iter()
        .map(|ranges| {
            let mut sel: Vec<&Piece<'_>> = Vec::new();
            for (s, e) in ranges {
                sel.extend(ps[s..e].iter());
            }
            let owned: Vec<Piece<'_>> = sel
                .into_iter()
                .map(|p| Piece {
                    g: p.g,
                    style: p.style,
                    w: p.w,
                })
                .collect();
            collect_spans(&owned)
        })
        .collect()
}

/// Word-wraps plain text to `width` cells.
pub fn wrap(s: &str, width: usize) -> Vec<String> {
    wrap_spans(&[Span::raw(s)], width, width)
        .into_iter()
        .map(|spans| spans.iter().map(|s| s.content.as_ref()).collect())
        .collect()
}

/// Returns the cells `[skip, skip + take)` of a styled line. A wide grapheme cut by either
/// edge is replaced by spaces so columns stay aligned.
pub fn slice_spans(spans: &[Span<'_>], skip: usize, take: usize) -> Vec<Span<'static>> {
    let mut out: Vec<Piece<'_>> = Vec::new();
    let end = skip + take;
    let mut col = 0usize;
    for p in pieces(spans) {
        let (a, b) = (col, col + p.w);
        col = b;
        if b <= skip || p.w == 0 {
            continue;
        }
        if a >= end {
            break;
        }
        if a >= skip && b <= end {
            out.push(p);
        } else {
            let visible = b.min(end) - a.max(skip);
            for _ in 0..visible {
                out.push(Piece {
                    g: " ",
                    style: p.style,
                    w: 1,
                });
            }
        }
    }
    collect_spans(&out)
}

/// Shortens styled spans to `max` cells, ending with `…` (in the style of the last kept cell).
pub fn truncate_spans(spans: &[Span<'_>], max: usize) -> Vec<Span<'static>> {
    if spans_width(spans) <= max {
        return spans
            .iter()
            .map(|s| Span::styled(s.content.to_string(), s.style))
            .collect();
    }
    if max == 0 {
        return Vec::new();
    }
    let mut kept: Vec<Piece<'_>> = Vec::new();
    let mut used = 0;
    let mut last_style = Style::default();
    for p in pieces(spans) {
        if used + p.w > max - 1 {
            break;
        }
        used += p.w;
        last_style = p.style;
        kept.push(p);
    }
    let mut out = collect_spans(&kept);
    out.push(Span::styled(ELLIPSIS, last_style));
    out
}

/// Concatenated text of a line (no styles).
pub fn plain(line: &Line<'_>) -> String {
    line.spans.iter().map(|s| s.content.as_ref()).collect()
}

/// Re-styles the cells `[from, to)` of a line with `patch` (merged over the existing style).
pub fn restyle_range(
    spans: &[Span<'_>],
    from: usize,
    to: usize,
    patch: Style,
) -> Vec<Span<'static>> {
    let mut col = 0;
    let out: Vec<Piece<'_>> = pieces(spans)
        .into_iter()
        .map(|mut p| {
            if col >= from && col < to {
                p.style = p.style.patch(patch);
            }
            col += p.w;
            p
        })
        .collect();
    collect_spans(&out)
}

/// Formats a UTC timestamp (seconds since the Unix epoch) as `YYYY-MM-DD HH:MM:SS`.
pub fn utc_timestamp(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Civil-from-days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(mo <= 2);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02}:{s:02}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::style::{Color, Style};

    fn texts(lines: &[Vec<Span<'static>>]) -> Vec<String> {
        lines
            .iter()
            .map(|l| l.iter().map(|s| s.content.as_ref()).collect())
            .collect()
    }

    #[test]
    fn sanitize_replaces_escape_sequences() {
        let hostile = "ok\u{1b}[31mRED\u{1b}]0;title\u{7}\u{1b}[2J";
        let clean = sanitize(hostile);
        assert!(!clean.contains('\u{1b}'));
        assert!(!clean.contains('\u{7}'));
        assert_eq!(
            clean,
            "ok\u{FFFD}[31mRED\u{FFFD}]0;title\u{FFFD}\u{FFFD}[2J"
        );
    }

    #[test]
    fn sanitize_replaces_c1_bidi_and_zero_width() {
        // C1 CSI (U+009B), RLO (U+202E), LRI (U+2066), ZWSP, ZWJ, BOM, DEL, TAB, newline.
        let s = "a\u{9b}31m b\u{202e}gnp.exe c\u{2066}d\u{200b}e\u{200d}f\u{feff}g\u{7f}h\ti\nj";
        let out = sanitize(s);
        for c in out.chars() {
            assert!(!is_forbidden(c), "forbidden char {c:?} survived");
        }
        assert_eq!(out.matches(REPLACEMENT).count(), 9);
        assert!(out.starts_with("a\u{FFFD}31m b\u{FFFD}gnp.exe"));
    }

    #[test]
    fn sanitize_borrows_clean_text() {
        assert!(matches!(sanitize("R$F → DEV-01 ✔"), Cow::Borrowed(_)));
        assert!(matches!(sanitize("ｶﾀｶﾅ 漢字 émoji"), Cow::Borrowed(_)));
    }

    #[test]
    fn widths_follow_terminal_cells() {
        assert_eq!(width("DEV-01"), 6);
        assert_eq!(width("漢字"), 4);
        assert_eq!(width("ｱｲｳ"), 3);
        assert_eq!(width("─━│●◌◐▼▲"), 8);
        assert_eq!(width("e\u{301}"), 1); // combining accent
    }

    #[test]
    fn truncate_and_fit() {
        assert_eq!(truncate("production", 20), "production");
        assert_eq!(truncate("production", 6), "produ…");
        assert_eq!(truncate("漢字漢字", 5), "漢字…");
        assert_eq!(fit("bob", 6), "bob   ");
        assert_eq!(fit("svc-deploy", 6), "svc-d…");
        assert_eq!(pad_left("97", 5), "   97");
        assert_eq!(center("ab", 6), "  ab  ");
        assert_eq!(clip("abcdef", 3), "abc");
    }

    #[test]
    fn wrap_breaks_at_spaces_and_keeps_alignment() {
        // Fits: the run of spaces used for alignment is preserved.
        assert_eq!(
            wrap("source      network:dev", 30),
            vec!["source      network:dev"]
        );
        // Does not fit: the break consumes the spaces.
        let lines = wrap("source      network:dev and a few more words here", 20);
        assert_eq!(
            lines,
            vec!["source", "network:dev and a", "few more words here"]
        );
        assert!(lines.iter().all(|l| width(l) <= 20));
    }

    #[test]
    fn wrap_simple_words() {
        assert_eq!(
            wrap("the quick brown fox jumps", 10),
            vec!["the quick", "brown fox", "jumps"]
        );
        assert_eq!(wrap("", 10), vec![String::new()]);
        assert_eq!(wrap("   indented", 20), vec!["   indented"]);
        assert_eq!(wrap("abcdefghijkl", 5), vec!["abcde", "fghij", "kl"]);
    }

    #[test]
    fn wrap_respects_first_and_rest_widths() {
        let spans = [Span::raw("aaa bbb ccc ddd eee")];
        let out = texts(&wrap_spans(&spans, 7, 11));
        assert_eq!(out, vec!["aaa bbb", "ccc ddd eee"]);
    }

    #[test]
    fn wrap_preserves_styles() {
        let red = Style::new().fg(Color::Red);
        let spans = [Span::raw("plain "), Span::styled("red words here", red)];
        let out = wrap_spans(&spans, 12, 12);
        assert_eq!(texts(&out), vec!["plain red", "words here"]);
        assert_eq!(out[0][1].style, red);
        assert_eq!(out[1][0].style, red);
    }

    #[test]
    fn wrap_wide_characters() {
        let out = wrap("漢字漢字漢字", 5);
        assert_eq!(out, vec!["漢字", "漢字", "漢字"]);
    }

    #[test]
    fn slice_spans_by_columns() {
        let spans = [Span::raw("abc"), Span::raw("def")];
        let s = slice_spans(&spans, 2, 3);
        assert_eq!(
            s.iter().map(|s| s.content.as_ref()).collect::<String>(),
            "cde"
        );
        let wide = [Span::raw("a漢b")];
        // Column 1 is the left half of 漢: replaced by a space.
        let s = slice_spans(&wide, 2, 2);
        assert_eq!(
            s.iter().map(|s| s.content.as_ref()).collect::<String>(),
            " b"
        );
    }

    #[test]
    fn truncate_spans_adds_ellipsis() {
        let spans = [Span::raw("hello "), Span::raw("world")];
        let s = truncate_spans(&spans, 8);
        assert_eq!(
            s.iter().map(|s| s.content.as_ref()).collect::<String>(),
            "hello w…"
        );
    }

    #[test]
    fn utc_timestamp_formats_dates() {
        assert_eq!(utc_timestamp(0), "1970-01-01 00:00:00");
        assert_eq!(utc_timestamp(1_791_376_331), "2026-10-07 12:32:11");
        assert_eq!(utc_timestamp(951_782_400), "2000-02-29 00:00:00");
    }
}
