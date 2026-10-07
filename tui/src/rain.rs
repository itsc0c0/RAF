//! Digital rain: falling half-width katakana, digits and `R$F` glyphs with bright heads and
//! fading phosphor trails. Deterministic (seeded xorshift), cheap (one cell array per area),
//! drawn straight into the frame buffer.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Modifier;

use crate::theme;

/// Small, fast, deterministic PRNG (xorshift64*).
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng((seed ^ 0x9E37_79B9_7F4A_7C15) | 1)
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Uniform in `0..n` (`n` > 0).
    pub fn below(&mut self, n: u32) -> u32 {
        (((self.next_u64() >> 32) * u64::from(n.max(1))) >> 32) as u32
    }

    /// Uniform in `[0, 1)`.
    pub fn unit(&mut self) -> f32 {
        (self.next_u64() >> 40) as f32 / (1u64 << 24) as f32
    }

    pub fn range(&mut self, lo: f32, hi: f32) -> f32 {
        lo + (hi - lo) * self.unit()
    }
}

/// Glyph pool: half-width katakana (U+FF66–U+FF9D), digits and a few symbols, with `R`, `$`
/// and `F` sprinkled in.
pub fn glyph(rng: &mut Rng) -> char {
    match rng.below(100) {
        0..=61 => char::from_u32(0xFF66 + rng.below(0xFF9D - 0xFF66 + 1)).unwrap_or('ｱ'),
        62..=81 => char::from(b'0' + rng.below(10) as u8),
        82..=89 => ['R', '$', 'F'][rng.below(3) as usize],
        _ => [':', '.', '=', '*', '+', '<', '>', '¦', '|', '"'][rng.below(10) as usize],
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct Drop {
    y: f32,
    speed: f32,
    len: f32,
    wait: u32,
}

#[derive(Debug, Clone, Copy)]
struct Cell {
    ch: char,
    life: f32,
}

impl Default for Cell {
    fn default() -> Cell {
        Cell { ch: ' ', life: 0.0 }
    }
}

/// Rain state for one rectangular area.
#[derive(Debug, Clone)]
pub struct Rain {
    w: usize,
    h: usize,
    drops: Vec<Drop>,
    cells: Vec<Cell>,
    rng: Rng,
    /// Probability that an idle column starts a new drop on a given step (density).
    pub density: f32,
}

impl Rain {
    pub fn new(seed: u64) -> Rain {
        Rain {
            w: 0,
            h: 0,
            drops: Vec::new(),
            cells: Vec::new(),
            rng: Rng::new(seed),
            density: 1.0,
        }
    }

    pub fn size(&self) -> (usize, usize) {
        (self.w, self.h)
    }

    /// Resizes the area (keeps the state when the size is unchanged). New columns start at
    /// random heights so the rain looks established immediately.
    pub fn resize(&mut self, w: usize, h: usize) {
        if (w, h) == (self.w, self.h) {
            return;
        }
        self.w = w;
        self.h = h;
        self.cells = vec![Cell::default(); w * h];
        self.drops = (0..w)
            .map(|_| {
                let mut d = Drop::default();
                Self::respawn(&mut self.rng, &mut d, h, true);
                d
            })
            .collect();
    }

    fn respawn(rng: &mut Rng, d: &mut Drop, h: usize, initial: bool) {
        let h = h.max(1) as f32;
        d.speed = rng.range(0.25, 1.1);
        d.len = rng.range(4.0, (h * 0.9).max(6.0));
        if initial {
            d.y = rng.range(-h, h);
            d.wait = 0;
        } else {
            d.y = -rng.range(0.0, h * 0.3);
            d.wait = rng.below(50);
        }
    }

    /// Advances the animation by one frame.
    pub fn step(&mut self) {
        let (w, h) = (self.w, self.h);
        if w == 0 || h == 0 {
            return;
        }
        for x in 0..w {
            let d = &mut self.drops[x];
            let decay = (d.speed / d.len.max(1.0)).max(0.02);
            for y in 0..h {
                let c = &mut self.cells[y * w + x];
                c.life = (c.life - decay).max(0.0);
            }
            if d.wait > 0 {
                d.wait -= 1;
                continue;
            }
            let before = d.y.floor() as i64;
            d.y += d.speed;
            let after = d.y.floor() as i64;
            for row in (before + 1)..=after {
                if row >= 0 && (row as usize) < h {
                    let ch = glyph(&mut self.rng);
                    self.cells[row as usize * w + x] = Cell { ch, life: 1.0 };
                }
            }
            if d.y - d.len > h as f32 {
                Self::respawn(&mut self.rng, d, h, false);
                if self.rng.unit() > self.density {
                    d.wait += 40;
                }
            }
        }
        // Flicker: a few glyphs inside trails mutate.
        let flips = (w * h / 90).max(1);
        for _ in 0..flips {
            let i = self.rng.below((w * h) as u32) as usize;
            if self.cells[i].life > 0.15 {
                self.cells[i].ch = glyph(&mut self.rng);
            }
        }
    }

    /// True when column `x` has its drop head on row `y`.
    fn is_head(&self, x: usize, y: usize) -> bool {
        let d = &self.drops[x];
        d.wait == 0 && d.y >= 0.0 && d.y.floor() as usize == y
    }

    /// Draws the rain into `area` (which should match the size given to [`Rain::resize`]).
    /// `intensity` scales the brightness (1 = full).
    pub fn render(&self, area: Rect, buf: &mut Buffer, intensity: f32) {
        let w = self.w.min(area.width as usize);
        let h = self.h.min(area.height as usize);
        for y in 0..h {
            for x in 0..w {
                let c = self.cells[y * self.w + x];
                if c.life <= 0.02 {
                    continue;
                }
                let pos = (area.x + x as u16, area.y + y as u16);
                let Some(cell) = buf.cell_mut(pos) else {
                    continue;
                };
                let (color, bold) = if self.is_head(x, y) {
                    (theme::mix(theme::BLACK, theme::GLOW, intensity), true)
                } else {
                    let t = (c.life * c.life * intensity).clamp(0.0, 1.0);
                    let base = if c.life > 0.85 {
                        theme::mix(theme::GREEN, theme::GLOW, (c.life - 0.85) * 3.0)
                    } else {
                        theme::GREEN
                    };
                    (theme::mix(theme::DEEP_RAIN, base, t), false)
                };
                cell.set_char(c.ch);
                cell.fg = color;
                if bold {
                    cell.modifier.insert(Modifier::BOLD);
                } else {
                    cell.modifier.remove(Modifier::BOLD);
                }
            }
        }
    }

    /// Number of lit cells (used by tests).
    pub fn lit(&self) -> usize {
        self.cells.iter().filter(|c| c.life > 0.02).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rng_is_deterministic_and_bounded() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        for _ in 0..1000 {
            let x = a.below(7);
            assert_eq!(x, b.below(7));
            assert!(x < 7);
            let u = a.unit();
            assert_eq!(u, b.unit());
            assert!((0.0..1.0).contains(&u));
        }
    }

    #[test]
    fn glyphs_are_single_cell() {
        let mut rng = Rng::new(7);
        for _ in 0..2000 {
            let g = glyph(&mut rng);
            let s = g.to_string();
            assert_eq!(crate::text::width(&s), 1, "{g:?}");
            assert!(!crate::text::is_forbidden(g));
        }
    }

    #[test]
    fn rain_falls_and_renders_inside_its_area() {
        let mut rain = Rain::new(1);
        rain.resize(20, 10);
        for _ in 0..30 {
            rain.step();
        }
        assert!(rain.lit() > 0);
        let area = Rect::new(5, 2, 20, 10);
        let mut buf = Buffer::empty(Rect::new(0, 0, 40, 20));
        rain.render(area, &mut buf, 1.0);
        for y in 0..20u16 {
            for x in 0..40u16 {
                let inside = area.contains((x, y).into());
                if !inside {
                    assert_eq!(buf[(x, y)].symbol(), " ");
                }
            }
        }
        // Same seed, same frames.
        let mut again = Rain::new(1);
        again.resize(20, 10);
        for _ in 0..30 {
            again.step();
        }
        let mut buf2 = Buffer::empty(Rect::new(0, 0, 40, 20));
        again.render(area, &mut buf2, 1.0);
        assert_eq!(buf, buf2);
    }

    #[test]
    fn resize_to_zero_is_safe() {
        let mut rain = Rain::new(3);
        rain.resize(0, 0);
        rain.step();
        rain.resize(3, 0);
        rain.step();
        assert_eq!(rain.lit(), 0);
    }
}
