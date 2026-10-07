/**
 * Small fuzzy matcher for the command palette: every query character must appear in order
 * (subsequence). Contiguous runs, word starts and prefix/substring matches score higher.
 */

export interface FuzzyMatch {
  score: number;
  /** Matched character positions in the (lower-cased) text. */
  indices: number[];
}

const WORD_BOUNDARY = /[\s\-_:./|@]/;

export function fuzzyMatch(query: string, text: string): FuzzyMatch | null {
  const q = query.trim().toLowerCase();
  if (!q) return { score: 0, indices: [] };
  const t = text.toLowerCase();
  const indices: number[] = [];
  let cursor = 0;
  let previous = -2;
  let score = 0;
  for (const char of q) {
    if (char === ' ') continue;
    const found = t.indexOf(char, cursor);
    if (found === -1) return null;
    let points = 1;
    if (found === previous + 1) points += 5;
    if (found === 0 || WORD_BOUNDARY.test(t[found - 1] ?? '')) points += 4;
    points -= Math.min(3, (found - cursor) * 0.1);
    score += points;
    indices.push(found);
    previous = found;
    cursor = found + 1;
  }
  if (t.startsWith(q)) score += 12;
  else if (t.includes(q)) score += 8;
  // Prefer shorter texts when everything else is equal (exact-ish matches first).
  score -= Math.min(4, t.length / 40);
  return { score, indices };
}

/** Filters and ranks `items` (stable for equal scores). An empty query keeps the original order. */
export function fuzzyFilter<T>(items: readonly T[], query: string, text: (item: T) => string): T[] {
  if (!query.trim()) return [...items];
  return items
    .map((item, index) => ({ item, index, match: fuzzyMatch(query, text(item)) }))
    .filter((entry): entry is { item: T; index: number; match: FuzzyMatch } => entry.match !== null)
    .sort((a, b) => b.match.score - a.match.score || a.index - b.index)
    .map((entry) => entry.item);
}
