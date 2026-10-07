/** Pure geometry for the time histogram and its brush. All times are epoch milliseconds. */

export interface Bucket {
  start: number;
  end: number;
  count: number;
}

export interface TimeRange {
  start: number;
  end: number;
}

const ONE_MINUTE = 60_000;

/**
 * Converts API buckets (`{start, count}`, uniform width) into intervals [start, end). The width is the
 * smallest positive gap between consecutive starts; a lone bucket spans one minute.
 */
export function toBuckets(raw: ReadonlyArray<{ start: string; count: number }>): Bucket[] {
  const starts = raw.map((bucket) => Date.parse(bucket.start));
  if (starts.some((value) => Number.isNaN(value))) return [];
  const gaps: number[] = [];
  for (let i = 1; i < starts.length; i += 1) {
    const gap = starts[i]! - starts[i - 1]!;
    if (gap > 0) gaps.push(gap);
  }
  const width = gaps.length > 0 ? Math.min(...gaps) : ONE_MINUTE;
  return raw.map((bucket, index) => {
    const start = starts[index]!;
    const next = starts[index + 1];
    return { start, end: next !== undefined && next > start ? next : start + width, count: bucket.count };
  });
}

export function domainOf(buckets: readonly Bucket[]): TimeRange | null {
  if (buckets.length === 0) return null;
  return { start: buckets[0]!.start, end: buckets[buckets.length - 1]!.end };
}

/** Pixel position (0..width) -> time within the domain (clamped). */
export function timeAtPixel(x: number, width: number, domain: TimeRange): number {
  if (width <= 0) return domain.start;
  const ratio = Math.max(0, Math.min(1, x / width));
  return domain.start + ratio * (domain.end - domain.start);
}

export function pixelAtTime(t: number, width: number, domain: TimeRange): number {
  const span = domain.end - domain.start;
  if (span <= 0) return 0;
  return Math.max(0, Math.min(width, ((t - domain.start) / span) * width));
}

/** Expands a raw time range to whole buckets (a brush always selects complete bars). */
export function snapToBuckets(range: TimeRange, buckets: readonly Bucket[]): TimeRange | null {
  const lo = Math.min(range.start, range.end);
  const hi = Math.max(range.start, range.end);
  let touched = buckets.filter((bucket) => bucket.start < hi && bucket.end > lo);
  if (touched.length === 0) {
    touched = buckets.filter((bucket) => bucket.start <= lo && lo <= bucket.end).slice(0, 1);
  }
  if (touched.length === 0) return null;
  return { start: touched[0]!.start, end: touched[touched.length - 1]!.end };
}

/** Brush gesture between two pixel positions -> snapped time range (null for a click). */
export function brushRange(
  x0: number,
  x1: number,
  width: number,
  buckets: readonly Bucket[],
  minDragPx = 4,
): TimeRange | null {
  if (Math.abs(x1 - x0) < minDragPx) return null;
  const domain = domainOf(buckets);
  if (!domain) return null;
  return snapToBuckets(
    {
      start: timeAtPixel(Math.min(x0, x1), width, domain),
      end: timeAtPixel(Math.max(x0, x1), width, domain),
    },
    buckets,
  );
}
