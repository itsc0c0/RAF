import { describe, expect, it } from 'vitest';
import { brushRange, domainOf, pixelAtTime, snapToBuckets, timeAtPixel, toBuckets } from './histogramMath';

// Shape of GET /timeline histogram: uniform buckets, the last one at `last`.
const RAW = [
  { start: '2026-10-06T22:00:00Z', count: 2 },
  { start: '2026-10-06T22:10:00Z', count: 0 },
  { start: '2026-10-06T22:20:00Z', count: 5 },
  { start: '2026-10-06T22:30:00Z', count: 1 },
];
const T = (time: string) => Date.parse(`2026-10-06T${time}Z`);

describe('histogram geometry', () => {
  it('derives bucket intervals from consecutive starts', () => {
    const buckets = toBuckets(RAW);
    expect(buckets.map((bucket) => [bucket.start, bucket.end])).toEqual([
      [T('22:00:00'), T('22:10:00')],
      [T('22:10:00'), T('22:20:00')],
      [T('22:20:00'), T('22:30:00')],
      [T('22:30:00'), T('22:40:00')],
    ]);
    expect(domainOf(buckets)).toEqual({ start: T('22:00:00'), end: T('22:40:00') });
    expect(toBuckets([{ start: '2026-10-06T22:00:00Z', count: 1 }])[0]!.end).toBe(T('22:01:00'));
    expect(toBuckets([{ start: 'not a date', count: 1 }])).toEqual([]);
  });

  it('maps pixels to time and back (clamped)', () => {
    const domain = { start: T('22:00:00'), end: T('22:40:00') };
    expect(timeAtPixel(200, 400, domain)).toBe(T('22:20:00'));
    expect(timeAtPixel(-10, 400, domain)).toBe(domain.start);
    expect(timeAtPixel(999, 400, domain)).toBe(domain.end);
    expect(pixelAtTime(T('22:10:00'), 400, domain)).toBe(100);
  });

  it('snaps a brushed range to whole buckets', () => {
    const buckets = toBuckets(RAW);
    expect(snapToBuckets({ start: T('22:12:00'), end: T('22:24:00') }, buckets)).toEqual({
      start: T('22:10:00'),
      end: T('22:30:00'),
    });
    // A boundary-aligned selection does not spill into the next bucket.
    expect(snapToBuckets({ start: T('22:20:00'), end: T('22:30:00') }, buckets)).toEqual({
      start: T('22:20:00'),
      end: T('22:30:00'),
    });
  });

  it('turns a drag into a range and ignores clicks', () => {
    const buckets = toBuckets(RAW);
    expect(brushRange(110, 290, 400, buckets)).toEqual({ start: T('22:10:00'), end: T('22:30:00') });
    expect(brushRange(290, 110, 400, buckets)).toEqual({ start: T('22:10:00'), end: T('22:30:00') });
    expect(brushRange(100, 102, 400, buckets)).toBeNull();
    expect(brushRange(0, 100, 400, [])).toBeNull();
  });
});
