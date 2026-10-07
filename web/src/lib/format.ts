/**
 * Formatting helpers. All timestamps are displayed in UTC (the API, CLI and evidence all speak UTC),
 * so the same instant reads identically in the terminal and in the browser.
 */

const DASH = '—';

const pad = (value: number, width = 2): string => String(value).padStart(width, '0');

/** Milliseconds since epoch, or null when the value is missing or unparseable. */
export function parseTime(value: string | null | undefined): number | null {
  if (!value) return null;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? null : ms;
}

function utcParts(ms: number) {
  const d = new Date(ms);
  return {
    y: d.getUTCFullYear(),
    mo: pad(d.getUTCMonth() + 1),
    d: pad(d.getUTCDate()),
    h: pad(d.getUTCHours()),
    mi: pad(d.getUTCMinutes()),
    s: pad(d.getUTCSeconds()),
  };
}

/** `2026-10-06 22:52:11Z` */
export function formatTimestamp(value: string | number | null | undefined): string {
  const ms = typeof value === 'number' ? value : parseTime(value);
  if (ms === null) return DASH;
  const p = utcParts(ms);
  return `${p.y}-${p.mo}-${p.d} ${p.h}:${p.mi}:${p.s}Z`;
}

/** `22:52:11` (UTC) */
export function formatTime(value: string | number | null | undefined): string {
  const ms = typeof value === 'number' ? value : parseTime(value);
  if (ms === null) return DASH;
  const p = utcParts(ms);
  return `${p.h}:${p.mi}:${p.s}`;
}

/** `2026-10-06` (UTC) */
export function formatDate(value: string | number | null | undefined): string {
  const ms = typeof value === 'number' ? value : parseTime(value);
  if (ms === null) return DASH;
  const p = utcParts(ms);
  return `${p.y}-${p.mo}-${p.d}`;
}

/** Short relative age, computed against an explicit `now` so callers stay pure. */
export function formatRelative(value: string | null | undefined, now: number): string {
  const ms = parseTime(value);
  if (ms === null) return DASH;
  const seconds = Math.round((now - ms) / 1000);
  const future = seconds < 0;
  const abs = Math.abs(seconds);
  let text: string;
  if (abs < 45) text = `${abs}s`;
  else if (abs < 45 * 60) text = `${Math.round(abs / 60)}m`;
  else if (abs < 36 * 3600) text = `${Math.round(abs / 3600)}h`;
  else text = `${Math.round(abs / 86400)}d`;
  return future ? `in ${text}` : `${text} ago`;
}

/** `320 ms`, `4.2 s`, `3m 05s`, `2h 01m` */
export function formatDuration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms)) return DASH;
  if (ms < 1000) return `${Math.round(ms)} ms`;
  const seconds = ms / 1000;
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  const total = Math.round(seconds);
  if (total < 3600) return `${Math.floor(total / 60)}m ${pad(total % 60)}s`;
  return `${Math.floor(total / 3600)}h ${pad(Math.floor((total % 3600) / 60))}m`;
}

/** Decimal (SI) byte sizes, matching the backend's `48.2 MB`. */
export function formatBytes(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return DASH;
  const units = ['B', 'kB', 'MB', 'GB', 'TB'];
  let size = Math.abs(value);
  let unit = 0;
  while (size >= 1000 && unit < units.length - 1) {
    size /= 1000;
    unit += 1;
  }
  const digits = unit === 0 ? 0 : size < 10 ? 1 : size < 100 ? 1 : 0;
  return `${value < 0 ? '-' : ''}${size.toFixed(digits)} ${units[unit] ?? 'B'}`;
}

export function formatNumber(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return DASH;
  return value.toLocaleString('en-US');
}

/** `1,284` / `12.9K` / `4.2M` */
export function formatCompact(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return DASH;
  const abs = Math.abs(value);
  if (abs < 10_000) return value.toLocaleString('en-US');
  if (abs < 1_000_000) return `${(value / 1000).toFixed(abs < 100_000 ? 1 : 0)}K`;
  return `${(value / 1_000_000).toFixed(1)}M`;
}

export function formatConfidence(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return DASH;
  return value.toFixed(2);
}

export function formatPercent(fraction: number | null | undefined): string {
  if (fraction === null || fraction === undefined || !Number.isFinite(fraction)) return DASH;
  return `${Math.round(fraction * 100)}%`;
}

/**
 * Converts a `datetime-local` input value (interpreted as UTC, which the UI labels explicitly)
 * to an ISO-8601 UTC timestamp. Returns null for empty or malformed input.
 */
export function isoFromInput(value: string): string | null {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?/.exec(value.trim());
  if (!match) return null;
  const [, y, mo, d, h, mi, s] = match;
  const iso = `${y}-${mo}-${d}T${h}:${mi}:${s ?? '00'}Z`;
  return Number.isNaN(Date.parse(iso)) ? null : iso;
}

/** ISO timestamp -> `datetime-local` value in UTC (`2026-10-06T22:40:00`). */
export function inputFromIso(value: string | null | undefined): string {
  const ms = parseTime(value);
  if (ms === null) return '';
  const p = utcParts(ms);
  return `${p.y}-${p.mo}-${p.d}T${p.h}:${p.mi}:${p.s}`;
}

/** ISO string for a millisecond instant without fractional seconds when they are zero. */
export function isoFromMs(ms: number): string {
  const iso = new Date(ms).toISOString();
  return iso.endsWith('.000Z') ? `${iso.slice(0, -5)}Z` : iso;
}

export function shortHash(value: string | null | undefined, length = 12): string {
  if (!value) return DASH;
  return value.length > length ? `${value.slice(0, length)}…` : value;
}

/** `host:ws-04` -> `host`. Types never contain ':'. */
export function objectTypeOf(id: string): string {
  const index = id.indexOf(':');
  return index > 0 ? id.slice(0, index) : 'unknown';
}

/** `host:ws-04` -> `ws-04` */
export function objectKeyOf(id: string): string {
  const index = id.indexOf(':');
  return index >= 0 ? id.slice(index + 1) : id;
}

/** Renders any metadata value as plain text (never markup). */
export function displayValue(value: unknown): string {
  if (value === null) return 'null';
  if (value === undefined) return DASH;
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') {
    return String(value);
  }
  try {
    return JSON.stringify(value) ?? '[unserializable value]';
  } catch {
    return '[unserializable value]';
  }
}

export function pluralize(count: number, word: string, plural = `${word}s`): string {
  return `${formatNumber(count)} ${count === 1 ? word : plural}`;
}

/** `iam.group.remove` -> `iam group remove` style humanization for enum-like keys. */
export function humanize(value: string): string {
  return value.replace(/[_.]+/g, ' ').replace(/\s+/g, ' ').trim();
}

export function titleCase(value: string): string {
  return humanize(value)
    .split(' ')
    .map((word) => (word ? word[0]!.toUpperCase() + word.slice(1).toLowerCase() : word))
    .join(' ');
}
