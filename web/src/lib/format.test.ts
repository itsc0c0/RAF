import { describe, expect, it } from 'vitest';
import {
  displayValue,
  formatBytes,
  formatCompact,
  formatDuration,
  formatRelative,
  formatTime,
  formatTimestamp,
  inputFromIso,
  isoFromInput,
  isoFromMs,
  objectKeyOf,
  objectTypeOf,
} from './format';

describe('formatting', () => {
  it('formats timestamps in UTC', () => {
    expect(formatTimestamp('2026-10-06T22:52:11Z')).toBe('2026-10-06 22:52:11Z');
    expect(formatTimestamp('2026-10-06T23:52:11+01:00')).toBe('2026-10-06 22:52:11Z');
    expect(formatTime('2026-10-06T22:40:00Z')).toBe('22:40:00');
    expect(formatTimestamp(null)).toBe('—');
    expect(formatTimestamp('garbage')).toBe('—');
  });

  it('round-trips datetime-local values as UTC', () => {
    expect(isoFromInput('2026-10-06T22:40')).toBe('2026-10-06T22:40:00Z');
    expect(isoFromInput('2026-10-06T22:40:05')).toBe('2026-10-06T22:40:05Z');
    expect(isoFromInput('')).toBeNull();
    expect(isoFromInput('yesterday')).toBeNull();
    expect(inputFromIso('2026-10-06T22:40:05Z')).toBe('2026-10-06T22:40:05');
    expect(isoFromMs(Date.parse('2026-10-06T22:40:05Z'))).toBe('2026-10-06T22:40:05Z');
    expect(isoFromMs(Date.parse('2026-10-06T22:40:05.250Z'))).toBe('2026-10-06T22:40:05.250Z');
  });

  it('formats sizes, durations, counts and ages', () => {
    expect(formatBytes(48_213_000)).toBe('48.2 MB');
    expect(formatBytes(512)).toBe('512 B');
    expect(formatDuration(320)).toBe('320 ms');
    expect(formatDuration(4200)).toBe('4.2 s');
    expect(formatDuration(185_000)).toBe('3m 05s');
    expect(formatCompact(1284)).toBe('1,284');
    expect(formatCompact(12_900)).toBe('12.9K');
    expect(formatCompact(4_200_000)).toBe('4.2M');
    const now = Date.parse('2026-10-07T12:00:00Z');
    expect(formatRelative('2026-10-07T11:57:00Z', now)).toBe('3m ago');
    expect(formatRelative('2026-10-07T12:00:30Z', now)).toBe('in 30s');
  });

  it('splits object IDs and renders metadata values as plain text', () => {
    expect(objectTypeOf('host:ws-04')).toBe('host');
    expect(objectKeyOf('file:app-01|/usr/bin/curl')).toBe('app-01|/usr/bin/curl');
    expect(objectTypeOf('noprefix')).toBe('unknown');
    expect(displayValue('<b>x</b>')).toBe('<b>x</b>');
    expect(displayValue({ a: [1, '<i>'] })).toBe('{"a":[1,"<i>"]}');
    expect(displayValue(null)).toBe('null');
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    expect(displayValue(circular)).toBe('[unserializable value]');
  });
});
