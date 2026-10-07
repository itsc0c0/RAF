import { describe, expect, it } from 'vitest';
import { fuzzyFilter, fuzzyMatch } from './fuzzy';

describe('fuzzy matching', () => {
  it('matches subsequences case-insensitively and rejects non-matches', () => {
    expect(fuzzyMatch('grph', 'Open Graph')).not.toBeNull();
    expect(fuzzyMatch('GRAPH', 'open graph')).not.toBeNull();
    expect(fuzzyMatch('xyz', 'Open Graph')).toBeNull();
    expect(fuzzyMatch('hparg', 'Open Graph')).toBeNull();
  });

  it('treats an empty query as a neutral match', () => {
    expect(fuzzyMatch('   ', 'anything')).toEqual({ score: 0, indices: [] });
  });

  it('ranks prefixes and word starts above scattered matches', () => {
    const items = ['Open Settings', 'Replay Incident INC-001', 'Open Replay', 'Timeline of INC-001'];
    expect(fuzzyFilter(items, 'replay', (item) => item)[0]).toBe('Replay Incident INC-001');
    expect(fuzzyFilter(items, 'op rep', (item) => item)[0]).toBe('Open Replay');
    expect(fuzzyFilter(items, 'inc', (item) => item).slice(0, 2)).toEqual([
      'Replay Incident INC-001',
      'Timeline of INC-001',
    ]);
  });

  it('keeps the original order when the query is empty or scores tie', () => {
    const items = ['b', 'a', 'c'];
    expect(fuzzyFilter(items, '', (item) => item)).toEqual(['b', 'a', 'c']);
    expect(fuzzyFilter(['alpha one', 'alpha two'], 'alpha', (item) => item)).toEqual([
      'alpha one',
      'alpha two',
    ]);
  });
});
