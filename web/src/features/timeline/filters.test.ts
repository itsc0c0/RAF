import { describe, expect, it } from 'vitest';
import {
  appendTerm,
  EMPTY_FILTERS,
  exportParams,
  groupFilterTerm,
  quoteFilterValue,
  toTimelineParams,
} from './filters';

describe('timeline filters', () => {
  it('maps form state to API parameters', () => {
    const params = toTimelineParams({
      ...EMPTY_FILTERS,
      scope: ' INC-001 ',
      types: 'auth.login, process.start,',
      category: 'auth',
      severity: 'HIGH',
      filter: ' actor:bob ',
      start: '2026-10-06T22:00:00Z',
    });
    expect(params).toMatchObject({
      ref: 'INC-001',
      type: ['auth.login', 'process.start'],
      category: ['auth'],
      severity: 'HIGH',
      filter: 'actor:bob',
      start: '2026-10-06T22:00:00Z',
      end: null,
      groupBy: 'category',
    });
    expect(toTimelineParams(EMPTY_FILTERS).ref).toBeNull();
  });

  it('turns group-by buckets into filter-language terms (quoted when needed)', () => {
    expect(groupFilterTerm('category', 'auth')).toBe('category:auth');
    expect(groupFilterTerm('event_type', 'auth.login')).toBe('type:auth.login');
    expect(groupFilterTerm('actor', 'user:bob')).toBe('actor:user:bob');
    expect(groupFilterTerm('source', 'proxy logs.csv')).toBe('source:"proxy logs.csv"');
    expect(quoteFilterValue('say "hi"')).toBe('"say \\"hi\\""');
    expect(appendTerm('', 'category:auth')).toBe('category:auth');
    expect(appendTerm('actor:bob', 'category:auth')).toBe('actor:bob category:auth');
    expect(appendTerm('actor:bob category:auth', 'category:auth')).toBe('actor:bob category:auth');
  });

  it('keeps exports identical to the view (category travels as a filter term)', () => {
    expect(
      exportParams(
        { ...EMPTY_FILTERS, scope: 'INC-001', category: 'auth, network', filter: 'actor:bob' },
        'csv',
      ),
    ).toEqual({
      ref: 'INC-001',
      format: 'csv',
      start: undefined,
      end: undefined,
      type: [],
      severity: undefined,
      filter: 'actor:bob category:auth category:network',
    });
  });
});
