/** Timeline filter state and its mapping to API parameters (pure). */

import type { TimelineParams } from '../../api/hooks';

export const GROUP_FIELDS = [
  'category',
  'event_type',
  'actor',
  'target',
  'severity',
  'source',
  'outcome',
] as const;
export type GroupField = (typeof GROUP_FIELDS)[number];

export interface TimelineFilterState {
  scope: string;
  types: string;
  category: string;
  severity: string;
  filter: string;
  start: string | null;
  end: string | null;
  groupBy: GroupField;
}

export const EMPTY_FILTERS: TimelineFilterState = {
  scope: '',
  types: '',
  category: '',
  severity: '',
  filter: '',
  start: null,
  end: null,
  groupBy: 'category',
};

export function splitList(value: string): string[] {
  return value
    .split(',')
    .map((part) => part.trim())
    .filter(Boolean);
}

export function toTimelineParams(state: TimelineFilterState, limit = 500): TimelineParams {
  return {
    ref: state.scope.trim() || null,
    type: splitList(state.types),
    category: splitList(state.category),
    severity: state.severity || null,
    filter: state.filter.trim() || null,
    start: state.start,
    end: state.end,
    groupBy: state.groupBy,
    buckets: 72,
    limit,
  };
}

/** Quotes a value for the filter language (shlex rules on the server). */
export function quoteFilterValue(value: string): string {
  return /[\s"'\\]/.test(value) ? `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"` : value;
}

const GROUP_KEYS: Record<GroupField, string> = {
  category: 'category',
  event_type: 'type',
  actor: 'actor',
  target: 'target',
  severity: 'severity',
  source: 'source',
  outcome: 'outcome',
};

/** Filter-language term that narrows to a group-by bucket (`category:auth`, `type:auth.login`). */
export function groupFilterTerm(field: GroupField, key: string): string {
  return `${GROUP_KEYS[field]}:${quoteFilterValue(key)}`;
}

export function appendTerm(filter: string, term: string): string {
  const current = filter.trim();
  if (current.split(/\s+/).includes(term)) return current;
  return current ? `${current} ${term}` : term;
}

/**
 * Export parameters. The export endpoint accepts ref/start/end/type/severity/filter, so the
 * category filter travels as filter-language terms to keep exports identical to the view.
 */
export function exportParams(state: TimelineFilterState, format: string) {
  const categoryTerms = splitList(state.category).map((category) => `category:${quoteFilterValue(category)}`);
  const filter = [state.filter.trim(), ...categoryTerms].filter(Boolean).join(' ');
  return {
    ref: state.scope.trim() || undefined,
    format,
    start: state.start ?? undefined,
    end: state.end ?? undefined,
    type: splitList(state.types),
    severity: state.severity || undefined,
    filter: filter || undefined,
  };
}
