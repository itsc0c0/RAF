import { useMemo } from 'react';
import { timelineQuery, useApiQuery, useLens, useProducts } from '../../api/hooks';
import type { CountGroup, HistogramBucket, LensResponse, RafEvent, TimelineResponse } from '../../api/types';

export interface LensParams {
  scope: string;
  filter: string;
  groupBy: string;
}

export interface LensData {
  source: 'lens' | 'timeline';
  total: number;
  items: RafEvent[];
  groups: CountGroup[];
  histogram: HistogramBucket[];
  names: Record<string, string>;
  involved: Array<{ type: string; count: number }>;
  topObjects: Array<{ id: string; name?: string; type?: string; count?: number }>;
  scopeLabel: string | null;
  filters: string[];
}

function fromLens(data: LensResponse): LensData {
  return {
    source: 'lens',
    total: data.total ?? 0,
    items: data.items ?? [],
    groups: data.groups ?? [],
    histogram: data.histogram ?? [],
    names: data.names ?? {},
    involved: data.involved ?? [],
    topObjects: data.top_objects ?? [],
    scopeLabel: data.scope?.label ?? null,
    filters: [],
  };
}

function fromTimeline(data: TimelineResponse): LensData {
  return {
    source: 'timeline',
    total: data.total,
    items: data.items,
    groups: data.groups,
    histogram: data.histogram,
    names: data.names,
    involved: [],
    topObjects: [],
    scopeLabel: data.scope.label,
    filters: data.filters,
  };
}

/**
 * Investigate data: `GET /lens/query` when the Lens product is available, otherwise the same
 * question answered by `GET /timeline` (search + filter language + group-by + histogram).
 */
export function useLensData(params: LensParams) {
  const products = useProducts();
  const lensAvailable = products.data
    ? products.data.items.some((product) => product.name === 'lens' && product.available && product.enabled)
    : null;
  const query = {
    ref: params.scope.trim() || undefined,
    filter: params.filter.trim() || undefined,
    group_by: params.groupBy,
    buckets: 60,
    limit: 300,
  };
  const lens = useLens(query, lensAvailable === true);
  const timeline = useApiQuery<TimelineResponse>(
    lensAvailable === false || products.isError ? '/timeline' : null,
    timelineQuery({
      ref: query.ref,
      filter: query.filter,
      groupBy: params.groupBy,
      buckets: 60,
      limit: 300,
    }),
    { keepPrevious: true },
  );
  const active = lensAvailable ? lens : timeline;
  const data = useMemo<LensData | undefined>(() => {
    if (lensAvailable && lens.data) return fromLens(lens.data);
    if (!lensAvailable && timeline.data) return fromTimeline(timeline.data);
    return undefined;
  }, [lensAvailable, lens.data, timeline.data]);
  return {
    data,
    error: active.error,
    isError: active.isError,
    isFetching: active.isFetching || products.isPending,
    refetch: () => void active.refetch(),
  };
}
