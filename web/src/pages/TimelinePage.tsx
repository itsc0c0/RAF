import { useMemo, useState, type ReactNode } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useTimeline } from '../api/hooks';
import type { RafEvent } from '../api/types';
import { Badge } from '../components/Badge';
import { Button, IconButton } from '../components/Button';
import { DownloadLink } from '../components/DownloadLink';
import { Histogram } from '../components/Histogram';
import { PageHeader, Panel } from '../components/Panel';
import { LoadingState } from '../components/Spinner';
import {
  EmptyState,
  ErrorState,
  isUnavailableError,
  NoDataHint,
  UnavailableState,
} from '../components/States';
import { EventDetail } from '../features/inspector/EventDetail';
import { EventList } from '../features/timeline/EventList';
import {
  appendTerm,
  EMPTY_FILTERS,
  exportParams,
  groupFilterTerm,
  toTimelineParams,
  type TimelineFilterState,
} from '../features/timeline/filters';
import { GroupCounts } from '../features/timeline/GroupCounts';
import { TimelineFilters } from '../features/timeline/TimelineFilters';
import { formatNumber, formatTimestamp, isoFromMs, parseTime } from '../lib/format';
import '../styles/timeline.css';

const EXPORTS = [
  { format: 'csv', label: 'CSV' },
  { format: 'json', label: 'JSON' },
  { format: 'raf', label: 'R$F bundle' },
] as const;

export default function TimelinePage() {
  const [params] = useSearchParams();
  const scope = params.get('object') ?? params.get('scope') ?? params.get('incident') ?? '';
  return <TimelineView key={scope} initialScope={scope} />;
}

function hasFilters(state: TimelineFilterState): boolean {
  return Boolean(state.types || state.category || state.severity || state.filter || state.start || state.end);
}

function TimelineView({ initialScope }: { initialScope: string }) {
  const [filters, setFilters] = useState<TimelineFilterState>({ ...EMPTY_FILTERS, scope: initialScope });
  const [selected, setSelected] = useState<RafEvent | null>(null);
  const query = useTimeline(toTimelineParams(filters));
  const pages = query.data?.pages;
  const first = pages?.[0];
  const events = useMemo(() => (pages ?? []).flatMap((page) => page.items), [pages]);
  const names = useMemo(
    () => Object.assign({}, ...(pages ?? []).map((page) => page.names)) as Record<string, string>,
    [pages],
  );
  const filterKey = JSON.stringify(filters);

  const apply = (next: TimelineFilterState) => {
    setFilters(next);
    setSelected(null);
  };

  const selection = (() => {
    const start = parseTime(filters.start);
    const end = parseTime(filters.end);
    return start !== null && end !== null ? { start, end } : null;
  })();

  const loadMore = () => {
    if (query.hasNextPage && !query.isFetchingNextPage) void query.fetchNextPage();
  };

  let body: ReactNode;
  if (query.isError && !first) {
    body = isUnavailableError(query.error) ? (
      <UnavailableState feature="Timeline" error={query.error} />
    ) : (
      <ErrorState error={query.error} onRetry={() => void query.refetch()} />
    );
  } else if (!first) {
    body = <LoadingState label="Loading timeline…" />;
  } else if (first.total === 0) {
    body =
      !filters.scope && !hasFilters(filters) ? (
        <NoDataHint />
      ) : (
        <EmptyState icon="filter" title="No events match">
          <p>Widen the time window or remove filters.</p>
        </EmptyState>
      );
  } else {
    body = (
      <div className="timeline-results">
        <Panel title={`By ${filters.groupBy.replace('_', ' ')}`} className="timeline-groups">
          <GroupCounts
            groups={first.groups}
            field={filters.groupBy}
            onPick={(key) =>
              apply({ ...filters, filter: appendTerm(filters.filter, groupFilterTerm(filters.groupBy, key)) })
            }
          />
        </Panel>
        <section className="timeline-events" aria-label="Event list">
          <EventList
            events={events}
            names={names}
            selectedId={selected?.id ?? null}
            onSelect={setSelected}
            onEndReached={loadMore}
            height="100%"
          />
          <footer className="timeline-events__footer">
            <span className="tabular">
              Showing {formatNumber(events.length)} of {formatNumber(first.total)} events
            </span>
            {query.hasNextPage ? (
              <Button size="sm" loading={query.isFetchingNextPage} onClick={loadMore}>
                Load more
              </Button>
            ) : (
              <span className="muted small">End of timeline</span>
            )}
          </footer>
        </section>
        {selected ? (
          <aside className="timeline-detail panel" aria-label="Event detail">
            <header className="panel__header">
              <h2 className="panel__title mono break">{selected.event_type}</h2>
              <IconButton icon="close" label="Close event detail" onClick={() => setSelected(null)} />
            </header>
            <div className="panel__body">
              <EventDetail event={selected} names={names} />
            </div>
          </aside>
        ) : null}
      </div>
    );
  }

  return (
    <div className="page page--full timeline-page">
      <PageHeader
        title="Timeline"
        subtitle={
          first ? (
            <>
              <span className="break">{first.scope.label}</span>
              <span className="muted tabular">
                {formatNumber(first.total)} events · {formatTimestamp(first.first)} →{' '}
                {formatTimestamp(first.last)}
              </span>
              {first.filters.map((term) => (
                <Badge key={term} tone="accent" outline>
                  {term}
                </Badge>
              ))}
            </>
          ) : (
            'Unified events for any scope'
          )
        }
        actions={
          <div className="row" role="group" aria-label="Export timeline">
            {EXPORTS.map((item) => (
              <DownloadLink
                key={item.format}
                className="btn btn--secondary btn--sm"
                path="/timeline/export"
                query={exportParams(filters, item.format)}
                filename={`raf-timeline.${item.format}`}
              >
                {item.label}
              </DownloadLink>
            ))}
          </div>
        }
      >
        <TimelineFilters key={filterKey} value={filters} onApply={apply} />
      </PageHeader>
      {first && first.histogram.length > 0 ? (
        <div className="timeline-histogram">
          <Histogram
            label="Events over time"
            buckets={first.histogram}
            selection={selection}
            onBrush={(range) =>
              apply({
                ...filters,
                start: range ? isoFromMs(range.start) : null,
                end: range ? isoFromMs(range.end) : null,
              })
            }
          />
          {filters.start || filters.end ? (
            <div className="row small">
              <span className="muted">Window</span>
              <span className="tabular">
                {formatTimestamp(filters.start)} → {formatTimestamp(filters.end)}
              </span>
              <Button size="sm" variant="ghost" onClick={() => apply({ ...filters, start: null, end: null })}>
                Clear window
              </Button>
            </div>
          ) : (
            <p className="small muted">Drag across the histogram to zoom into a time window.</p>
          )}
        </div>
      ) : null}
      {body}
    </div>
  );
}
