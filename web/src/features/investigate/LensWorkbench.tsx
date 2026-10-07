import { useState } from 'react';
import { useObjects } from '../../api/hooks';
import type { SecurityObject } from '../../api/types';
import { useInspector } from '../../app/shellState';
import { Badge, ConfidenceBadge } from '../../components/Badge';
import { Button } from '../../components/Button';
import { Field, Select, TextInput } from '../../components/Form';
import { Histogram } from '../../components/Histogram';
import { ObjectChip, TypeTag } from '../../components/ObjectChip';
import { Panel } from '../../components/Panel';
import { LoadingState } from '../../components/Spinner';
import {
  EmptyState,
  ErrorState,
  isUnavailableError,
  NoDataHint,
  QueryView,
  UnavailableState,
} from '../../components/States';
import { Table } from '../../components/Table';
import { formatNumber, isoFromMs } from '../../lib/format';
import { useDebouncedValue } from '../../lib/hooks';
import { EventList } from '../timeline/EventList';
import { appendTerm, GROUP_FIELDS, groupFilterTerm, type GroupField } from '../timeline/filters';
import { GroupCounts } from '../timeline/GroupCounts';
import { FILTER_HELP } from '../timeline/TimelineFilters';
import { QuickPivots } from './quickPivots';
import { useLensData, type LensParams } from './useLensData';

/** Replaces any after:/before: terms with the brushed window. */
export function withTimeWindow(filter: string, start: string | null, end: string | null): string {
  const kept = filter
    .trim()
    .split(/\s+/)
    .filter((term) => term && !term.startsWith('after:') && !term.startsWith('before:'));
  if (start) kept.push(`after:${start}`);
  if (end) kept.push(`before:${end}`);
  return kept.join(' ');
}

function ObjectSearch() {
  const [text, setText] = useState('');
  const q = useDebouncedValue(text.trim(), 250);
  const objects = useObjects({ q, limit: 25 }, q.length > 0);
  const inspector = useInspector();
  return (
    <Panel title="Objects" id="lens-objects">
      <div className="stack">
        <Field label="Find objects by name, ID or alias">
          {(id) => (
            <TextInput
              id={id}
              value={text}
              placeholder="e.g. svc-deploy, 10.20.0.11, DB-01"
              onChange={(e) => setText(e.target.value)}
            />
          )}
        </Field>
        {q ? (
          <QueryView query={objects} feature="Object search" compact>
            {(page) => (
              <Table<SecurityObject>
                caption="Matching objects"
                dense
                rows={page.items}
                rowKey={(object) => object.id}
                onRowClick={(object) => inspector.open(object.id)}
                empty={<span className="muted">No objects match “{q}”.</span>}
                columns={[
                  { key: 'type', header: 'Type', width: '120px', render: (o) => <TypeTag type={o.type} /> },
                  { key: 'name', header: 'Name', render: (o) => <span className="break">{o.name}</span> },
                  {
                    key: 'id',
                    header: 'ID',
                    render: (o) => <span className="mono small muted break">{o.id}</span>,
                  },
                  {
                    key: 'conf',
                    header: 'Confidence',
                    render: (o) => (
                      <ConfidenceBadge
                        confidence={o.confidence}
                        level={o.confidence_level}
                        showValue={false}
                      />
                    ),
                  },
                  { key: 'pivots', header: 'Pivot', render: (o) => <QuickPivots id={o.id} type={o.type} /> },
                ]}
              />
            )}
          </QueryView>
        ) : (
          <p className="muted small">
            Type to search objects; each result pivots to Graph, Timeline, Trace, Evidence or Exposure.
          </p>
        )}
      </div>
    </Panel>
  );
}

/** Lens-style workbench: scope + filter language + group-by + histogram + results + pivots. */
export function LensWorkbench({ initialScope }: { initialScope: string }) {
  const inspector = useInspector();
  const [applied, setApplied] = useState<LensParams>({
    scope: initialScope,
    filter: '',
    groupBy: 'category',
  });
  const [draft, setDraft] = useState(applied);
  const result = useLensData(applied);
  const data = result.data;

  const apply = (next: LensParams) => {
    setApplied(next);
    setDraft(next);
  };

  return (
    <div className="stack">
      <form
        className="filters filters--lens"
        aria-label="Lens query"
        onSubmit={(event) => {
          event.preventDefault();
          apply(draft);
        }}
      >
        <Field label="Scope" className="filters__scope">
          {(id) => (
            <TextInput
              id={id}
              value={draft.scope}
              placeholder="workspace, INC-001, alice, host:ws-04…"
              onChange={(e) => setDraft({ ...draft, scope: e.target.value })}
            />
          )}
        </Field>
        <Field
          label="Filter"
          className="filters__query"
          hint={<span title={FILTER_HELP}>R$F filter language · hover for keys</span>}
        >
          {(id) => (
            <TextInput
              id={id}
              className="mono"
              value={draft.filter}
              title={FILTER_HELP}
              placeholder='type:auth.* severity>=medium "export"'
              onChange={(e) => setDraft({ ...draft, filter: e.target.value })}
            />
          )}
        </Field>
        <Field label="Group by">
          {(id) => (
            <Select
              id={id}
              value={draft.groupBy}
              options={GROUP_FIELDS.map((field) => ({ value: field, label: field.replace('_', ' ') }))}
              onChange={(e) => apply({ ...draft, groupBy: e.target.value })}
            />
          )}
        </Field>
        <div className="filters__actions">
          <Button type="submit" variant="primary" icon="search" loading={result.isFetching && !data}>
            Run
          </Button>
        </div>
      </form>

      {result.isError && !data ? (
        isUnavailableError(result.error) ? (
          <UnavailableState feature="Lens" error={result.error} />
        ) : (
          <ErrorState error={result.error} onRetry={result.refetch} />
        )
      ) : !data ? (
        <LoadingState label="Querying…" />
      ) : data.total === 0 && !applied.scope && !applied.filter ? (
        <NoDataHint />
      ) : (
        <>
          <div className="row row--wrap small">
            <Badge tone={data.source === 'lens' ? 'accent' : 'neutral'} outline>
              {data.source === 'lens' ? 'Lens' : 'Timeline fallback'}
            </Badge>
            <span className="muted">{data.scopeLabel}</span>
            <span className="tabular">{formatNumber(data.total)} events</span>
            {data.filters.map((term) => (
              <Badge key={term} tone="accent" outline>
                {term}
              </Badge>
            ))}
          </div>
          {data.histogram.length > 0 ? (
            <Histogram
              label="Matching events over time"
              buckets={data.histogram}
              onBrush={(range) =>
                apply({
                  ...applied,
                  filter: withTimeWindow(
                    applied.filter,
                    range ? isoFromMs(range.start) : null,
                    range ? isoFromMs(range.end) : null,
                  ),
                })
              }
            />
          ) : null}
          {data.total === 0 ? (
            <EmptyState icon="filter" title="No events match">
              <p>Remove terms from the filter or widen the scope.</p>
            </EmptyState>
          ) : (
            <div className="lens-grid">
              <div className="stack">
                <Panel title={`By ${applied.groupBy.replace('_', ' ')}`}>
                  <GroupCounts
                    groups={data.groups}
                    field={applied.groupBy}
                    onPick={(key) =>
                      apply({
                        ...applied,
                        filter: appendTerm(
                          applied.filter,
                          groupFilterTerm(applied.groupBy as GroupField, key),
                        ),
                      })
                    }
                  />
                </Panel>
                {data.involved.length > 0 ? (
                  <Panel title="Involved object types">
                    <ul className="stack stack--tight">
                      {data.involved.map((entry) => (
                        <li key={entry.type} className="row row--between">
                          <TypeTag type={entry.type} />
                          <span className="tabular">{formatNumber(entry.count)}</span>
                        </li>
                      ))}
                    </ul>
                  </Panel>
                ) : null}
                {data.topObjects.length > 0 ? (
                  <Panel title="Top objects">
                    <ul className="stack stack--tight">
                      {data.topObjects.map((object) => (
                        <li key={object.id} className="row row--between">
                          <ObjectChip id={object.id} name={object.name} type={object.type} />
                          {object.count !== undefined ? (
                            <span className="tabular small">{formatNumber(object.count)}</span>
                          ) : null}
                        </li>
                      ))}
                    </ul>
                  </Panel>
                ) : null}
              </div>
              <section className="lens-events" aria-label="Matching events">
                <EventList
                  events={data.items}
                  names={data.names}
                  selectedId={null}
                  onSelect={(event) => inspector.openEvent(event.id)}
                  height={420}
                />
                {data.items.length < data.total ? (
                  <p className="small muted">
                    Showing the first {formatNumber(data.items.length)} of {formatNumber(data.total)} events —
                    open the Timeline for the complete, paginated list.
                  </p>
                ) : null}
              </section>
            </div>
          )}
        </>
      )}
      <ObjectSearch />
    </div>
  );
}
