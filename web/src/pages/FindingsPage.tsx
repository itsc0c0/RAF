import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useFindings, useStatus } from '../api/hooks';
import { FINDING_STATUSES, SEVERITIES, type Finding } from '../api/types';
import { ConfidenceBadge, SeverityBadge } from '../components/Badge';
import { Button } from '../components/Button';
import { Time } from '../components/Data';
import { Field, Select, TextInput } from '../components/Form';
import { ObjectChip } from '../components/ObjectChip';
import { PageHeader, Panel } from '../components/Panel';
import { EmptyState, QueryView } from '../components/States';
import { Table } from '../components/Table';
import { FindingDrawer, FindingStatusBadge } from '../features/findings/FindingDetail';
import { formatNumber } from '../lib/format';
import { useDebouncedValue } from '../lib/hooks';

const PAGE_SIZE = 50;

interface Filters {
  severity: string;
  status: string;
  product: string;
  q: string;
}

export function FindingsTable({
  rows,
  selectedId,
  onOpen,
}: {
  rows: readonly Finding[];
  selectedId: string | null;
  onOpen: (finding: Finding) => void;
}) {
  return (
    <Table<Finding>
      caption="Findings"
      rows={rows}
      rowKey={(finding) => finding.id}
      selectedKey={selectedId}
      onRowClick={onOpen}
      rowLabel={(finding) => `Open finding ${finding.title}`}
      empty={<span className="muted">No findings match these filters.</span>}
      columns={[
        {
          key: 'severity',
          header: 'Severity',
          width: '96px',
          render: (f) => <SeverityBadge severity={f.severity} />,
        },
        {
          key: 'confidence',
          header: 'Confidence',
          width: '128px',
          render: (f) => <ConfidenceBadge confidence={f.confidence} level={f.confidence_level} />,
        },
        {
          key: 'title',
          header: 'Finding',
          render: (f) => (
            <span className="stack stack--tight">
              <span className="break">{f.title}</span>
              <span className="mono small muted">{f.rule_id}</span>
            </span>
          ),
        },
        { key: 'product', header: 'Product', render: (f) => <span className="mono small">{f.product}</span> },
        { key: 'status', header: 'Status', render: (f) => <FindingStatusBadge status={f.status} /> },
        {
          key: 'affected',
          header: 'Affected',
          render: (f) => (
            <span className="row row--wrap">
              {f.affected_objects.slice(0, 2).map((id) => (
                <ObjectChip key={id} id={id} showType={false} />
              ))}
              {f.affected_objects.length > 2 ? (
                <span className="small muted">+{f.affected_objects.length - 2}</span>
              ) : null}
            </span>
          ),
        },
        { key: 'updated', header: 'Updated', render: (f) => <Time value={f.updated_at} className="small" /> },
      ]}
    />
  );
}

export default function FindingsPage() {
  const [params, setParams] = useSearchParams();
  const openId = params.get('finding');
  const [filters, setFilters] = useState<Filters>({ severity: '', status: 'OPEN', product: '', q: '' });
  const [offset, setOffset] = useState(0);
  const q = useDebouncedValue(filters.q.trim(), 300);
  const status = useStatus();
  const query = useFindings({
    severity: filters.severity || undefined,
    status: filters.status ? [filters.status] : [],
    product: filters.product.trim() || undefined,
    q: q || undefined,
    limit: PAGE_SIZE,
    offset,
  });

  const update = (patch: Partial<Filters>) => {
    setFilters((current) => ({ ...current, ...patch }));
    setOffset(0);
  };

  const total = query.data?.total ?? 0;
  const totalFindings = status.data?.data.findings;

  return (
    <div className="page">
      <PageHeader
        title="Findings"
        subtitle="Severity (how bad if true) and confidence (how sure the evidence makes us) are independent"
      />
      <Panel flush>
        <form
          className="filters filters--inline"
          aria-label="Finding filters"
          onSubmit={(event) => event.preventDefault()}
        >
          <Field label="Min severity">
            {(id) => (
              <Select
                id={id}
                value={filters.severity}
                options={[
                  { value: '', label: 'Any' },
                  ...SEVERITIES.map((value) => ({ value, label: value })),
                ]}
                onChange={(event) => update({ severity: event.target.value })}
              />
            )}
          </Field>
          <Field label="Status">
            {(id) => (
              <Select
                id={id}
                value={filters.status}
                options={[
                  { value: '', label: 'Any' },
                  ...FINDING_STATUSES.map((value) => ({ value, label: value.replace('_', ' ') })),
                ]}
                onChange={(event) => update({ status: event.target.value })}
              />
            )}
          </Field>
          <Field label="Product">
            {(id) => (
              <TextInput
                id={id}
                value={filters.product}
                placeholder="iam, exposure…"
                onChange={(event) => update({ product: event.target.value })}
              />
            )}
          </Field>
          <Field label="Search" className="grow">
            {(id) => (
              <TextInput
                id={id}
                value={filters.q}
                placeholder="Title or description"
                onChange={(event) => update({ q: event.target.value })}
              />
            )}
          </Field>
        </form>
        <QueryView query={query} feature="Findings">
          {(page) =>
            page.items.length === 0 && totalFindings === 0 ? (
              <div className="panel__pad">
                <EmptyState title="No findings yet">
                  <p>
                    Findings are produced by analysis products (IAM, exposure, policy…). Run an analysis, e.g.{' '}
                    <code>raf iam analyze</code>, or load the demo with <code>raf demo load</code>.
                  </p>
                </EmptyState>
              </div>
            ) : (
              <>
                <FindingsTable
                  rows={page.items}
                  selectedId={openId}
                  onOpen={(finding) => setParams({ finding: finding.id })}
                />
                <footer className="table-footer">
                  <span className="tabular small muted">
                    {total === 0
                      ? 'No results'
                      : `${formatNumber(offset + 1)}–${formatNumber(offset + page.items.length)} of ${formatNumber(total)}`}
                  </span>
                  <span className="row">
                    <Button
                      size="sm"
                      disabled={offset === 0}
                      onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
                    >
                      Previous
                    </Button>
                    <Button
                      size="sm"
                      disabled={offset + PAGE_SIZE >= total}
                      onClick={() => setOffset(offset + PAGE_SIZE)}
                    >
                      Next
                    </Button>
                  </span>
                </footer>
              </>
            )
          }
        </QueryView>
      </Panel>
      {openId ? <FindingDrawer key={openId} id={openId} onClose={() => setParams({})} /> : null}
    </div>
  );
}
