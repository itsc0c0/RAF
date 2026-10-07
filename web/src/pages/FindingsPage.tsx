import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useFindings, useStatus } from '../api/hooks';
import { FINDING_STATUSES, SEVERITIES } from '../api/types';
import { Button } from '../components/Button';
import { Field, Select, TextInput } from '../components/Form';
import { PageHeader, Panel } from '../components/Panel';
import { EmptyState, QueryView } from '../components/States';
import { TabPanel, Tabs } from '../components/Tabs';
import { DependencyView } from '../features/dependency/DependencyViews';
import { FindingDrawer } from '../features/findings/FindingDetail';
import { FindingsTable } from '../features/findings/FindingsTable';
import { VaultView } from '../features/vault/VaultViews';
import { formatNumber } from '../lib/format';
import { useDebouncedValue } from '../lib/hooks';
import '../styles/findings.css';

const PAGE_SIZE = 50;

type Tab = 'all' | 'vault' | 'dependency';

interface Filters {
  severity: string;
  status: string;
  product: string;
  q: string;
}

function readTab(value: string | null): Tab {
  return value === 'vault' || value === 'dependency' ? value : 'all';
}

function AllFindings({ openId, onOpen }: { openId: string | null; onOpen: (id: string) => void }) {
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
              options={[{ value: '', label: 'Any' }, ...SEVERITIES.map((value) => ({ value, label: value }))]}
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
              <FindingsTable rows={page.items} selectedId={openId} onOpen={(finding) => onOpen(finding.id)} />
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
  );
}

export default function FindingsPage() {
  const [params, setParams] = useSearchParams();
  const openId = params.get('finding');
  const tab = readTab(params.get('tab'));
  const project = params.get('project');

  /** Updates some parameters and keeps the others (tab, project, open finding). */
  const update = (changes: Record<string, string | null>) => {
    const next = new URLSearchParams(params);
    for (const [key, value] of Object.entries(changes)) {
      if (value) next.set(key, value);
      else next.delete(key);
    }
    setParams(next);
  };

  return (
    <div className="page">
      <PageHeader
        title="Findings"
        subtitle="Severity (how bad if true) and confidence (how sure the evidence makes us) are independent"
      >
        <Tabs<Tab>
          label="Finding views"
          idPrefix="findings"
          value={tab}
          onChange={(next) => update({ tab: next === 'all' ? null : next, project: null })}
          items={[
            { key: 'all', label: 'All findings' },
            { key: 'vault', label: 'Secrets (Vault)' },
            { key: 'dependency', label: 'Dependencies' },
          ]}
        />
      </PageHeader>
      <TabPanel idPrefix="findings" activeKey={tab}>
        {tab === 'all' ? <AllFindings openId={openId} onOpen={(id) => update({ finding: id })} /> : null}
        {tab === 'vault' ? <VaultView selectedId={openId} onOpen={(id) => update({ finding: id })} /> : null}
        {tab === 'dependency' ? (
          <DependencyView
            project={project}
            onProject={(id) => update({ project: id })}
            onOpenFinding={(id) => update({ finding: id })}
          />
        ) : null}
      </TabPanel>
      {openId ? <FindingDrawer key={openId} id={openId} onClose={() => update({ finding: null })} /> : null}
    </div>
  );
}
