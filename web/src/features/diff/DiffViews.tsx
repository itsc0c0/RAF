import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useCreateSnapshot, useDiff, useGhostModels, useSnapshots } from '../../api/hooks';
import type { DiffChange, DiffResult, Snapshot } from '../../api/types';
import { Button } from '../../components/Button';
import { Mono, Time } from '../../components/Data';
import { Field, Select, TextInput } from '../../components/Form';
import { ObjectChip, ObjectRefText } from '../../components/ObjectChip';
import { Callout, Panel } from '../../components/Panel';
import { EmptyState, ErrorState, QueryView } from '../../components/States';
import { Table } from '../../components/Table';
import { useToast } from '../../components/Toast';
import { cx } from '../../lib/cx';
import { displayValue, formatNumber, shortHash } from '../../lib/format';
import { routeTo } from '../../lib/routes';

/** Category order of `raf diff` (src/raf/products/diff/service.py). */
export const DIFF_CATEGORIES = [
  'privileges',
  'exposure',
  'vulnerabilities',
  'network',
  'policies',
  'hosts',
  'services',
  'identities',
  'packages',
  'findings',
  'objects',
  'relationships',
  'activity',
] as const;

const IMPORTANCE = ['HIGH', 'MEDIUM', 'LOW'] as const;
export const DIFF_LIMITS = [100, 500, 1000, 2000];

/** HIGH / MEDIUM / LOW importance of a change, on the severity scale (labelled, not colour alone). */
export function ImportanceBadge({ importance }: { importance: string }) {
  const value = importance.toUpperCase();
  const level = value === 'HIGH' || value === 'MEDIUM' || value === 'LOW' ? value.toLowerCase() : 'info';
  return (
    <span className={cx('sev', `sev--${level}`)} title={`Importance: ${value}`}>
      <span className="sr-only">Importance: </span>
      <span className="sev__value">{value}</span>
    </span>
  );
}

const CHANGE_SIGNS: Record<string, string> = { added: '+', removed: '−', changed: '~' };

function ChangeKind({ change }: { change: string }) {
  return (
    <span className={cx('change-kind', `change-kind--${change}`)}>
      <span aria-hidden="true">{CHANGE_SIGNS[change] ?? '·'}</span> {change}
    </span>
  );
}

function stringDetail(details: Record<string, unknown>, key: string): string | null {
  const value = details[key];
  return typeof value === 'string' && value ? value : null;
}

function ChangeItem({ change }: { change: DiffChange }) {
  const navigate = useNavigate();
  if (change.item_kind === 'finding') {
    return (
      <button
        type="button"
        className="link-btn break"
        title={change.item_id}
        onClick={() => void navigate(routeTo.finding(change.item_id))}
      >
        {change.label}
      </button>
    );
  }
  if (change.item_kind === 'relationship') {
    const source = stringDetail(change.details, 'source');
    const target = stringDetail(change.details, 'target');
    return (
      <span className="stack stack--tight">
        <span className="break" title={change.item_id}>
          {change.label}
        </span>
        {source && target && change.change !== 'removed' ? (
          <span className="row row--wrap">
            <ObjectChip id={source} showType={false} />
            <span className="mono small muted">{stringDetail(change.details, 'type') ?? '→'}</span>
            <ObjectChip id={target} showType={false} />
          </span>
        ) : null}
      </span>
    );
  }
  return change.change === 'removed' ? (
    <ObjectRefText id={change.item_id} name={change.label} />
  ) : (
    <span className="stack stack--tight">
      <ObjectChip id={change.item_id} />
      <span className="small muted break">{change.label}</span>
    </span>
  );
}

function fieldChanges(details: Record<string, unknown>): string[] {
  const fields = details.fields;
  if (fields && typeof fields === 'object' && !Array.isArray(fields)) {
    return Object.entries(fields as Record<string, unknown>).map(([key, value]) => {
      const change = value && typeof value === 'object' ? (value as Record<string, unknown>) : {};
      return `${key}: ${displayValue(change.from)} → ${displayValue(change.to)}`;
    });
  }
  if ('from' in details || 'to' in details)
    return [`${displayValue(details.from)} → ${displayValue(details.to)}`];
  return [];
}

function ChangeDetails({ change }: { change: DiffChange }) {
  const lines = fieldChanges(change.details);
  if (lines.length === 0) return <span className="muted">—</span>;
  return (
    <ul className="diff-fields">
      {lines.slice(0, 6).map((line, index) => (
        <li key={index} className="mono small break">
          {line}
        </li>
      ))}
      {lines.length > 6 ? <li className="small muted">+{lines.length - 6} more</li> : null}
    </ul>
  );
}

/**
 * States offered for comparison: `current`, every snapshot and every Ghost model (`ghost:<name>`),
 * plus URL extras.
 */
function refOptions(
  snapshots: readonly Snapshot[],
  models: ReadonlyArray<{ name: string }>,
  extra: ReadonlyArray<string | null>,
) {
  const options = [{ value: 'current', label: 'current (live workspace)' }];
  for (const snapshot of snapshots) options.push({ value: snapshot.name, label: snapshot.name });
  for (const model of models) {
    options.push({ value: `ghost:${model.name}`, label: `ghost:${model.name} (what-if model)` });
  }
  for (const ref of extra) {
    if (ref && !options.some((option) => option.value === ref)) options.push({ value: ref, label: ref });
  }
  return options;
}

export interface CompareParams {
  a: string | null;
  b: string | null;
  category: string | null;
  limit: number;
}

export function CompareForm({
  value,
  onCompare,
}: {
  value: CompareParams;
  onCompare: (next: CompareParams) => void;
}) {
  const snapshots = useSnapshots();
  const ghost = useGhostModels();
  const items = snapshots.data?.items ?? [];
  const latest = items.length > 0 ? items[items.length - 1]!.name : null;
  const [a, setA] = useState(value.a ?? latest ?? 'current');
  const [b, setB] = useState(value.b ?? 'current');
  const [category, setCategory] = useState(value.category ?? '');
  const [limit, setLimit] = useState(value.limit);
  const options = refOptions(items, ghost.data?.items ?? [], [value.a, value.b, a, b]);
  return (
    <form
      className="filters filters--inline"
      aria-label="Compare security states"
      onSubmit={(event) => {
        event.preventDefault();
        onCompare({ a, b, category: category || null, limit });
      }}
    >
      <Field label="A (before)">
        {(id) => <Select id={id} value={a} options={options} onChange={(e) => setA(e.target.value)} />}
      </Field>
      <Field label="B (after)">
        {(id) => <Select id={id} value={b} options={options} onChange={(e) => setB(e.target.value)} />}
      </Field>
      <Field label="Category">
        {(id) => (
          <Select
            id={id}
            value={category}
            options={[{ value: '', label: 'All' }, ...DIFF_CATEGORIES.map((c) => ({ value: c, label: c }))]}
            onChange={(e) => setCategory(e.target.value)}
          />
        )}
      </Field>
      <Field label="Limit">
        {(id) => (
          <Select
            id={id}
            value={String(limit)}
            options={DIFF_LIMITS.map((n) => ({ value: String(n), label: `${n} changes` }))}
            onChange={(e) => setLimit(Number(e.target.value))}
          />
        )}
      </Field>
      <div className="filters__actions">
        <Button
          variant="ghost"
          icon="diff"
          onClick={() => {
            setA(b);
            setB(a);
          }}
        >
          Swap
        </Button>
        <Button type="submit" variant="primary" disabled={!a || !b || a === b}>
          Compare
        </Button>
      </div>
    </form>
  );
}

function DiffSummary({ result, onCategory }: { result: DiffResult; onCategory: (category: string) => void }) {
  const categories = [
    ...DIFF_CATEGORIES.filter((category) => result.summary[category]),
    ...Object.keys(result.summary).filter(
      (category) => !(DIFF_CATEGORIES as readonly string[]).includes(category),
    ),
  ];
  return (
    <div className="split">
      <Panel title="By category" flush>
        <Table<string>
          caption="Changes by category"
          dense
          rows={categories}
          rowKey={(category) => category}
          onRowClick={onCategory}
          rowLabel={(category) => `Show only ${category} changes`}
          empty={<span className="muted">No differences.</span>}
          columns={[
            { key: 'category', header: 'Category', render: (c) => <span className="tag">{c}</span> },
            {
              key: 'added',
              header: 'Added',
              align: 'right',
              render: (c) => formatNumber(result.summary[c]?.added ?? 0),
            },
            {
              key: 'removed',
              header: 'Removed',
              align: 'right',
              render: (c) => formatNumber(result.summary[c]?.removed ?? 0),
            },
            {
              key: 'changed',
              header: 'Changed',
              align: 'right',
              render: (c) => formatNumber(result.summary[c]?.changed ?? 0),
            },
          ]}
        />
      </Panel>
      <Panel title="Importance">
        <ul className="importance-counts" aria-label="Changes by importance">
          {IMPORTANCE.map((level) => (
            <li key={level}>
              <ImportanceBadge importance={level} />
              <span className="tabular">{formatNumber(result.importance[level] ?? 0)}</span>
            </li>
          ))}
        </ul>
        <p className="small muted">
          HIGH: privilege onto a privileged or critical target, new internet exposure, new CVSS ≥ 7
          vulnerability, new reachability into a critical zone. MEDIUM: other grants, new hosts, services or
          identities, policy changes. LOW: removals and other changes.
        </p>
      </Panel>
    </div>
  );
}

export function DiffResultView({
  params,
  onCategory,
}: {
  params: CompareParams;
  onCategory: (category: string | null) => void;
}) {
  const query = useDiff({ a: params.a, b: params.b, category: params.category, limit: params.limit });
  return (
    <QueryView query={query} feature="Diff" loadingLabel="Comparing states…">
      {(result) => {
        const rows = result.changes.map((change, index) => ({ change, key: `${index}:${change.item_id}` }));
        const totals = result.totals;
        return (
          <div className="stack">
            <div className="row row--wrap diff-head">
              <Mono>{result.a}</Mono>
              <span aria-hidden="true">→</span>
              <Mono>{result.b}</Mono>
              <span className="small muted">
                objects {formatNumber(totals.objects_a ?? 0)} → {formatNumber(totals.objects_b ?? 0)} ·
                relationships {formatNumber(totals.relationships_a ?? 0)} →{' '}
                {formatNumber(totals.relationships_b ?? 0)} · {formatNumber(totals.changes ?? 0)} changes
              </span>
              <span className="small muted">
                generated <Time value={result.generated_at} />
              </span>
              {query.isFetching ? <span className="small muted">Updating…</span> : null}
            </div>
            <DiffSummary result={result} onCategory={(category) => onCategory(category)} />
            <Panel
              title={params.category ? `Changes · ${params.category}` : 'Changes'}
              flush
              actions={
                params.category ? (
                  <Button size="sm" variant="ghost" onClick={() => onCategory(null)}>
                    All categories
                  </Button>
                ) : null
              }
            >
              {result.truncated ? (
                <div className="panel__pad">
                  <Callout tone="warn" title="Only the first changes are listed">
                    Showing {formatNumber(result.changes.length)} changes; raise the limit or filter by
                    category. The counts above cover every change.
                  </Callout>
                </div>
              ) : null}
              <Table<(typeof rows)[number]>
                caption="Changes"
                rows={rows}
                rowKey={(row) => row.key}
                empty={
                  <span className="muted">No differences{params.category ? ' in this category' : ''}.</span>
                }
                columns={[
                  { key: 'change', header: 'Change', render: (r) => <ChangeKind change={r.change.change} /> },
                  {
                    key: 'importance',
                    header: 'Importance',
                    render: (r) => <ImportanceBadge importance={r.change.importance} />,
                  },
                  {
                    key: 'category',
                    header: 'Category',
                    render: (r) => <span className="tag">{r.change.category}</span>,
                  },
                  { key: 'item', header: 'Item', render: (r) => <ChangeItem change={r.change} /> },
                  {
                    key: 'reason',
                    header: 'Why',
                    render: (r) => <span className="break">{r.change.reason}</span>,
                  },
                  { key: 'details', header: 'Details', render: (r) => <ChangeDetails change={r.change} /> },
                ]}
              />
            </Panel>
          </div>
        );
      }}
    </QueryView>
  );
}

function CreateSnapshotForm() {
  const create = useCreateSnapshot();
  const ghost = useGhostModels();
  const { notify } = useToast();
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [source, setSource] = useState('current');
  const sources = [
    { value: 'current', label: 'Current workspace' },
    ...(ghost.data?.items ?? []).map((model) => ({
      value: `ghost:${model.name}`,
      label: `Ghost model ${model.name}`,
    })),
  ];
  return (
    <form
      className="filters filters--inline"
      aria-label="New snapshot"
      onSubmit={(event) => {
        event.preventDefault();
        create.mutate(
          { name: name.trim(), source, description: description.trim() },
          {
            onSuccess: (snapshot) => {
              notify({ tone: 'good', title: `Snapshot ${snapshot.name} created` });
              setName('');
              setDescription('');
            },
          },
        );
      }}
    >
      <Field label="Name">
        {(id) => (
          <TextInput
            id={id}
            value={name}
            placeholder="before-remediation"
            onChange={(e) => setName(e.target.value)}
          />
        )}
      </Field>
      <Field label="Source">
        {(id) => (
          <Select id={id} value={source} options={sources} onChange={(e) => setSource(e.target.value)} />
        )}
      </Field>
      <Field label="Description (optional)" className="grow">
        {(id) => <TextInput id={id} value={description} onChange={(e) => setDescription(e.target.value)} />}
      </Field>
      <div className="filters__actions">
        <Button type="submit" icon="database" loading={create.isPending} disabled={!name.trim()}>
          Create snapshot
        </Button>
      </div>
      {create.isError ? (
        <div className="filters__error">
          <ErrorState title="The snapshot was not created" error={create.error} compact />
        </div>
      ) : null}
    </form>
  );
}

export function SnapshotsPanel({ onCompare }: { onCompare: (a: string, b: string) => void }) {
  const snapshots = useSnapshots();
  return (
    <Panel title="Snapshots" flush>
      <CreateSnapshotForm />
      <QueryView query={snapshots} feature="Snapshots">
        {(data) =>
          data.items.length === 0 ? (
            <div className="panel__pad">
              <EmptyState icon="database" title="No snapshots yet">
                <p>
                  Snapshots freeze the security state (objects, relationships, findings) for later comparison.
                </p>
              </EmptyState>
            </div>
          ) : (
            <Table<Snapshot>
              caption="Snapshots"
              dense
              rows={data.items}
              rowKey={(snapshot) => snapshot.id}
              columns={[
                {
                  key: 'name',
                  header: 'Name',
                  render: (s) => (
                    <span className="stack stack--tight">
                      <strong className="break">{s.name}</strong>
                      {s.description ? <span className="small muted break">{s.description}</span> : null}
                    </span>
                  ),
                },
                { key: 'source', header: 'Source', render: (s) => <Mono className="small">{s.source}</Mono> },
                {
                  key: 'created',
                  header: 'Created',
                  render: (s) => <Time value={s.created_at} className="small" />,
                },
                {
                  key: 'stats',
                  header: 'Objects · rels · findings',
                  render: (s) => (
                    <span className="small tabular">
                      {[s.stats.objects, s.stats.relationships, s.stats.findings]
                        .map((v) => displayValue(v ?? '—'))
                        .join(' · ')}
                    </span>
                  ),
                },
                {
                  key: 'hash',
                  header: 'Content hash',
                  render: (s) => (
                    <Mono className="small" title={s.content_hash}>
                      {shortHash(s.content_hash)}
                    </Mono>
                  ),
                },
                {
                  key: 'compare',
                  header: '',
                  render: (s) => (
                    <Button
                      size="sm"
                      variant="ghost"
                      icon="diff"
                      onClick={() => onCompare(s.name, 'current')}
                    >
                      Diff → current
                    </Button>
                  ),
                },
              ]}
            />
          )
        }
      </QueryView>
    </Panel>
  );
}
