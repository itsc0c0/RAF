import { useId, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  useApplyGhostOp,
  useCloneGhostModel,
  useCreateGhostModel,
  useCreateSnapshot,
  useDeleteGhostModel,
  useGhostCompare,
  useGhostModel,
  useGhostModels,
  useGhostOperations,
  useGhostSimulation,
  useSnapshots,
  useUndoGhostOp,
} from '../../api/hooks';
import type {
  AssetExposure,
  ExposureMetrics,
  GhostAssetChange,
  GhostModel,
  GhostModelSummary,
  GhostOp,
  GhostUserChange,
} from '../../api/types';
import { RiskLevelBadge } from '../../components/Badge';
import { Button } from '../../components/Button';
import { FactorList, KeyValueList, Meter, Mono, StatTile, Time } from '../../components/Data';
import { Field, Select, TextArea, TextInput } from '../../components/Form';
import { ConfirmDialog, Modal } from '../../components/Modal';
import { ObjectChip } from '../../components/ObjectChip';
import { Callout, Panel } from '../../components/Panel';
import { EmptyState, ErrorState, errorSummary, QueryView } from '../../components/States';
import { Table } from '../../components/Table';
import { TabPanel, Tabs } from '../../components/Tabs';
import { useToast } from '../../components/Toast';
import { cx } from '../../lib/cx';
import { formatNumber, pluralize } from '../../lib/format';
import { routeTo } from '../../lib/routes';

export const METRICS: ReadonlyArray<{ key: string; label: string; help: string }> = [
  {
    key: 'attack_paths',
    label: 'Attack paths',
    help: '(entry point, high/critical asset) pairs that are connected',
  },
  { key: 'critical_paths', label: 'Critical paths', help: 'pairs where a critical asset can be controlled' },
  {
    key: 'reachable_assets',
    label: 'Reachable assets',
    help: 'assets reachable or controllable from any entry point',
  },
  { key: 'entry_points', label: 'Entry points', help: 'external zones, user workstations and users' },
  {
    key: 'exposed_critical_assets',
    label: 'Exposed critical assets',
    help: 'high/critical assets with exposure HIGH or CRITICAL',
  },
];

const LEVELS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const;

/** Fewer paths, assets or entry points is an improvement for every metric. */
export function DeltaValue({ value }: { value: number }) {
  const tone = value < 0 ? 'good' : value > 0 ? 'bad' : 'neutral';
  const text = value === 0 ? 'no change' : value < 0 ? `${Math.abs(value)} fewer` : `${value} more`;
  return (
    <span className={cx('delta', `delta--${tone}`)} title={text}>
      <span className="tabular">{value > 0 ? `+${value}` : value < 0 ? `−${Math.abs(value)}` : '0'}</span>
      <span className="sr-only"> ({text})</span>
    </span>
  );
}

function metric(metrics: ExposureMetrics | undefined, key: string): number {
  const value = metrics?.[key];
  return typeof value === 'number' ? value : 0;
}

// ------------------------------------------------------------------ models

function CreateModelForm({ onCreated }: { onCreated: (name: string) => void }) {
  const create = useCreateGhostModel();
  const snapshots = useSnapshots();
  const [name, setName] = useState('');
  const [base, setBase] = useState('current');
  const [description, setDescription] = useState('');
  return (
    <form
      className="stack"
      aria-label="New Ghost model"
      onSubmit={(event) => {
        event.preventDefault();
        create.mutate(
          { name: name.trim(), base, description: description.trim() },
          {
            onSuccess: (model) => {
              setName('');
              setDescription('');
              onCreated(model.name);
            },
          },
        );
      }}
    >
      <Field label="Name" hint="lowercase letters, digits, “.”, “_” or “-”">
        {(id) => (
          <TextInput id={id} value={name} placeholder="hardened" onChange={(e) => setName(e.target.value)} />
        )}
      </Field>
      <Field label="Base state" hint="Frozen when the model is created; the model never changes it">
        {(id) => (
          <Select
            id={id}
            value={base}
            options={[
              { value: 'current', label: 'Current workspace' },
              ...(snapshots.data?.items ?? []).map((s) => ({ value: s.name, label: `Snapshot ${s.name}` })),
            ]}
            onChange={(e) => setBase(e.target.value)}
          />
        )}
      </Field>
      <Field label="Description (optional)">
        {(id) => <TextInput id={id} value={description} onChange={(e) => setDescription(e.target.value)} />}
      </Field>
      {create.isError ? <ErrorState title="The model was not created" error={create.error} compact /> : null}
      <div>
        <Button
          type="submit"
          variant="primary"
          icon="plus"
          loading={create.isPending}
          disabled={!name.trim()}
        >
          Create model
        </Button>
      </div>
    </form>
  );
}

export function GhostModelList({
  selected,
  onSelect,
}: {
  selected: string | null;
  onSelect: (name: string) => void;
}) {
  const models = useGhostModels();
  return (
    <div className="stack">
      <Panel title="Models" flush>
        <QueryView query={models} feature="Ghost">
          {(data) =>
            data.items.length === 0 ? (
              <div className="panel__pad">
                <EmptyState icon="ghost" title="No models yet">
                  <p>
                    Create one below or with <code>raf ghost create NAME</code>.
                  </p>
                </EmptyState>
              </div>
            ) : (
              <Table<GhostModelSummary>
                caption="Ghost models"
                dense
                rows={data.items}
                rowKey={(model) => model.name}
                selectedKey={selected}
                onRowClick={(model) => onSelect(model.name)}
                rowLabel={(model) => `Open model ${model.name}`}
                columns={[
                  {
                    key: 'name',
                    header: 'Model',
                    render: (m) => (
                      <span className="stack stack--tight">
                        <strong className="break">{m.name}</strong>
                        <span className="small muted break">{m.base_label}</span>
                      </span>
                    ),
                  },
                  { key: 'ops', header: 'Ops', align: 'right', render: (m) => formatNumber(m.ops_count) },
                  {
                    key: 'updated',
                    header: 'Updated',
                    render: (m) => <Time value={m.updated_at} className="small" />,
                  },
                ]}
              />
            )
          }
        </QueryView>
      </Panel>
      <Panel title="New model">
        <CreateModelForm onCreated={onSelect} />
      </Panel>
    </div>
  );
}

// ------------------------------------------------------------------ operations

function OpEffects({ op }: { op: GhostOp }) {
  const effects = op.effects;
  const patched = Object.keys(effects.patched_objects ?? {});
  return (
    <div className="ghost-effects small">
      {effects.removed_relationships.length > 0 ? (
        <p>
          <span className="muted">Removed relationships:</span>{' '}
          <span className="mono break">{effects.removed_relationships.join(', ')}</span>
        </p>
      ) : null}
      {effects.added_relationships.length > 0 ? (
        <ul className="stack stack--tight">
          <li className="muted">Added relationships:</li>
          {effects.added_relationships.map((rel, index) => (
            <li key={index} className="row row--wrap">
              <ObjectChip id={rel.source} showType={false} />
              <span className="mono">{rel.type}</span>
              <ObjectChip id={rel.target} showType={false} />
            </li>
          ))}
        </ul>
      ) : null}
      {effects.added_objects.length > 0 ? (
        <p>
          <span className="muted">Added objects:</span>{' '}
          <span className="break">
            {effects.added_objects.map((object) => `${object.name} (${object.type})`).join(', ')}
          </span>
        </p>
      ) : null}
      {patched.length > 0 ? (
        <p>
          <span className="muted">Metadata replaced on:</span>{' '}
          <span className="mono break">{patched.join(', ')}</span>
        </p>
      ) : null}
    </div>
  );
}

function OpCard({ op, index }: { op: GhostOp; index: number }) {
  return (
    <li className="ghost-op">
      <div className="row row--wrap">
        <span className="ghost-op__index tabular">{index + 1}.</span>
        <span className="tag">{op.op}</span>
        <Mono className="break">{op.arg}</Mono>
        <span className="spacer" />
        <Time value={op.applied_at} className="small muted" />
      </div>
      <p className="ghost-op__summary break">{op.summary}</p>
      {op.explanation.length > 0 ? (
        <ul className="ghost-op__explanation">
          {op.explanation.map((line, i) => (
            <li key={i} className="break">
              {line}
            </li>
          ))}
        </ul>
      ) : null}
      <details>
        <summary className="small">Effects</summary>
        <OpEffects op={op} />
      </details>
    </li>
  );
}

/** The operations log: every what-if change with its summary, explanation and stored effects. */
export function OperationsLog({ ops }: { ops: readonly GhostOp[] }) {
  if (ops.length === 0) {
    return <p className="muted small">No operations yet: the model equals its base state.</p>;
  }
  return (
    <ol className="ghost-ops" aria-label="Operations log">
      {ops.map((op, index) => (
        <OpCard key={`${index}:${op.op}:${op.applied_at}`} op={op} index={index} />
      ))}
    </ol>
  );
}

/** `POST /ghost/models/{name}/ops {op, arg}` with the supported operations of `GET /ghost/operations`. */
export function OperationForm({ model }: { model: string }) {
  const operations = useGhostOperations();
  const apply = useApplyGhostOp();
  const [op, setOp] = useState('');
  const [arg, setArg] = useState('');
  const argId = useId();
  const items = operations.data?.items ?? [];
  const chosen = items.find((item) => item.op === op) ?? items[0];
  const opValue = chosen?.op ?? '';
  return (
    <form
      className="stack"
      aria-label="Apply a what-if operation"
      onSubmit={(event) => {
        event.preventDefault();
        if (!opValue || !arg.trim()) return;
        apply.mutate({ model, op: opValue, arg: arg.trim() }, { onSuccess: () => setArg('') });
      }}
    >
      <QueryView query={operations} feature="Ghost operations" compact>
        {() => (
          <div className="ghost-op-form">
            <Field label="Operation">
              {(id) => (
                <Select
                  id={id}
                  value={opValue}
                  options={items.map((item) => ({ value: item.op, label: item.op }))}
                  onChange={(e) => setOp(e.target.value)}
                />
              )}
            </Field>
            <div className="field grow">
              <label className="field__label" htmlFor={argId}>
                Argument
              </label>
              <TextInput
                id={argId}
                className="mono"
                value={arg}
                placeholder={chosen?.argument ?? ''}
                onChange={(e) => setArg(e.target.value)}
              />
              {chosen ? (
                <p className="field__hint">
                  <span className="mono">{chosen.argument}</span> — {chosen.effect}
                </p>
              ) : null}
            </div>
            <div className="filters__actions">
              <Button
                type="submit"
                variant="primary"
                icon="play"
                loading={apply.isPending}
                disabled={!arg.trim()}
              >
                Apply
              </Button>
            </div>
          </div>
        )}
      </QueryView>
      {apply.isError ? (
        <ErrorState title="The operation was not applied" error={apply.error} compact />
      ) : null}
      {apply.data ? (
        <Callout tone="info" title="Applied">
          <ul className="stack stack--tight">
            {apply.data.applied.map((applied, index) => (
              <li key={index}>
                <span className="tag">{applied.op}</span> <span className="break">{applied.summary}</span>
              </li>
            ))}
          </ul>
        </Callout>
      ) : null}
      <p className="small muted">
        Operations change only the model (an in-memory copy); nothing touches a real environment. References
        are resolved against the model (names, aliases, typed IDs).
      </p>
    </form>
  );
}

// ------------------------------------------------------------------ simulate

function LevelCounts({ levels }: { levels: Record<string, number> }) {
  return (
    <ul className="importance-counts" aria-label="Assets by exposure level">
      {LEVELS.map((level) => (
        <li key={level}>
          <RiskLevelBadge level={level} />
          <span className="tabular">{formatNumber(levels[level] ?? 0)}</span>
        </li>
      ))}
    </ul>
  );
}

function UserControl({ control }: { control: Record<string, number> }) {
  const entries = Object.entries(control).sort((a, b) => b[1] - a[1]);
  if (entries.length === 0) return <p className="small muted">No users.</p>;
  return (
    <ul className="stack stack--tight" aria-label="High and critical assets each user can control">
      {entries.map(([user, count]) => (
        <li key={user} className="row row--between">
          <ObjectChip id={user} />
          <span className="tabular small">{pluralize(count, 'asset')}</span>
        </li>
      ))}
    </ul>
  );
}

function AssetRow({ item }: { item: AssetExposure }) {
  return (
    <details className="ghost-asset">
      <summary>
        <span className="row row--wrap">
          <RiskLevelBadge level={item.level} />
          <span className="break">{item.object.name}</span>
          <span className="small muted">{item.object.type}</span>
          <span className="spacer" />
          <span className="ghost-asset__score">
            <Meter value={Math.min(1, item.score / 100)} label={`Exposure score ${item.score}`} />
            <span className="tabular small">{formatNumber(item.score)}</span>
          </span>
        </span>
      </summary>
      <div className="stack stack--tight ghost-asset__body">
        <ObjectChip id={item.object.id} name={item.object.name} type={item.object.type} />
        <FactorList factors={item.factors} total={item.score} />
      </div>
    </details>
  );
}

export function SimulateView({ model }: { model: string }) {
  const query = useGhostSimulation(model, 20);
  return (
    <QueryView query={query} feature="Ghost simulation" loadingLabel="Simulating exposure…">
      {(data) => (
        <div className="stack">
          <div className="stats" aria-label="Simulated metrics">
            {METRICS.map((m) => (
              <StatTile
                key={m.key}
                label={m.label}
                value={formatNumber(metric(data.summary.metrics, m.key))}
              />
            ))}
          </div>
          <div className="split">
            <Panel title="Assets by level">
              <LevelCounts levels={data.summary.levels} />
            </Panel>
            <Panel title="User control (high/critical assets)">
              <UserControl control={data.summary.user_control} />
            </Panel>
          </div>
          <Panel title={`Most exposed assets in ${data.summary.label}`}>
            {data.items.length === 0 ? (
              <p className="muted small">No assessed assets.</p>
            ) : (
              <div className="stack stack--tight">
                {data.items.map((item) => (
                  <AssetRow key={item.object.id} item={item} />
                ))}
              </div>
            )}
          </Panel>
          <p className="small muted">
            Exposure is recomputed on the model (raf-risk/1.0). Object chips open the inspector with the
            workspace’s current data, not the model’s.
          </p>
        </div>
      )}
    </QueryView>
  );
}

// ------------------------------------------------------------------ compare

function AssetChanges({ assets }: { assets: readonly GhostAssetChange[] }) {
  return (
    <Table<GhostAssetChange>
      caption="Assets whose exposure changed"
      dense
      rows={assets}
      rowKey={(asset) => asset.id}
      empty={<span className="muted">No asset changed its exposure.</span>}
      columns={[
        { key: 'asset', header: 'Asset', render: (a) => <ObjectChip id={a.id} name={a.name} /> },
        {
          key: 'before',
          header: 'Before',
          render: (a) =>
            a.before ? (
              <span className="row">
                <RiskLevelBadge level={a.before.level} />
                <span className="tabular small">{a.before.score}</span>
              </span>
            ) : (
              <span className="muted">absent</span>
            ),
        },
        {
          key: 'after',
          header: 'After',
          render: (a) =>
            a.after ? (
              <span className="row">
                <RiskLevelBadge level={a.after.level} />
                <span className="tabular small">{a.after.score}</span>
              </span>
            ) : (
              <span className="muted">absent</span>
            ),
        },
        {
          key: 'delta',
          header: 'Score change',
          align: 'right',
          render: (a) => <DeltaValue value={(a.after?.score ?? 0) - (a.before?.score ?? 0)} />,
        },
      ]}
    />
  );
}

function IdChips({ ids }: { ids: readonly string[] }) {
  if (ids.length === 0) return <span className="muted">—</span>;
  return (
    <span className="row row--wrap">
      {ids.slice(0, 8).map((id) => (
        <ObjectChip key={id} id={id} showType={false} />
      ))}
      {ids.length > 8 ? <span className="small muted">+{ids.length - 8}</span> : null}
    </span>
  );
}

function UserChanges({ users }: { users: readonly GhostUserChange[] }) {
  return (
    <Table<GhostUserChange>
      caption="Users whose control changed"
      dense
      rows={users}
      rowKey={(user) => user.id}
      empty={<span className="muted">No user gained or lost control.</span>}
      columns={[
        { key: 'user', header: 'User', render: (u) => <ObjectChip id={u.id} name={u.name} /> },
        {
          key: 'count',
          header: 'High/critical assets',
          render: (u) => (
            <span className="tabular">
              {u.before} → {u.after}
            </span>
          ),
        },
        { key: 'lost', header: 'Lost', render: (u) => <IdChips ids={u.lost} /> },
        { key: 'gained', header: 'Gained', render: (u) => <IdChips ids={u.gained} /> },
      ]}
    />
  );
}

/** `GET /ghost/compare?a=&b=` — `current`, a model or a snapshot on each side. */
export function CompareView({ model }: { model: string }) {
  const models = useGhostModels();
  const snapshots = useSnapshots();
  const [a, setA] = useState('current');
  const [b, setB] = useState(model);
  const [applied, setApplied] = useState<{ a: string; b: string }>({ a: 'current', b: model });
  const query = useGhostCompare(applied.a, applied.b);
  const options = [
    { value: 'current', label: 'current (live workspace)' },
    ...(models.data?.items ?? []).map((m) => ({ value: m.name, label: `model ${m.name}` })),
    ...(snapshots.data?.items ?? []).map((s) => ({ value: s.name, label: `snapshot ${s.name}` })),
  ];
  return (
    <div className="stack">
      <form
        className="filters filters--inline"
        aria-label="Compare states"
        onSubmit={(event) => {
          event.preventDefault();
          setApplied({ a, b });
        }}
      >
        <Field label="Baseline (A)">
          {(id) => <Select id={id} value={a} options={options} onChange={(e) => setA(e.target.value)} />}
        </Field>
        <Field label="Experiment (B)">
          {(id) => <Select id={id} value={b} options={options} onChange={(e) => setB(e.target.value)} />}
        </Field>
        <div className="filters__actions">
          <Button type="submit" variant="primary" icon="diff" disabled={a === b}>
            Compare
          </Button>
        </div>
      </form>
      <QueryView query={query} feature="Ghost compare" loadingLabel="Comparing exposure…">
        {(data) => (
          <div className="stack">
            <Panel title="Metrics" flush>
              <Table<(typeof METRICS)[number]>
                caption="Exposure metrics, baseline and experiment"
                rows={METRICS}
                rowKey={(m) => m.key}
                columns={[
                  {
                    key: 'metric',
                    header: 'Metric',
                    render: (m) => (
                      <span className="stack stack--tight">
                        <span>{m.label}</span>
                        <span className="small muted">{m.help}</span>
                      </span>
                    ),
                  },
                  {
                    key: 'a',
                    header: <span className="break">A · {data.a.label}</span>,
                    align: 'right',
                    render: (m) => formatNumber(metric(data.a.metrics, m.key)),
                  },
                  {
                    key: 'b',
                    header: <span className="break">B · {data.b.label}</span>,
                    align: 'right',
                    render: (m) => formatNumber(metric(data.b.metrics, m.key)),
                  },
                  {
                    key: 'delta',
                    header: 'Change',
                    align: 'right',
                    render: (m) => <DeltaValue value={metric(data.delta, m.key)} />,
                  },
                ]}
              />
            </Panel>
            <div className="split">
              <Panel title={`Levels · A · ${data.a.label}`}>
                <LevelCounts levels={data.a.levels} />
              </Panel>
              <Panel title={`Levels · B · ${data.b.label}`}>
                <LevelCounts levels={data.b.levels} />
              </Panel>
            </div>
            <Panel title={`Assets (${formatNumber(data.assets.length)})`} flush>
              <AssetChanges assets={data.assets} />
            </Panel>
            <Panel title={`Users (${formatNumber(data.users.length)})`} flush>
              <UserChanges users={data.users} />
            </Panel>
            {data.relationships_removed !== undefined || data.relationships_added !== undefined ? (
              <p className="small muted">
                Relationships: {formatNumber(data.relationships_removed ?? 0)} removed,{' '}
                {formatNumber(data.relationships_added ?? 0)} added (B compared with A).
              </p>
            ) : null}
          </div>
        )}
      </QueryView>
    </div>
  );
}

// ------------------------------------------------------------------ model actions

function CloneDialog({
  model,
  onClose,
  onCloned,
}: {
  model: string;
  onClose: () => void;
  onCloned: (n: string) => void;
}) {
  const clone = useCloneGhostModel();
  const [name, setName] = useState(`${model}-copy`);
  const formId = useId();
  return (
    <Modal
      title={`Clone model “${model}”`}
      onClose={onClose}
      size="sm"
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            type="submit"
            form={formId}
            variant="primary"
            loading={clone.isPending}
            disabled={!name.trim()}
          >
            Clone
          </Button>
        </>
      }
    >
      <form
        id={formId}
        className="stack"
        onSubmit={(event) => {
          event.preventDefault();
          clone.mutate({ source: model, name: name.trim() }, { onSuccess: (copy) => onCloned(copy.name) });
        }}
      >
        <Field label="Name of the copy">
          {(id) => (
            <TextInput id={id} value={name} data-autofocus onChange={(e) => setName(e.target.value)} />
          )}
        </Field>
        <p className="small muted">The copy keeps the base state and every operation; it can then diverge.</p>
        {clone.isError ? <ErrorState error={clone.error} compact /> : null}
      </form>
    </Modal>
  );
}

function SnapshotDialog({ model, onClose }: { model: GhostModel; onClose: () => void }) {
  const create = useCreateSnapshot();
  const navigate = useNavigate();
  const [name, setName] = useState(`${model.name}-after`);
  const [description, setDescription] = useState(`Ghost model ${model.name}`);
  const formId = useId();
  return (
    <Modal
      title="Save the model as a snapshot"
      onClose={onClose}
      size="sm"
      footer={
        <>
          <Button onClick={onClose}>{create.isSuccess ? 'Close' : 'Cancel'}</Button>
          {create.isSuccess ? (
            <Button
              variant="primary"
              icon="diff"
              onClick={() => void navigate(routeTo.diff(model.base_snapshot, create.data.name))}
            >
              Diff against the base
            </Button>
          ) : (
            <Button
              type="submit"
              form={formId}
              variant="primary"
              loading={create.isPending}
              disabled={!name.trim()}
            >
              Save snapshot
            </Button>
          )}
        </>
      }
    >
      <form
        id={formId}
        className="stack"
        onSubmit={(event) => {
          event.preventDefault();
          create.mutate({
            name: name.trim(),
            source: `ghost:${model.name}`,
            description: description.trim(),
          });
        }}
      >
        <p className="small">
          A snapshot of the model (source <code>ghost:{model.name}</code>) makes it comparable with real
          states in Diff. Findings are carried over from the base snapshot; analyzers are not re-run inside
          models.
        </p>
        <Field label="Snapshot name">
          {(id) => (
            <TextInput id={id} value={name} data-autofocus onChange={(e) => setName(e.target.value)} />
          )}
        </Field>
        <Field label="Description">
          {(id) => (
            <TextArea id={id} rows={2} value={description} onChange={(e) => setDescription(e.target.value)} />
          )}
        </Field>
        {create.isError ? <ErrorState error={create.error} compact /> : null}
        {create.isSuccess ? (
          <Callout tone="info" title={`Snapshot ${create.data.name} saved`}>
            Compare it with the model’s base snapshot <code>{model.base_snapshot}</code> or any other state in
            Diff.
          </Callout>
        ) : null}
      </form>
    </Modal>
  );
}

type ModelTab = 'ops' | 'simulate' | 'compare';
type Dialog = 'clone' | 'undo' | 'delete' | 'snapshot' | null;

export function GhostModelView({
  name,
  tab,
  onTab,
  onSelect,
}: {
  name: string;
  tab: ModelTab;
  onTab: (tab: ModelTab) => void;
  onSelect: (name: string | null) => void;
}) {
  const query = useGhostModel(name);
  const undo = useUndoGhostOp();
  const remove = useDeleteGhostModel();
  const { notify } = useToast();
  const [dialog, setDialog] = useState<Dialog>(null);
  return (
    <QueryView query={query} feature="Ghost model" loadingLabel="Loading model…">
      {(model) => {
        const last = model.ops[model.ops.length - 1];
        return (
          <Panel
            title={
              <span className="row row--wrap">
                <span className="break">{model.name}</span>
                <span className="small muted">{pluralize(model.ops.length, 'operation')}</span>
              </span>
            }
            actions={
              <span className="row row--wrap">
                <Button size="sm" icon="copy" onClick={() => setDialog('clone')}>
                  Clone
                </Button>
                <Button size="sm" icon="reset" disabled={!last} onClick={() => setDialog('undo')}>
                  Undo
                </Button>
                <Button size="sm" icon="database" onClick={() => setDialog('snapshot')}>
                  Save as snapshot
                </Button>
                <Button size="sm" variant="danger" icon="trash" onClick={() => setDialog('delete')}>
                  Delete
                </Button>
              </span>
            }
          >
            <div className="stack">
              <KeyValueList
                entries={[
                  ['Base', <span className="break">{model.base_label}</span>],
                  ['Base snapshot', <Mono>{model.base_snapshot}</Mono>],
                  ['Cloned from', model.parent ? <Mono>{model.parent}</Mono> : '—'],
                  [
                    'Description',
                    model.description ? <span className="break">{model.description}</span> : '—',
                  ],
                  ['Created', <Time value={model.created_at} />],
                  ['Updated', <Time value={model.updated_at} />],
                ]}
              />
              <Tabs<ModelTab>
                label="Model views"
                idPrefix="ghost-model"
                value={tab}
                onChange={onTab}
                items={[
                  { key: 'ops', label: 'Operations', badge: formatNumber(model.ops.length) },
                  { key: 'simulate', label: 'Simulate' },
                  { key: 'compare', label: 'Compare' },
                ]}
              />
              <TabPanel idPrefix="ghost-model" activeKey={tab}>
                {tab === 'ops' ? (
                  <div className="stack">
                    <OperationForm model={model.name} />
                    <h4>Operations log</h4>
                    <OperationsLog ops={model.ops} />
                  </div>
                ) : null}
                {tab === 'simulate' ? <SimulateView model={model.name} /> : null}
                {tab === 'compare' ? <CompareView key={model.name} model={model.name} /> : null}
              </TabPanel>
            </div>
            {dialog === 'clone' ? (
              <CloneDialog
                model={model.name}
                onClose={() => setDialog(null)}
                onCloned={(copy) => {
                  setDialog(null);
                  notify({ tone: 'good', title: `Model ${copy} created from ${model.name}` });
                  onSelect(copy);
                }}
              />
            ) : null}
            {dialog === 'snapshot' ? <SnapshotDialog model={model} onClose={() => setDialog(null)} /> : null}
            {dialog === 'undo' && last ? (
              <ConfirmDialog
                title="Undo the last operation?"
                confirmLabel="Undo"
                busy={undo.isPending}
                onCancel={() => setDialog(null)}
                onConfirm={() =>
                  undo.mutateAsync(model.name).then(
                    (result) => {
                      notify({ tone: 'good', title: `Removed ${result.removed.op} ${result.removed.arg}` });
                      setDialog(null);
                    },
                    (error: unknown) => {
                      notify({ tone: 'bad', title: 'Undo failed', description: errorSummary(error) });
                      setDialog(null);
                    },
                  )
                }
              >
                <p>
                  Removes <span className="tag">{last.op}</span>{' '}
                  <span className="mono break">{last.arg}</span> from the model.
                </p>
              </ConfirmDialog>
            ) : null}
            {dialog === 'delete' ? (
              <ConfirmDialog
                title={`Delete model “${model.name}”?`}
                danger
                confirmLabel="Delete"
                requireText={model.name}
                busy={remove.isPending}
                onCancel={() => setDialog(null)}
                onConfirm={() =>
                  remove.mutateAsync(model.name).then(
                    (result) => {
                      notify({
                        tone: 'good',
                        title: `Model ${result.model} deleted`,
                        description: result.base_snapshot_removed
                          ? `Its base snapshot ${result.base_snapshot_removed} was removed too.`
                          : undefined,
                      });
                      setDialog(null);
                      onSelect(null);
                    },
                    (error: unknown) => {
                      notify({ tone: 'bad', title: 'Delete failed', description: errorSummary(error) });
                      setDialog(null);
                    },
                  )
                }
              >
                <p>
                  The model and its operations log are removed; its base snapshot too when no other model uses
                  it. The workspace itself is never changed by Ghost.
                </p>
              </ConfirmDialog>
            ) : null}
          </Panel>
        );
      }}
    </QueryView>
  );
}
