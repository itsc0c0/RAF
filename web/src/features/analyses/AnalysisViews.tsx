import { useId, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAnalyses, useAnalysis, useConfig, useProducts } from '../../api/hooks';
import type { AnalysisRecord, AnalysisStep } from '../../api/types';
import { useAnalyze } from '../../app/analyze';
import { Badge } from '../../components/Badge';
import { Button } from '../../components/Button';
import { CommandList, CopyButton, KeyValueList, Mono, StatTile, Time } from '../../components/Data';
import { Checkbox, Field, TextInput } from '../../components/Form';
import { Icon, type IconName } from '../../components/Icon';
import { ObjectChip } from '../../components/ObjectChip';
import { Callout, Panel } from '../../components/Panel';
import { EmptyState, ErrorState, QueryView } from '../../components/States';
import { Table } from '../../components/Table';
import { cx } from '../../lib/cx';
import {
  displayValue,
  formatBytes,
  formatDuration,
  formatNumber,
  humanize,
  shortHash,
} from '../../lib/format';
import { routeTo } from '../../lib/routes';
import {
  analysisIncidents,
  analysisJobs,
  detectedLabel,
  displaySuggestions,
  isObjectId,
  STATUS_TONES,
  stepCounts,
} from './analysisModel';

const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/;
const PREVIEW = 12;

export function AnalysisStatusBadge({ status }: { status: string }) {
  return (
    <Badge tone={STATUS_TONES[status] ?? 'neutral'} title={`Analysis status: ${status}`}>
      {status.toUpperCase()}
    </Badge>
  );
}

/** A statistic value as text, chips (object IDs) or nested counts; never interpreted as markup. */
function StatValue({ value }: { value: unknown }) {
  if (typeof value === 'number') return <span className="tabular">{formatNumber(value)}</span>;
  if (typeof value === 'boolean') return <span>{value ? 'yes' : 'no'}</span>;
  if (typeof value === 'string') {
    if (ISO_RE.test(value)) return <Time value={value} />;
    return isObjectId(value) ? <ObjectChip id={value} /> : <span className="break">{value}</span>;
  }
  if (Array.isArray(value)) {
    if (value.length === 0) return <span className="muted">none</span>;
    const strings = value.filter((item): item is string => typeof item === 'string');
    if (strings.length === value.length && strings.every(isObjectId)) {
      return (
        <span className="row row--wrap">
          {strings.slice(0, PREVIEW).map((id) => (
            <ObjectChip key={id} id={id} showType={false} />
          ))}
          {strings.length > PREVIEW ? (
            <span className="small muted">+{formatNumber(strings.length - PREVIEW)} more</span>
          ) : null}
        </span>
      );
    }
    return <span className="mono small break">{value.map((item) => displayValue(item)).join(', ')}</span>;
  }
  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length === 0) return <span className="muted">none</span>;
    return (
      <span className="row row--wrap small">
        {entries.map(([key, item]) => (
          <span key={key} className="tag">
            {key} {displayValue(item)}
          </span>
        ))}
      </span>
    );
  }
  return <span className="muted">{displayValue(value)}</span>;
}

/** Generic statistics of a step or of the analysis (keys are product-defined). */
export function StatsList({ stats, exclude = [] }: { stats: Record<string, unknown>; exclude?: string[] }) {
  const keys = Object.keys(stats).filter((key) => !exclude.includes(key));
  if (keys.length === 0) return <p className="small muted">No statistics.</p>;
  return (
    <KeyValueList
      className="kv--compact"
      entries={keys.map((key) => [humanize(key), <StatValue value={stats[key]} />, key] as const)}
    />
  );
}

const STEP_ICONS: Record<string, IconName> = { ok: 'check', skipped: 'minus', failed: 'warning' };

function StepItem({ step, index }: { step: AnalysisStep; index: number }) {
  const statsKeys = Object.keys(step.stats ?? {});
  return (
    <li className={cx('step', `step--${step.status}`)}>
      <span className="step__status">
        <Icon name={STEP_ICONS[step.status] ?? 'info'} size={14} />
        <span className="step__status-label">{step.status}</span>
      </span>
      <div className="step__body">
        <div className="row row--wrap">
          <span className="step__index tabular muted">{index + 1}.</span>
          <strong className="break">{step.name}</strong>
          {step.product ? (
            <span className="tag" title="Product that ran this step">
              {step.product}
            </span>
          ) : null}
          <span className="spacer" />
          <span className="small muted tabular" title="Duration">
            {formatDuration(step.duration_ms)}
          </span>
        </div>
        {step.detail ? <p className="step__detail break">{step.detail}</p> : null}
        {statsKeys.length > 0 ? (
          <details className="step__stats">
            <summary>Statistics ({statsKeys.length})</summary>
            <StatsList stats={step.stats} />
          </details>
        ) : null}
      </div>
    </li>
  );
}

/** Every executed step, in order, with its status (ok / skipped / failed), detail, duration and stats. */
export function StepList({ steps }: { steps: readonly AnalysisStep[] }) {
  if (steps.length === 0) return <p className="muted small">No steps were recorded.</p>;
  return (
    <ol className="steps" aria-label="Analysis steps">
      {steps.map((step, index) => (
        <StepItem key={`${index}:${step.name}`} step={step} index={index} />
      ))}
    </ol>
  );
}

interface ExplorePivot {
  key: string;
  product: string;
  label: string;
  icon: IconName;
  route: string;
}

function explorePivots(record: AnalysisRecord): ExplorePivot[] {
  const pivots: ExplorePivot[] = [
    { key: 'lens', product: 'lens', label: 'Lens', icon: 'investigate', route: routeTo.lens(record.id) },
    { key: 'graph', product: 'graph', label: 'Graph', icon: 'graph', route: routeTo.graph(record.id) },
    {
      key: 'timeline',
      product: 'timeline',
      label: 'Timeline',
      icon: 'timeline',
      route: routeTo.timelineScope(record.id),
    },
  ];
  for (const incident of analysisIncidents(record)) {
    pivots.push({
      key: `replay:${incident}`,
      product: 'replay',
      label: `Replay ${incident.replace(/^incident:/, '').toUpperCase()}`,
      icon: 'replay',
      route: routeTo.replay(incident),
    });
  }
  return pivots;
}

/** Lens / Graph / Timeline scoped to the analysis (job provenance), Replay for linked incidents. */
export function ExplorePivots({ record }: { record: AnalysisRecord }) {
  const navigate = useNavigate();
  const products = useProducts();
  const available = products.data
    ? new Set(products.data.items.filter((p) => p.available && p.enabled).map((p) => p.name))
    : null;
  return (
    <nav className="pivots" aria-label={`Explore ${record.id}`}>
      {explorePivots(record).map((pivot) => {
        // Lens falls back to the timeline inside Investigate, so it only needs one of them.
        const missing =
          available !== null &&
          !available.has(pivot.product) &&
          !(pivot.product === 'lens' && available.has('timeline'));
        return (
          <button
            key={pivot.key}
            type="button"
            className="pivot"
            disabled={missing}
            title={
              missing ? `${pivot.label} is not available in this installation yet` : `Open ${pivot.label}`
            }
            onClick={() => void navigate(pivot.route)}
          >
            <Icon name={pivot.icon} size={14} />
            <span>{pivot.label}</span>
          </button>
        );
      })}
    </nav>
  );
}

const TOP_STATS: Array<{ key: string; label: string }> = [
  { key: 'events', label: 'Events' },
  { key: 'objects', label: 'Objects' },
  { key: 'relationships', label: 'Relationships' },
  { key: 'findings', label: 'Findings' },
];

/** The full record: detected type, steps, statistics, explore pivots, suggestions, jobs. */
export function AnalysisBody({ record }: { record: AnalysisRecord }) {
  const label = detectedLabel(record);
  const counts = stepCounts(record.steps);
  const { commands, redacted } = displaySuggestions(record);
  const jobs = analysisJobs(record);
  const incidents = analysisIncidents(record);
  return (
    <div className="stack">
      <div className="row row--wrap">
        <AnalysisStatusBadge status={record.status} />
        <span className="tag" title="Detected input type">
          {record.detected_type}
        </span>
        {label ? <span className="small">{label}</span> : null}
        <span className="small muted">
          {formatNumber(counts.ok)} ok · {formatNumber(counts.skipped)} skipped ·{' '}
          {formatNumber(counts.failed)} failed
        </span>
      </div>
      {record.status === 'failed' ? (
        <Callout tone="bad" title="The analysis failed">
          The first, essential step failed: nothing was imported. The failed step below says why.
        </Callout>
      ) : record.status === 'partial' ? (
        <Callout tone="warn" title="Partially completed">
          A later step failed; the data imported before it stays in the workspace.
        </Callout>
      ) : null}
      <KeyValueList
        entries={[
          ['Input', <span className="break">{record.input}</span>],
          [
            'SHA-256',
            <span className="row">
              <Mono title={record.input_sha256}>{shortHash(record.input_sha256, 24)}</Mono>
              <CopyButton value={record.input_sha256} label="Copy SHA-256" />
            </span>,
          ],
          ['Detected', <span>{[record.detected_type, label].filter(Boolean).join(' · ')}</span>],
          ...(record.detection && record.detection.length > 0
            ? ([['Detection', <span className="break">{record.detection.join('; ')}</span>]] as const)
            : []),
          ['Created', <Time value={record.created_at} />],
          ...(record.duration_ms !== null && record.duration_ms !== undefined
            ? ([['Duration', formatDuration(record.duration_ms)]] as const)
            : []),
          ['Jobs', jobs.length > 0 ? <Mono>{jobs.join(', ')}</Mono> : '—'],
          [
            'Incidents',
            incidents.length > 0 ? (
              <span className="row row--wrap">
                {incidents.map((id) => (
                  <ObjectChip key={id} id={id} />
                ))}
              </span>
            ) : (
              '—'
            ),
          ],
        ]}
      />
      <section className="stack stack--tight" aria-label="Explore">
        <h4>Explore</h4>
        <ExplorePivots record={record} />
        <p className="small muted">
          Lens, Graph and Timeline are scoped to exactly the data of {record.id} (through job provenance).
        </p>
      </section>
      <div className="stats" aria-label="Analysis statistics">
        {TOP_STATS.map((tile) => (
          <StatTile
            key={tile.key}
            label={tile.label}
            value={
              typeof record.stats[tile.key] === 'number'
                ? formatNumber(record.stats[tile.key] as number)
                : '—'
            }
          />
        ))}
      </div>
      <section className="stack stack--tight">
        <h4>Steps</h4>
        <StepList steps={record.steps} />
      </section>
      <section className="stack stack--tight">
        <h4>Statistics</h4>
        <StatsList
          stats={record.stats}
          exclude={['detected_label', 'input_name', 'job_ids', 'incidents', ...TOP_STATS.map((t) => t.key)]}
        />
      </section>
      {commands.length > 0 ? (
        <section className="stack stack--tight">
          <h4>Suggested next commands</h4>
          <CommandList commands={commands} label="Suggested commands" />
          {redacted ? (
            <p className="small muted">
              Server file paths in suggestions are replaced by the uploaded file’s name.
            </p>
          ) : null}
        </section>
      ) : null}
    </div>
  );
}

export function AnalysisDetail({ id }: { id: string }) {
  const query = useAnalysis(id);
  return (
    <Panel title={<span className="mono">{id}</span>} id="analysis-detail">
      <QueryView query={query} feature="Analysis" loadingLabel="Loading analysis…">
        {(record) => <AnalysisBody record={record} />}
      </QueryView>
    </Panel>
  );
}

export function AnalysisList({
  selected,
  onOpen,
}: {
  selected: string | null;
  onOpen: (id: string) => void;
}) {
  const query = useAnalyses(100);
  return (
    <QueryView query={query} feature="Analyses">
      {(data) =>
        data.items.length === 0 ? (
          <div className="panel__pad">
            <EmptyState icon="analyses" title="No analyses yet">
              <p>
                Upload a file above, or run <code>raf analyze &lt;file&gt;</code>.
              </p>
            </EmptyState>
          </div>
        ) : (
          <>
            <Table<AnalysisRecord>
              caption="Analyses"
              dense
              rows={data.items}
              rowKey={(record) => record.id}
              selectedKey={selected}
              onRowClick={(record) => onOpen(record.id)}
              rowLabel={(record) => `Open ${record.id}`}
              columns={[
                {
                  key: 'id',
                  header: 'Analysis',
                  render: (r) => (
                    <span className="stack stack--tight">
                      <Mono className="analysis-list__id">{r.id}</Mono>
                      <Time value={r.created_at} className="small muted" />
                    </span>
                  ),
                },
                {
                  key: 'input',
                  header: 'Input',
                  render: (r) => (
                    <span className="stack stack--tight">
                      <span className="break">{r.input}</span>
                      <span className="small muted">
                        {[r.detected_type, detectedLabel(r)].filter(Boolean).join(' · ')}
                      </span>
                    </span>
                  ),
                },
                {
                  key: 'status',
                  header: 'Result',
                  render: (r) => {
                    const counts = stepCounts(r.steps);
                    return (
                      <span className="stack stack--tight">
                        <AnalysisStatusBadge status={r.status} />
                        <span
                          className="small muted tabular"
                          title={`${counts.ok} ok, ${counts.skipped} skipped, ${counts.failed} failed`}
                        >
                          {counts.ok}/{counts.skipped}/{counts.failed} steps
                        </span>
                      </span>
                    );
                  },
                },
              ]}
            />
            {data.total > data.items.length ? (
              <p className="small muted panel__pad">
                Showing the {formatNumber(data.items.length)} most recent of {formatNumber(data.total)}{' '}
                analyses.
              </p>
            ) : null}
          </>
        )
      }
    </QueryView>
  );
}

/** Upload form (`POST /analyze`): the shell's analyze helper uploads and opens the result. */
export function AnalyzeForm() {
  const { analyze, isUploading } = useAnalyze();
  const config = useConfig();
  const [file, setFile] = useState<File | null>(null);
  const [incident, setIncident] = useState('');
  const [correlate, setCorrelate] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const [inputKey, setInputKey] = useState(0);
  const fileId = useId();
  const limit = config.data?.items.find((item) => item.key === 'api.max_upload_mb')?.value;
  return (
    <form
      className="stack"
      aria-label="Analyze a file"
      onSubmit={(event) => {
        event.preventDefault();
        if (!file) return;
        setError(null);
        analyze({ file, incident, correlate }).then(
          () => {
            setFile(null);
            setIncident('');
            setInputKey((key) => key + 1);
          },
          (reason: unknown) => setError(reason),
        );
      }}
    >
      <div className="field">
        <label className="field__label" htmlFor={fileId}>
          File
        </label>
        <input
          key={inputKey}
          id={fileId}
          type="file"
          className="input input--file"
          onChange={(event) => setFile(event.target.files?.[0] ?? null)}
        />
        <p className="field__hint">
          Logs (JSON, JSONL, CSV, syslog…), packet captures, SBOMs, policy documents or R$F bundles.
          {typeof limit === 'number' ? ` At most ${formatNumber(limit)} MB (api.max_upload_mb).` : ''} The
          server only ever receives the upload, never a path.
        </p>
        {file ? (
          <p className="small muted">
            {file.name} · {formatBytes(file.size)}
          </p>
        ) : null}
      </div>
      <Field label="Incident (optional)" hint="Link the imported events to this incident name">
        {(id) => (
          <TextInput
            id={id}
            value={incident}
            placeholder="INC-002"
            onChange={(e) => setIncident(e.target.value)}
          />
        )}
      </Field>
      <Checkbox
        label="Correlate (re-run the workspace-wide IAM and exposure analyses)"
        checked={correlate}
        onChange={setCorrelate}
      />
      {error ? <ErrorState title="The analysis did not run" error={error} compact /> : null}
      <div>
        <Button type="submit" variant="primary" icon="upload" loading={isUploading} disabled={!file}>
          Analyze
        </Button>
      </div>
    </form>
  );
}
