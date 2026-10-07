import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { isApiError } from '../api/client';
import { useCreateSnapshot, useIncidents, useJobs, useSnapshots, useStatus } from '../api/hooks';
import type { Incident, Job, Snapshot } from '../api/types';
import { useAnalyze } from '../app/analyze';
import { useOracle, usePalette } from '../app/shellState';
import { JobStatusBadge, SeverityBadge } from '../components/Badge';
import { Button } from '../components/Button';
import { Meter, Mono, StatTile, Time } from '../components/Data';
import { Field, TextInput } from '../components/Form';
import { PageHeader, Panel } from '../components/Panel';
import { EmptyState, NoDataHint, QueryView } from '../components/States';
import { Table } from '../components/Table';
import { useToast } from '../components/Toast';
import { SeverityBreakdown } from '../features/overview/SeverityBreakdown';
import { formatCompact, formatDuration, formatNumber, formatRelative, shortHash } from '../lib/format';
import { useNow } from '../lib/hooks';
import { routeTo } from '../lib/routes';
import '../styles/overview.css';

const COUNT_TILES: Array<{ key: string; label: string }> = [
  { key: 'objects', label: 'Objects' },
  { key: 'relationships', label: 'Relationships' },
  { key: 'events', label: 'Events' },
  { key: 'incidents', label: 'Incidents' },
  { key: 'findings', label: 'Findings' },
];

function IncidentsPanel() {
  const incidents = useIncidents();
  const navigate = useNavigate();
  return (
    <Panel title="Incidents" flush>
      <QueryView query={incidents} feature="Incidents">
        {(data) =>
          data.items.length === 0 ? (
            <div className="panel__pad">
              <EmptyState title="No incidents">
                <p>Incidents arrive with imported data and can be replayed step by step.</p>
              </EmptyState>
            </div>
          ) : (
            <Table<Incident>
              caption="Incidents"
              rows={data.items}
              rowKey={(incident) => incident.id}
              columns={[
                {
                  key: 'name',
                  header: 'Incident',
                  render: (i) => (
                    <span className="stack stack--tight">
                      <strong>{i.name}</strong>
                      <span className="small break">{i.title}</span>
                    </span>
                  ),
                },
                { key: 'sev', header: 'Severity', render: (i) => <SeverityBadge severity={i.severity} /> },
                { key: 'status', header: 'Status', render: (i) => <span className="tag">{i.status}</span> },
                {
                  key: 'window',
                  header: 'Window (UTC)',
                  render: (i) => (
                    <span className="small">
                      <Time value={i.start} /> → <Time value={i.end} />
                    </span>
                  ),
                },
                {
                  key: 'events',
                  header: 'Events',
                  align: 'right',
                  render: (i) => formatNumber(i.event_count),
                },
                {
                  key: 'pivots',
                  header: 'Open',
                  render: (i) => (
                    <span className="row row--wrap">
                      <Button size="sm" icon="replay" onClick={() => navigate(routeTo.replay(i.id))}>
                        Replay
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        icon="timeline"
                        onClick={() => navigate(routeTo.timeline(i.id))}
                      >
                        Timeline
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        icon="graph"
                        onClick={() => navigate(routeTo.graph(i.id))}
                      >
                        Graph
                      </Button>
                    </span>
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

function JobsPanel() {
  const jobs = useJobs({ limit: 8 }, 10_000);
  const now = useNow(15_000);
  return (
    <Panel title="Recent jobs" flush>
      <QueryView query={jobs} feature="Jobs">
        {(data) => (
          <Table<Job>
            caption="Recent jobs"
            dense
            rows={data.items}
            rowKey={(job) => job.id}
            empty={<span className="muted">No jobs yet.</span>}
            columns={[
              { key: 'status', header: 'Status', render: (j) => <JobStatusBadge status={j.status} /> },
              {
                key: 'title',
                header: 'Job',
                render: (j) => (
                  <span className="stack stack--tight">
                    <span className="break">{j.title}</span>
                    <span className="mono small muted">
                      {j.id} · {j.kind}
                    </span>
                  </span>
                ),
              },
              {
                key: 'progress',
                header: 'Progress',
                width: '120px',
                render: (j) =>
                  j.status === 'RUNNING' ? (
                    <Meter value={j.progress} label={`${j.title} progress`} />
                  ) : (
                    formatDuration(j.duration_ms)
                  ),
              },
              {
                key: 'created',
                header: 'Started',
                render: (j) => (
                  <span className="small" title={j.created_at}>
                    {formatRelative(j.created_at, now)}
                  </span>
                ),
              },
            ]}
          />
        )}
      </QueryView>
    </Panel>
  );
}

function SnapshotsPanel() {
  const snapshots = useSnapshots();
  const create = useCreateSnapshot();
  const { notify } = useToast();
  const [name, setName] = useState('');
  return (
    <Panel title="Snapshots" flush>
      <QueryView query={snapshots} feature="Snapshots">
        {(data) => (
          <Table<Snapshot>
            caption="Snapshots"
            dense
            rows={data.items}
            rowKey={(snapshot) => snapshot.id}
            empty={
              <span className="muted">
                No snapshots. Snapshots freeze the security state for later diffs.
              </span>
            }
            columns={[
              { key: 'name', header: 'Name', render: (s) => <strong className="break">{s.name}</strong> },
              {
                key: 'source',
                header: 'Source',
                render: (s) => <span className="mono small">{s.source}</span>,
              },
              {
                key: 'created',
                header: 'Created',
                render: (s) => <Time value={s.created_at} className="small" />,
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
            ]}
          />
        )}
      </QueryView>
      <form
        className="row panel__pad"
        onSubmit={(event) => {
          event.preventDefault();
          create.mutate(
            { name: name.trim() },
            {
              onSuccess: () => {
                notify({ tone: 'good', title: `Snapshot ${name.trim()} created` });
                setName('');
              },
              onError: (error) =>
                notify({
                  tone: 'bad',
                  title: 'Snapshot failed',
                  description: isApiError(error)
                    ? [error.message, error.hint].filter(Boolean).join(' ')
                    : undefined,
                }),
            },
          );
        }}
      >
        <Field label="New snapshot" inline>
          {(id) => (
            <TextInput
              id={id}
              value={name}
              placeholder="before-remediation"
              onChange={(e) => setName(e.target.value)}
            />
          )}
        </Field>
        <Button type="submit" icon="database" loading={create.isPending} disabled={!name.trim()}>
          Create
        </Button>
      </form>
    </Panel>
  );
}

function QuickActions() {
  const analyze = useAnalyze();
  const oracle = useOracle();
  const palette = usePalette();
  const navigate = useNavigate();
  return (
    <Panel title="Quick actions">
      <div className="quick-actions">
        <Button icon="upload" loading={analyze.isUploading} onClick={analyze.pickFile}>
          Analyze evidence…
        </Button>
        <Button icon="graph" onClick={() => navigate(routeTo.graph())}>
          Open graph
        </Button>
        <Button icon="investigate" onClick={() => navigate('/investigate')}>
          Investigate
        </Button>
        <Button icon="oracle" onClick={() => oracle.open()}>
          Ask Oracle
        </Button>
        <Button icon="command" onClick={palette.open}>
          Command palette
        </Button>
      </div>
    </Panel>
  );
}

export default function OverviewPage() {
  const status = useStatus();
  const navigate = useNavigate();
  return (
    <div className="page">
      <PageHeader
        title="Overview"
        subtitle={
          status.data
            ? `Workspace ${status.data.workspace} · R$F ${status.data.raf_version}`
            : 'Workspace status'
        }
      />
      <QueryView query={status} feature="Status">
        {(data) => {
          const empty = (data.data.objects ?? 0) === 0 && (data.data.events ?? 0) === 0;
          return (
            <div className="stack stack--loose">
              {empty ? (
                <Panel>
                  <NoDataHint />
                </Panel>
              ) : null}
              <div className="stats" aria-label="Workspace counts">
                {COUNT_TILES.map((tile) => (
                  <StatTile
                    key={tile.key}
                    label={tile.label}
                    value={formatCompact(data.data[tile.key] ?? 0)}
                  />
                ))}
                <StatTile
                  label="Products available"
                  value={`${data.products.available}/${data.products.total}`}
                  detail={
                    <button type="button" className="link-btn" onClick={() => navigate('/products')}>
                      registry
                    </button>
                  }
                />
              </div>
              <div className="grid-2">
                <Panel
                  title="Open findings by severity"
                  actions={
                    <Button size="sm" variant="ghost" onClick={() => navigate('/findings')}>
                      Triage
                    </Button>
                  }
                >
                  <SeverityBreakdown counts={data.findings_by_severity} />
                </Panel>
                <QuickActions />
              </div>
              <IncidentsPanel />
              <div className="grid-2">
                <JobsPanel />
                <SnapshotsPanel />
              </div>
            </div>
          );
        }}
      </QueryView>
    </div>
  );
}
