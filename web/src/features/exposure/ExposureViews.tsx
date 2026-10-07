import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useBlast, useExposureDetail, useExposureList, useIamPath } from '../../api/hooks';
import type { BlastHop, ExposureItem, IamPathResponse, Reach } from '../../api/types';
import { ConfidenceBadge, CriticalityTag, RiskLevelBadge } from '../../components/Badge';
import { Button } from '../../components/Button';
import { Chain, hopsToChain } from '../../components/Chain';
import { FactorList, Meter, StatTile } from '../../components/Data';
import { Field, Select, TextInput } from '../../components/Form';
import { ObjectChip, TypeTag } from '../../components/ObjectChip';
import { Panel } from '../../components/Panel';
import { EmptyState, QueryView } from '../../components/States';
import { Table } from '../../components/Table';
import { displayValue, formatConfidence, formatNumber } from '../../lib/format';
import { routeTo } from '../../lib/routes';

const LEVELS = [
  { value: '', label: 'Any level' },
  { value: 'LOW', label: 'LOW and above' },
  { value: 'MEDIUM', label: 'MEDIUM and above' },
  { value: 'HIGH', label: 'HIGH and above' },
  { value: 'CRITICAL', label: 'CRITICAL' },
];

function scoreFraction(score: number): number {
  return Math.max(0, Math.min(1, score / 100));
}

function EntryPoints({ entries }: { entries: readonly unknown[] }) {
  if (entries.length === 0) return <span className="muted">None</span>;
  return (
    <span className="row row--wrap">
      {entries.map((entry, index) => {
        if (typeof entry === 'string') return <ObjectChip key={entry} id={entry} />;
        const id = typeof entry === 'object' && entry !== null && 'id' in entry ? String(entry.id) : null;
        return id ? (
          <ObjectChip key={id} id={id} />
        ) : (
          <span key={index} className="tag">
            {displayValue(entry)}
          </span>
        );
      })}
    </span>
  );
}

export function ExposureBreakdown({ item }: { item: ExposureItem }) {
  const navigate = useNavigate();
  return (
    <div className="stack">
      <div className="row row--wrap">
        <ObjectChip id={item.object.id} name={item.object.name} type={item.object.type} />
        <CriticalityTag value={item.object.criticality} />
        <RiskLevelBadge level={item.level} />
        <span className="tabular">score {formatNumber(item.score)}</span>
      </div>
      <h4>Why this score</h4>
      <FactorList factors={item.factors} total={item.score} />
      <h4>Entry points</h4>
      <EntryPoints entries={item.entry_points ?? []} />
      <h4>Vulnerabilities</h4>
      {(item.vulnerabilities ?? []).length === 0 ? (
        <span className="muted small">None recorded.</span>
      ) : (
        <ul className="row row--wrap">
          {item.vulnerabilities.map((vuln) => (
            <li key={vuln.id} className="row">
              <ObjectChip id={vuln.id} />
              {vuln.cvss !== null && vuln.cvss !== undefined ? (
                <span className="small muted">CVSS {vuln.cvss}</span>
              ) : null}
            </li>
          ))}
        </ul>
      )}
      <div className="row row--wrap">
        <Button size="sm" icon="target" onClick={() => navigate(routeTo.blast(item.object.id))}>
          Blast radius
        </Button>
        <Button size="sm" icon="graph" onClick={() => navigate(routeTo.graph(item.object.id))}>
          Graph
        </Button>
      </div>
    </div>
  );
}

export function ExposureRanking() {
  const [minLevel, setMinLevel] = useState('');
  const [selected, setSelected] = useState<string | null>(null);
  const query = useExposureList(minLevel || null);
  return (
    <QueryView query={query} feature="Exposure ranking">
      {(data) => {
        const items = data.items ?? [];
        const current = items.find((item) => item.object.id === selected) ?? items[0] ?? null;
        return (
          <div className="split split--wide-left">
            <Panel
              title="Ranked assets"
              flush
              actions={
                <Select
                  aria-label="Minimum level"
                  value={minLevel}
                  options={LEVELS}
                  onChange={(e) => setMinLevel(e.target.value)}
                />
              }
            >
              <Table<ExposureItem>
                caption="Assets ranked by exposure"
                rows={items}
                rowKey={(item) => item.object.id}
                selectedKey={current?.object.id ?? null}
                onRowClick={(item) => setSelected(item.object.id)}
                empty={<span className="muted">No exposed assets at this level.</span>}
                columns={[
                  {
                    key: 'rank',
                    header: '#',
                    width: '40px',
                    align: 'right',
                    render: (item) => items.indexOf(item) + 1,
                  },
                  {
                    key: 'asset',
                    header: 'Asset',
                    render: (item) => (
                      <ObjectChip id={item.object.id} name={item.object.name} type={item.object.type} />
                    ),
                  },
                  {
                    key: 'crit',
                    header: 'Criticality',
                    render: (item) => <CriticalityTag value={item.object.criticality} />,
                  },
                  { key: 'level', header: 'Level', render: (item) => <RiskLevelBadge level={item.level} /> },
                  {
                    key: 'score',
                    header: 'Score',
                    width: '140px',
                    render: (item) => (
                      <span className="row">
                        <Meter value={scoreFraction(item.score)} label={`Exposure score ${item.score}`} />
                        <span className="tabular small">{formatNumber(item.score)}</span>
                      </span>
                    ),
                  },
                  {
                    key: 'entry',
                    header: 'Entry pts',
                    align: 'right',
                    render: (item) => formatNumber((item.entry_points ?? []).length),
                  },
                  {
                    key: 'vulns',
                    header: 'Vulns',
                    align: 'right',
                    render: (item) => formatNumber((item.vulnerabilities ?? []).length),
                  },
                ]}
              />
            </Panel>
            <Panel title="Explanation">
              {current ? <ExposureBreakdown item={current} /> : <p className="muted">Select an asset.</p>}
            </Panel>
          </div>
        );
      }}
    </QueryView>
  );
}

export function ExposureDetailView({ reference }: { reference: string }) {
  const query = useExposureDetail(reference);
  return (
    <QueryView query={query} feature="Exposure assessment">
      {(item) => (
        <Panel title={`Exposure of ${item.object?.name ?? reference}`}>
          <ExposureBreakdown item={item} />
        </Panel>
      )}
    </QueryView>
  );
}

function ReachTable({ rows, caption }: { rows: readonly Reach[]; caption: string }) {
  return (
    <Table<Reach>
      caption={caption}
      dense
      rows={rows}
      rowKey={(row) => row.id}
      empty={<span className="muted">None.</span>}
      columns={[
        {
          key: 'asset',
          header: 'Asset',
          render: (r) => <ObjectChip id={r.id} name={r.name} type={r.type} />,
        },
        {
          key: 'mode',
          header: 'Mode',
          render: (r) => (
            <span
              className="tag"
              title="control: can administer; reach: network reachable; trust: via trust relationship"
            >
              {r.mode}
            </span>
          ),
        },
        { key: 'depth', header: 'Hops', align: 'right', render: (r) => r.depth },
        { key: 'conf', header: 'Confidence', render: (r) => <ConfidenceBadge confidence={r.confidence} /> },
        { key: 'crit', header: 'Criticality', render: (r) => <CriticalityTag value={r.criticality} /> },
      ]}
    />
  );
}

export function HopChain({ hops, label }: { hops: readonly BlastHop[]; label: string }) {
  if (hops.length === 0) return <p className="muted small">No path.</p>;
  const names = new Map<string, string>();
  for (const hop of hops) {
    if (hop.source_name) names.set(hop.source, hop.source_name);
    if (hop.target_name) names.set(hop.target, hop.target_name);
  }
  return (
    <Chain
      label={label}
      items={hopsToChain(
        hops,
        (id) => (
          <ObjectChip id={id} name={names.get(id)} />
        ),
        (hop) => (
          <div className="stack stack--tight">
            <div className="row row--wrap">
              <span className="mono small">{hop.relationship_type}</span>
              <ConfidenceBadge confidence={hop.confidence} />
            </div>
            <span className="small">
              <span className="muted">Why traversable: </span>
              {hop.why}
            </span>
          </div>
        ),
      )}
    />
  );
}

function PropagationList({ title, ids }: { title: string; ids: readonly string[] }) {
  return (
    <div className="stack stack--tight">
      <h4>
        {title} <span className="muted tabular">{ids.length}</span>
      </h4>
      {ids.length === 0 ? (
        <span className="muted small">None.</span>
      ) : (
        <div className="row row--wrap">
          {ids.slice(0, 40).map((id) => (
            <ObjectChip key={id} id={id} />
          ))}
          {ids.length > 40 ? <span className="muted small">+{ids.length - 40} more</span> : null}
        </div>
      )}
    </div>
  );
}

export function BlastView({ reference }: { reference: string }) {
  const query = useBlast(reference);
  return (
    <QueryView query={query} feature="Blast radius" loadingLabel="Computing blast radius…">
      {(blast) => (
        <div className="stack">
          <div className="row row--wrap">
            <span className="muted">Blast radius of</span>
            <ObjectChip id={blast.target.id} name={blast.target.name} type={blast.target.type} />
            <RiskLevelBadge level={blast.risk?.level ?? 'INFO'} />
          </div>
          <div className="stats">
            <StatTile label="Reachable assets" value={formatNumber(blast.reachable_assets)} />
            <StatTile label="Critical assets" value={formatNumber(blast.critical_assets)} />
            <StatTile label="Privileged paths" value={formatNumber(blast.privileged_paths)} />
            <StatTile label="Max depth" value={formatNumber(blast.max_depth)} />
          </div>
          <div className="split">
            <Panel title="Primary path">
              <HopChain hops={blast.primary_path ?? []} label="Primary attack path" />
            </Panel>
            <Panel title={`Risk ${blast.risk ? `· score ${formatNumber(blast.risk.score)}` : ''}`}>
              <FactorList factors={blast.risk?.factors ?? []} total={blast.risk?.score} />
            </Panel>
          </div>
          <div className="split">
            <Panel title={`Direct (${formatNumber((blast.direct ?? []).length)})`} flush>
              <ReachTable rows={blast.direct ?? []} caption="Directly reached assets" />
            </Panel>
            <Panel title={`Indirect (${formatNumber((blast.indirect ?? []).length)})`} flush>
              <ReachTable rows={blast.indirect ?? []} caption="Indirectly reached assets" />
            </Panel>
          </div>
          <Panel title="Propagation">
            <div className="grid-3">
              <PropagationList title="Identity" ids={blast.identity_propagation ?? []} />
              <PropagationList title="Network" ids={blast.network_propagation ?? []} />
              <PropagationList title="Trust" ids={blast.trust_propagation ?? []} />
            </div>
          </Panel>
          <p className="small muted">
            Confidence threshold and depth follow the server defaults (<code>raf blast {reference}</code>).
          </p>
        </div>
      )}
    </QueryView>
  );
}

/** Normalizes the partially documented IAM path payload into hop lists. */
export function iamPaths(data: IamPathResponse): BlastHop[][] {
  if (Array.isArray(data.paths)) {
    return data.paths
      .map((path) => (Array.isArray(path.hops) ? path.hops : []))
      .filter((hops) => hops.length > 0);
  }
  if (Array.isArray(data.hops) && data.hops.length > 0) return [data.hops];
  return [];
}

export function IamPathsView({ source }: { source: string }) {
  const [targetInput, setTargetInput] = useState('');
  const [target, setTarget] = useState<string | null>(null);
  const query = useIamPath(source, target);
  return (
    <div className="stack">
      <Panel title="Privilege paths">
        <form
          className="row row--wrap"
          onSubmit={(event) => {
            event.preventDefault();
            setTarget(targetInput.trim() || null);
          }}
        >
          <span className="row">
            <span className="muted">From</span>
            <ObjectChip id={source} />
          </span>
          <Field label="To" inline>
            {(id) => (
              <TextInput
                id={id}
                value={targetInput}
                placeholder="e.g. DB-01, role:prod-admin"
                onChange={(e) => setTargetInput(e.target.value)}
              />
            )}
          </Field>
          <Button type="submit" variant="primary" icon="route" disabled={!targetInput.trim()}>
            Find privilege paths
          </Button>
        </form>
      </Panel>
      {target ? (
        <QueryView query={query} feature="IAM paths">
          {(data) => {
            const paths = iamPaths(data);
            if (paths.length === 0) {
              return (
                <EmptyState title="No privilege path">
                  <p>
                    No path from {source} to {target} was found.
                  </p>
                </EmptyState>
              );
            }
            return (
              <div className="stack">
                {paths.map((hops, index) => (
                  <Panel
                    key={index}
                    title={`Path ${index + 1} · ${hops.length} hop${hops.length === 1 ? '' : 's'} · min confidence ${formatConfidence(Math.min(...hops.map((h) => h.confidence)))}`}
                  >
                    <HopChain hops={hops} label={`Privilege path ${index + 1}`} />
                  </Panel>
                ))}
              </div>
            );
          }}
        </QueryView>
      ) : (
        <p className="muted small">
          Choose a target resource to explain how <TypeTag type="identity" /> {source} can reach it.
        </p>
      )}
    </div>
  );
}
