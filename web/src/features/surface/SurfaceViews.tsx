import { useId, useState } from 'react';
import {
  useAddSurfaceScope,
  useAnalyzeSurface,
  useImportSurface,
  useRemoveSurfaceScope,
  useSurfaceAssets,
  useSurfaceFindings,
  useSurfaceScope,
  useSurfaceSummary,
  type SurfaceFormat,
} from '../../api/hooks';
import type {
  SurfaceAsset,
  SurfaceImportResult,
  SurfaceScopeEntry,
  SurfaceSummary,
  SurfaceTreeCertificate,
  SurfaceTreeNode,
  SurfaceTreeRecord,
} from '../../api/types';
import { Badge, type Tone } from '../../components/Badge';
import { Button } from '../../components/Button';
import { KeyValueList, Mono, StatTile, Time } from '../../components/Data';
import { Checkbox, Field, Select, TextInput } from '../../components/Form';
import { ConfirmDialog } from '../../components/Modal';
import { ObjectChip } from '../../components/ObjectChip';
import { Callout, Panel } from '../../components/Panel';
import { EmptyState, ErrorState, errorSummary, QueryView } from '../../components/States';
import { Table } from '../../components/Table';
import { useToast } from '../../components/Toast';
import { formatBytes, formatNumber, pluralize, shortHash } from '../../lib/format';
import { SeverityBreakdown } from '../overview/SeverityBreakdown';
import { FindingsTable } from '../findings/FindingsTable';
import {
  certificateState,
  inferSurfaceFormat,
  MAX_INVENTORY_BYTES,
  SCOPE_KINDS,
  scopeLabel,
  SURFACE_FORMATS,
  SURFACE_KINDS,
  SURFACE_RULES,
} from './surfaceModel';

export const NO_SCANNING =
  'R$F Surface never scans: no DNS resolution, port scanning, HTTP requests, certificate retrieval or WHOIS lookups. Everything here comes from imported inventories and the authorized scope you declare, so a finding means “according to the imported data”.';

export const SCOPE_EXPLANATION =
  'Scope means explicit authorization: only assets covered by an entry are treated as the organization’s and judged by the ownership, certificate, DNS and exposure rules. Assets outside the scope are shown but never treated as owned. Every change is written to the audit log.';

export const APPLY_SCOPE_EXPLANATION =
  'Off by default. When checked, the file’s own “scope” section is added to the authorized scope (entries that conflict with existing ones are reported and the existing entry is kept). Review the file’s scope before you enable this: scope means authorization.';

export function NoScanningNotice() {
  return (
    <Callout tone="info" title="Surface never scans">
      {NO_SCANNING}
    </Callout>
  );
}

const SCOPE_TONES: Record<string, Tone> = { in: 'good', out: 'warn' };

export function ScopeBadge({ scope, entry }: { scope: string; entry?: string | null }) {
  return (
    <Badge
      tone={SCOPE_TONES[scope] ?? 'neutral'}
      outline={scope !== 'in'}
      title={
        entry
          ? `Covered by the scope entry ${entry}`
          : scope === 'out'
            ? 'No scope entry covers it'
            : undefined
      }
    >
      {scopeLabel(scope)}
    </Badge>
  );
}

export function CertificateStateBadge({ certificate }: { certificate: SurfaceTreeCertificate }) {
  const state = certificateState(certificate.state, certificate.days_remaining);
  return (
    <span className="row">
      <Badge tone={state.tone} title={`Certificate ${state.label.toLowerCase()} at the reference time`}>
        {state.label}
      </Badge>
      <span className="small muted">{state.detail}</span>
    </span>
  );
}

function Owners({ owners, claimed }: { owners: readonly string[]; claimed: readonly string[] }) {
  if (owners.length > 0) return <span className="small">owner {owners.join(', ')}</span>;
  if (claimed.length > 0) {
    return (
      <span
        className="small muted"
        title="Recorded for an asset outside the scope: shown as a claim, not accepted"
      >
        claimed by {claimed.join(', ')} (not accepted)
      </span>
    );
  }
  return null;
}

function RecordView({ record }: { record: SurfaceTreeRecord }) {
  const services = record.services ?? [];
  const certificates = record.certificates ?? [];
  const cloud = record.cloud ?? [];
  return (
    <li className="surface-record">
      <div className="row row--wrap">
        <span className="tag">{record.type}</span>
        <Mono className="break">{record.value}</Mono>
        {record.view === 'internal' ? (
          <span className="small muted" title="Internal DNS view">
            internal view
          </span>
        ) : null}
        {record.internal ? (
          <Badge tone="warn" outline title="RFC 1918, CGNAT, loopback, link-local or ULA address">
            INTERNAL ADDRESS
          </Badge>
        ) : null}
        {record.hosts && record.hosts.length > 0 ? (
          <span className="small">host {record.hosts.join(', ')}</span>
        ) : null}
        {record.scope ? <ScopeBadge scope={record.scope} /> : null}
        {record.status && record.status !== 'active' ? (
          <Badge tone="bad" outline>
            TARGET {record.status.toUpperCase()}
          </Badge>
        ) : null}
      </div>
      {services.length > 0 || certificates.length > 0 || cloud.length > 0 ? (
        <ul className="surface-endpoints">
          {services.map((service) => (
            <li key={`s:${service.id}:${service.endpoint}`} className="row row--wrap">
              <span className="surface-endpoints__kind">service</span>
              <ObjectChip id={service.id} name={service.name} showType={false} />
              <Mono className="small">{service.endpoint}</Mono>
              {service.product ? <span className="small break">{service.product}</span> : null}
              {service.internet_facing ? (
                <Badge tone="warn" title="Recorded as reachable from the internet">
                  INTERNET-FACING
                </Badge>
              ) : null}
              {service.status !== 'active' ? <span className="small muted">{service.status}</span> : null}
            </li>
          ))}
          {certificates.map((certificate) => (
            <li key={`c:${certificate.id}:${certificate.endpoint}`} className="row row--wrap">
              <span className="surface-endpoints__kind">certificate</span>
              <ObjectChip id={certificate.id} name={certificate.name} showType={false} />
              <Mono className="small">{certificate.endpoint}</Mono>
              <CertificateStateBadge certificate={certificate} />
              {certificate.not_after ? (
                <span className="small muted">
                  not after <Time value={certificate.not_after} />
                </span>
              ) : null}
            </li>
          ))}
          {cloud.map((asset) => (
            <li key={`a:${asset.id}`} className="row row--wrap">
              <span className="surface-endpoints__kind">cloud</span>
              <ObjectChip id={asset.id} name={asset.name} showType={false} />
              <span className="small muted">{[asset.provider, asset.kind].filter(Boolean).join(' ')}</span>
              {asset.public ? (
                <Badge tone="warn" title="Publicly accessible according to the inventory">
                  PUBLIC
                </Badge>
              ) : null}
            </li>
          ))}
        </ul>
      ) : null}
    </li>
  );
}

function TreeNodeView({ node }: { node: SurfaceTreeNode }) {
  return (
    <li className="surface-tree__item">
      <div className="surface-tree__name row row--wrap">
        <ObjectChip id={node.id} name={node.name} showType={false} />
        <ScopeBadge scope={node.scope} entry={node.scope_entry} />
        {node.status !== 'active' ? (
          <Badge tone="neutral" outline>
            {node.status.toUpperCase()}
          </Badge>
        ) : null}
        {!node.inventoried ? (
          <span className="small muted" title="Seen in DNS records only, not in an inventory">
            not inventoried
          </span>
        ) : null}
        <Owners owners={node.owners} claimed={node.claimed_owners} />
        {node.findings > 0 ? <Badge tone="bad">{pluralize(node.findings, 'finding')}</Badge> : null}
      </div>
      {node.records.length > 0 ? (
        <ul className="surface-records" aria-label={`DNS records of ${node.name}`}>
          {node.records.map((record, index) => (
            <RecordView key={`${index}:${record.type}:${record.value}`} record={record} />
          ))}
        </ul>
      ) : (
        <p className="small muted surface-records">No DNS records.</p>
      )}
      {node.txt.length > 0 ? (
        <p className="small muted break surface-records">TXT: {node.txt.join(' · ')}</p>
      ) : null}
      {node.children.length > 0 ? (
        <ul className="surface-tree">
          {node.children.map((child) => (
            <TreeNodeView key={child.id} node={child} />
          ))}
        </ul>
      ) : null}
    </li>
  );
}

/** Domains → names → DNS records → addresses/hosts → services and certificates (with their state). */
export function SurfaceTree({ nodes }: { nodes: readonly SurfaceTreeNode[] }) {
  if (nodes.length === 0) return <p className="muted small">No names in the imported inventories.</p>;
  return (
    <ul className="surface-tree surface-tree--root" aria-label="Domain tree">
      {nodes.map((node) => (
        <TreeNodeView key={node.id} node={node} />
      ))}
    </ul>
  );
}

function AssetTable({
  rows,
  caption,
  empty,
}: {
  rows: readonly SurfaceAsset[];
  caption: string;
  empty: string;
}) {
  return (
    <Table<SurfaceAsset>
      caption={caption}
      dense
      rows={rows}
      rowKey={(asset) => asset.id}
      empty={<span className="muted">{empty}</span>}
      columns={[
        { key: 'kind', header: 'Kind', render: (a) => <span className="tag">{a.kind}</span> },
        {
          key: 'asset',
          header: 'Asset',
          render: (a) => (
            <span className="stack stack--tight">
              <ObjectChip id={a.id} name={a.name} showType={false} />
              {!a.asset ? <span className="small muted">reference only</span> : null}
            </span>
          ),
        },
        {
          key: 'scope',
          header: 'Scope',
          render: (a) => (
            <span className="stack stack--tight">
              <ScopeBadge scope={a.scope} entry={a.scope_entry} />
              {a.scope_entry ? <Mono className="small muted">{a.scope_entry}</Mono> : null}
            </span>
          ),
        },
        {
          key: 'owners',
          header: 'Owner',
          render: (a) =>
            a.owners.length > 0 ? (
              <span className="small" title={a.owner_via ? `inherited from ${a.owner_via}` : undefined}>
                {a.owners.join(', ')}
                {a.owner_via ? <span className="muted"> (via {a.owner_via})</span> : null}
              </span>
            ) : a.claimed_owners.length > 0 ? (
              <span className="small muted">claimed by {a.claimed_owners.join(', ')}</span>
            ) : (
              <span className="muted small">none</span>
            ),
        },
        {
          key: 'flags',
          header: 'Exposure',
          render: (a) => (
            <span className="row row--wrap">
              {a.internet_facing ? <Badge tone="warn">INTERNET-FACING</Badge> : null}
              {a.criticality ? <span className="small">criticality {a.criticality}</span> : null}
              {a.status !== 'active' ? <span className="small muted">{a.status}</span> : null}
            </span>
          ),
        },
        {
          key: 'summary',
          header: 'Summary',
          render: (a) => <span className="small break">{a.summary || '—'}</span>,
        },
        {
          key: 'findings',
          header: 'Findings',
          align: 'right',
          render: (a) =>
            a.findings > 0 ? (
              <Badge tone="bad">{formatNumber(a.findings)}</Badge>
            ) : (
              <span className="muted">0</span>
            ),
        },
      ]}
    />
  );
}

function AnalyzeActions() {
  const analyze = useAnalyzeSurface();
  const { notify } = useToast();
  const run = (persist: boolean) =>
    analyze.mutate(persist, {
      onSuccess: (result) =>
        notify({
          tone: 'good',
          title: persist
            ? `Surface analysis: ${pluralize(result.findings.length, 'finding')}`
            : `Dry run: ${pluralize(result.findings.length, 'finding')} (nothing recorded)`,
          description: persist
            ? `${result.created} new, ${result.updated} updated, ${result.resolved} resolved`
            : result.notes.join(' ') || undefined,
        }),
      onError: (error) =>
        notify({ tone: 'bad', title: 'Surface analysis failed', description: errorSummary(error) }),
    });
  return (
    <span className="row">
      <Button
        size="sm"
        icon="refresh"
        loading={analyze.isPending && analyze.variables === false}
        onClick={() => run(false)}
      >
        Dry run
      </Button>
      <Button
        size="sm"
        variant="primary"
        icon="check"
        loading={analyze.isPending && analyze.variables === true}
        onClick={() => run(true)}
      >
        Analyze
      </Button>
    </span>
  );
}

const EXPIRING_OPTIONS = [7, 14, 30, 60, 90];

function SummaryBody({
  summary,
  onOpenFinding,
}: {
  summary: SurfaceSummary;
  onOpenFinding: (id: string) => void;
}) {
  return (
    <div className="stack">
      {summary.notes.map((note, index) => (
        <Callout key={index} tone="warn">
          <span className="break">{note}</span>
        </Callout>
      ))}
      <div className="stats" aria-label="Surface counts">
        <StatTile
          label="Assets"
          value={formatNumber(summary.assets)}
          detail={`${formatNumber(summary.references)} references`}
        />
        <StatTile label="In scope" value={formatNumber(summary.in_scope)} />
        <StatTile label="Out of scope" value={formatNumber(summary.out_of_scope)} />
        {summary.unscoped > 0 ? <StatTile label="No scope" value={formatNumber(summary.unscoped)} /> : null}
        <StatTile label="Internet-facing" value={formatNumber(summary.internet_facing)} />
        <StatTile label="Open findings" value={formatNumber(summary.findings_open)} />
      </div>
      <div className="split">
        <Panel title="Open findings by severity">
          <div className="stack">
            <SeverityBreakdown counts={summary.findings_by_severity} />
            {summary.top_findings.length > 0 ? (
              <ul className="stack stack--tight">
                {summary.top_findings.map((finding) => (
                  <li key={finding.id} className="row">
                    <Badge
                      tone={
                        finding.severity === 'CRITICAL' || finding.severity === 'HIGH' ? 'bad' : 'neutral'
                      }
                    >
                      {finding.severity}
                    </Badge>
                    <button
                      type="button"
                      className="link-btn break"
                      onClick={() => onOpenFinding(finding.id)}
                    >
                      {finding.title}
                    </button>
                  </li>
                ))}
              </ul>
            ) : null}
          </div>
        </Panel>
        <Panel title="Inventory">
          <KeyValueList
            entries={[
              [
                'By kind',
                <span className="row row--wrap">
                  {Object.entries(summary.by_kind).map(([kind, count]) => (
                    <span key={kind} className="tag">
                      {kind} {formatNumber(count)}
                    </span>
                  ))}
                </span>,
              ],
              ['Owners', summary.owners.length > 0 ? summary.owners.join(', ') : '—'],
              ['Scope entries', formatNumber(summary.scope.length)],
              [
                'Reference time',
                <span>
                  <Time value={summary.reference_time} />{' '}
                  <span className="small muted">({summary.reference_source})</span>
                </span>,
              ],
            ]}
          />
        </Panel>
      </div>
      <Panel title="Domain tree">
        <SurfaceTree nodes={summary.tree} />
        {summary.truncated ? <p className="small muted">The tree is truncated (first names only).</p> : null}
      </Panel>
      <Panel title={`Cloud assets (${formatNumber(summary.cloud.length)})`} flush>
        <AssetTable rows={summary.cloud} caption="Cloud assets" empty="No in-scope cloud assets." />
      </Panel>
      {summary.addresses.length > 0 ? (
        <Panel title={`Addresses without a name (${formatNumber(summary.addresses.length)})`} flush>
          <AssetTable rows={summary.addresses} caption="Addresses without a name" empty="None." />
        </Panel>
      ) : null}
      <Panel
        title={`Addresses, services and cloud assets outside the authorized scope (${formatNumber(summary.outside.length)})`}
        flush
      >
        <AssetTable
          rows={summary.outside}
          caption="Addresses, services and cloud assets outside the scope"
          empty="None. Out-of-scope domain names are marked OUT OF SCOPE in the domain tree above."
        />
      </Panel>
    </div>
  );
}

export function SurfaceOverview({ onOpenFinding }: { onOpenFinding: (id: string) => void }) {
  const [expiringDays, setExpiringDays] = useState(30);
  const query = useSurfaceSummary(expiringDays);
  return (
    <div className="stack">
      <div className="row row--wrap row--between">
        <label className="row small">
          <span className="muted">Certificates expiring within</span>
          <Select
            aria-label="Expiring window in days"
            value={String(expiringDays)}
            options={EXPIRING_OPTIONS.map((days) => ({ value: String(days), label: `${days} days` }))}
            onChange={(event) => setExpiringDays(Number(event.target.value))}
          />
        </label>
        <AnalyzeActions />
      </div>
      <QueryView query={query} feature="Surface" loadingLabel="Loading the surface…">
        {(summary) => <SummaryBody summary={summary} onOpenFinding={onOpenFinding} />}
      </QueryView>
    </div>
  );
}

// ------------------------------------------------------------------ assets

const ASSET_PAGE = 100;

export function SurfaceAssetsView() {
  const [kind, setKind] = useState('');
  const [scope, setScope] = useState<'all' | 'in' | 'out'>('all');
  const [references, setReferences] = useState(false);
  const [offset, setOffset] = useState(0);
  const query = useSurfaceAssets({ kind: kind || null, scope, references, limit: ASSET_PAGE, offset });
  const total = query.data?.total ?? 0;
  return (
    <Panel flush>
      <form
        className="filters filters--inline"
        aria-label="Asset filters"
        onSubmit={(e) => e.preventDefault()}
      >
        <Field label="Kind">
          {(id) => (
            <Select
              id={id}
              value={kind}
              options={[
                { value: '', label: 'All kinds' },
                ...SURFACE_KINDS.map((k) => ({ value: k, label: k })),
              ]}
              onChange={(e) => {
                setKind(e.target.value);
                setOffset(0);
              }}
            />
          )}
        </Field>
        <Field label="Scope">
          {(id) => (
            <Select
              id={id}
              value={scope}
              options={[
                { value: 'all', label: 'All' },
                { value: 'in', label: 'In scope' },
                { value: 'out', label: 'Out of scope' },
              ]}
              onChange={(e) => {
                setScope(e.target.value as 'all' | 'in' | 'out');
                setOffset(0);
              }}
            />
          )}
        </Field>
        <div className="filters__actions">
          <Checkbox
            label="Include references"
            checked={references}
            onChange={(value) => {
              setReferences(value);
              setOffset(0);
            }}
          />
        </div>
      </form>
      <QueryView query={query} feature="Surface assets">
        {(page) => (
          <>
            <AssetTable rows={page.items} caption="Surface assets" empty="No assets match these filters." />
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
                  onClick={() => setOffset(Math.max(0, offset - ASSET_PAGE))}
                >
                  Previous
                </Button>
                <Button
                  size="sm"
                  disabled={offset + ASSET_PAGE >= total}
                  onClick={() => setOffset(offset + ASSET_PAGE)}
                >
                  Next
                </Button>
              </span>
            </footer>
            <p className="small muted panel__pad">
              References are names and addresses seen only as DNS answers or in certificates: shown, never
              judged on their own.
            </p>
          </>
        )}
      </QueryView>
    </Panel>
  );
}

// ------------------------------------------------------------------ scope

function AddScopeForm() {
  const add = useAddSurfaceScope();
  const { notify } = useToast();
  const [target, setTarget] = useState('');
  const [kind, setKind] = useState('');
  const [owner, setOwner] = useState('');
  const [authorization, setAuthorization] = useState('');
  const [replace, setReplace] = useState(false);
  return (
    <form
      className="stack"
      aria-label="Add a scope entry"
      onSubmit={(event) => {
        event.preventDefault();
        add.mutate(
          {
            target: target.trim(),
            kind: kind || undefined,
            owner: owner.trim() || undefined,
            authorization: authorization.trim() || undefined,
            replace,
          },
          {
            onSuccess: (result) => {
              notify({ tone: 'good', title: `Scope entry ${result.entry.target}: ${result.result}` });
              setTarget('');
              setOwner('');
              setAuthorization('');
              setReplace(false);
            },
          },
        );
      }}
    >
      <div className="filters">
        <Field label="Target" hint="domain, CIDR, IP or provider:account">
          {(id) => (
            <TextInput
              id={id}
              value={target}
              placeholder="raven.example"
              onChange={(e) => setTarget(e.target.value)}
            />
          )}
        </Field>
        <Field label="Kind">
          {(id) => (
            <Select
              id={id}
              value={kind}
              options={[
                { value: '', label: 'Infer from target' },
                ...SCOPE_KINDS.map((k) => ({ value: k, label: k })),
              ]}
              onChange={(e) => setKind(e.target.value)}
            />
          )}
        </Field>
        <Field label="Owner" hint="Who is accountable for this entry">
          {(id) => (
            <TextInput
              id={id}
              value={owner}
              placeholder="IT operations"
              onChange={(e) => setOwner(e.target.value)}
            />
          )}
        </Field>
        <Field label="Authorization" hint="Reference, e.g. a ticket">
          {(id) => (
            <TextInput
              id={id}
              value={authorization}
              placeholder="SEC-2026-031"
              onChange={(e) => setAuthorization(e.target.value)}
            />
          )}
        </Field>
      </div>
      <Checkbox
        label="Replace an existing entry for this target (owner and authorization)"
        checked={replace}
        onChange={setReplace}
      />
      {add.isError ? <ErrorState title="The entry was not added" error={add.error} compact /> : null}
      <div>
        <Button type="submit" variant="primary" icon="plus" loading={add.isPending} disabled={!target.trim()}>
          Add to the authorized scope
        </Button>
      </div>
    </form>
  );
}

export function SurfaceScopeView() {
  const query = useSurfaceScope();
  const remove = useRemoveSurfaceScope();
  const { notify } = useToast();
  const [pending, setPending] = useState<SurfaceScopeEntry | null>(null);
  return (
    <div className="stack">
      <Callout tone="warn" title="Scope is authorization">
        {SCOPE_EXPLANATION}
      </Callout>
      <Panel title="Authorized scope" flush>
        <QueryView query={query} feature="Surface scope">
          {(data) => (
            <Table<SurfaceScopeEntry>
              caption="Authorized scope entries"
              rows={data.items}
              rowKey={(entry) => entry.target}
              empty={
                <span className="muted">
                  No scope: nothing is treated as owned and analysis produces no findings.
                </span>
              }
              columns={[
                { key: 'target', header: 'Target', render: (e) => <Mono className="break">{e.target}</Mono> },
                { key: 'kind', header: 'Kind', render: (e) => <span className="tag">{e.kind}</span> },
                {
                  key: 'owner',
                  header: 'Owner',
                  render: (e) => <span className="break">{e.owner ?? '—'}</span>,
                },
                {
                  key: 'authorization',
                  header: 'Authorization',
                  render: (e) =>
                    e.authorization ? (
                      <span className="small break">{e.authorization}</span>
                    ) : (
                      <span className="small muted">no reference</span>
                    ),
                },
                {
                  key: 'added',
                  header: 'Added',
                  render: (e) => <Time value={e.added_at} className="small" />,
                },
                {
                  key: 'remove',
                  header: '',
                  render: (e) => (
                    <Button
                      size="sm"
                      variant="danger"
                      icon="trash"
                      aria-label={`Remove ${e.target} from the scope`}
                      onClick={() => setPending(e)}
                    >
                      Remove
                    </Button>
                  ),
                },
              ]}
            />
          )}
        </QueryView>
      </Panel>
      <Panel title="Add an entry">
        <AddScopeForm />
      </Panel>
      {pending ? (
        <ConfirmDialog
          title={`Remove ${pending.target} from the authorized scope?`}
          danger
          confirmLabel="Remove from scope"
          requireText={pending.target}
          busy={remove.isPending}
          onCancel={() => setPending(null)}
          onConfirm={() => {
            const target = pending.target;
            remove.mutateAsync(target).then(
              () => {
                notify({ tone: 'good', title: `${target} removed from the authorized scope` });
                setPending(null);
              },
              (error: unknown) => {
                notify({
                  tone: 'bad',
                  title: 'Could not remove the entry',
                  description: errorSummary(error),
                });
                setPending(null);
              },
            );
          }}
        >
          <p>
            Assets covered only by this entry stop being treated as the organization’s: rules no longer judge
            them and their open findings are resolved by the next analysis. The change is audited.
          </p>
        </ConfirmDialog>
      ) : null}
    </div>
  );
}

// ------------------------------------------------------------------ findings

const FINDING_STATUSES = ['open', 'acknowledged', 'resolved', 'false_positive', 'suppressed', 'all'];
const SEVERITIES = ['low', 'medium', 'high', 'critical'];

export function SurfaceFindingsView({
  selectedId,
  onOpen,
}: {
  selectedId: string | null;
  onOpen: (id: string) => void;
}) {
  const [rule, setRule] = useState('');
  const [severity, setSeverity] = useState('');
  const [status, setStatus] = useState('open');
  const query = useSurfaceFindings({
    rule: rule || undefined,
    min_severity: severity || undefined,
    status,
    limit: 500,
  });
  return (
    <Panel flush>
      <form
        className="filters filters--inline"
        aria-label="Surface finding filters"
        onSubmit={(e) => e.preventDefault()}
      >
        <Field label="Rule">
          {(id) => (
            <Select
              id={id}
              value={rule}
              options={[
                { value: '', label: 'All rules' },
                ...SURFACE_RULES.map((r) => ({ value: r, label: r })),
              ]}
              onChange={(e) => setRule(e.target.value)}
            />
          )}
        </Field>
        <Field label="Min severity">
          {(id) => (
            <Select
              id={id}
              value={severity}
              options={[
                { value: '', label: 'Any' },
                ...SEVERITIES.map((s) => ({ value: s, label: s.toUpperCase() })),
              ]}
              onChange={(e) => setSeverity(e.target.value)}
            />
          )}
        </Field>
        <Field label="Status">
          {(id) => (
            <Select
              id={id}
              value={status}
              options={FINDING_STATUSES.map((s) => ({ value: s, label: s.replace('_', ' ') }))}
              onChange={(e) => setStatus(e.target.value)}
            />
          )}
        </Field>
      </form>
      <QueryView query={query} feature="Surface findings">
        {(page) => (
          <>
            <FindingsTable
              rows={page.items}
              selectedId={selectedId}
              showProduct={false}
              onOpen={(finding) => onOpen(finding.id)}
              empty="No surface findings match these filters."
            />
            {(page.total ?? 0) > page.items.length ? (
              <p className="small muted panel__pad">
                Showing {formatNumber(page.items.length)} of {formatNumber(page.total ?? 0)} findings.
              </p>
            ) : null}
          </>
        )}
      </QueryView>
    </Panel>
  );
}

// ------------------------------------------------------------------ import

function ImportResultView({ result }: { result: SurfaceImportResult }) {
  return (
    <div className="stack">
      <Callout tone={result.rejected > 0 ? 'warn' : 'info'} title={`Imported ${result.source}`}>
        {formatNumber(result.accepted)} of {formatNumber(result.records)} records accepted
        {result.rejected > 0 ? `, ${formatNumber(result.rejected)} rejected` : ''}.
        {result.job_id ? (
          <>
            {' '}
            Job <Mono>{result.job_id}</Mono>.
          </>
        ) : null}{' '}
        Run Analyze to update the findings.
      </Callout>
      <KeyValueList
        entries={[
          ['Format', result.format],
          ['Organization', result.organization ?? '—'],
          ['As of', <Time value={result.as_of} />],
          ['Size', formatBytes(result.size)],
          ['SHA-256', <Mono title={result.sha256}>{shortHash(result.sha256, 24)}</Mono>],
          [
            'By kind',
            <span className="row row--wrap">
              {Object.entries(result.by_kind).map(([kind, count]) => (
                <span key={kind} className="tag">
                  {kind} {formatNumber(count)}
                </span>
              ))}
            </span>,
          ],
          [
            'Scope section',
            result.scope_declared === 0
              ? 'none in the file'
              : result.scope_applied
                ? `${pluralize(result.scope_declared, 'entry', 'entries')} declared, applied`
                : `${pluralize(result.scope_declared, 'entry', 'entries')} declared, not applied`,
          ],
        ]}
      />
      {result.scope_changes.length > 0 ? (
        <section className="stack stack--tight">
          <h4>Scope changes</h4>
          <ul className="stack stack--tight">
            {result.scope_changes.map((change, index) => (
              <li key={index} className="row row--wrap">
                <Mono>{change.target}</Mono>
                <span className="tag">{change.kind}</span>
                <span className="small">{change.result}</span>
                {change.detail ? <span className="small muted break">{change.detail}</span> : null}
              </li>
            ))}
          </ul>
        </section>
      ) : null}
      {result.warnings.length > 0 ? (
        <Callout tone="warn" title="Warnings">
          <ul className="stack stack--tight">
            {result.warnings.map((warning, index) => (
              <li key={index} className="break">
                {warning}
              </li>
            ))}
          </ul>
        </Callout>
      ) : null}
      {result.rejections.length > 0 ? (
        <section className="stack stack--tight">
          <h4>Rejected records</h4>
          <Table<SurfaceImportResult['rejections'][number]>
            caption="Rejected records"
            dense
            rows={result.rejections}
            rowKey={(row) => `${row.record}:${row.reason}`}
            columns={[
              { key: 'record', header: 'Record', render: (r) => <Mono className="small">{r.record}</Mono> },
              {
                key: 'reason',
                header: 'Reason',
                render: (r) => <span className="small break">{r.reason}</span>,
              },
            ]}
          />
        </section>
      ) : null}
    </div>
  );
}

/** `POST /surface/import`: the file is sent as the request body; `apply_scope` only when checked. */
export function SurfaceImportView() {
  const importer = useImportSurface();
  const [file, setFile] = useState<File | null>(null);
  const [format, setFormat] = useState<'' | SurfaceFormat>('');
  const [applyScope, setApplyScope] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const fileId = useId();
  const applyHintId = useId();
  const effective: SurfaceFormat = format || (file ? inferSurfaceFormat(file.name) : 'json');
  return (
    <div className="stack">
      <Panel title="Import an inventory">
        <form
          className="stack"
          aria-label="Import a surface inventory"
          onSubmit={(event) => {
            event.preventDefault();
            if (!file) return;
            if (file.size > MAX_INVENTORY_BYTES) {
              setProblem('Surface inventories are limited to 20 MB per request.');
              return;
            }
            setProblem(null);
            importer.mutate({ file, format: effective, sourceName: file.name, applyScope });
          }}
        >
          <div className="field">
            <label className="field__label" htmlFor={fileId}>
              Inventory file
            </label>
            <input
              id={fileId}
              type="file"
              className="input input--file"
              accept=".json,.jsonl,.ndjson,.yaml,.yml,.csv"
              onChange={(event) => setFile(event.target.files?.[0] ?? null)}
            />
            <p className="field__hint">
              raf-surface/1 JSON or YAML, JSON Lines, CSV with a <code>kind</code> column, or a JSON list of
              records; at most 20 MB. The file is sent as the request body; the server never reads a path.
            </p>
            {file ? (
              <p className="small muted">
                {file.name} · {formatBytes(file.size)}
              </p>
            ) : null}
          </div>
          <Field label="Format">
            {(id) => (
              <Select
                id={id}
                value={format}
                options={[
                  {
                    value: '',
                    label: `From the file name${file ? ` (${inferSurfaceFormat(file.name)})` : ''}`,
                  },
                  ...SURFACE_FORMATS.map((value) => ({ value, label: value })),
                ]}
                onChange={(e) => setFormat(e.target.value as '' | SurfaceFormat)}
              />
            )}
          </Field>
          <div className="stack stack--tight">
            <Checkbox label="Apply the file’s scope section" checked={applyScope} onChange={setApplyScope} />
            <p className="field__hint" id={applyHintId}>
              {APPLY_SCOPE_EXPLANATION}
            </p>
          </div>
          {problem ? (
            <p className="field__error" role="alert">
              {problem}
            </p>
          ) : null}
          {importer.isError ? (
            <ErrorState title="The inventory was not imported" error={importer.error} compact />
          ) : null}
          <div>
            <Button
              type="submit"
              variant="primary"
              icon="upload"
              loading={importer.isPending}
              disabled={!file}
            >
              Import
            </Button>
          </div>
        </form>
      </Panel>
      {importer.data ? (
        <Panel title="Import result" actions={<AnalyzeActions />}>
          <ImportResultView result={importer.data} />
        </Panel>
      ) : (
        <EmptyState icon="surface" title="Inventories are untrusted input">
          <p>
            The server parses them with safe loaders, validates names, addresses and fingerprints and rejects
            broken records with a reason; everything is shown here as text.
          </p>
        </EmptyState>
      )}
    </div>
  );
}
