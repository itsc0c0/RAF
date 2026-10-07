import { useState } from 'react';
import { useVaultFindings, useVaultRules, useVaultSecrets } from '../../api/hooks';
import {
  FINDING_STATUSES,
  SEVERITIES,
  type Finding,
  type VaultRule,
  type VaultSecret,
} from '../../api/types';
import { Badge, ConfidenceBadge, SeverityBadge } from '../../components/Badge';
import { Button } from '../../components/Button';
import { Mono, Time } from '../../components/Data';
import { Checkbox, Field, Select } from '../../components/Form';
import { Callout, Panel } from '../../components/Panel';
import { QueryView } from '../../components/States';
import { Table } from '../../components/Table';
import { formatNumber, shortHash } from '../../lib/format';
import { FindingStatusBadge } from '../findings/FindingDetail';

export const VAULT_NOTE =
  'Secret values are always redacted by the API (a few characters and a fingerprint); R$F never stores or returns them, and this view cannot reveal them. Scanning reads local files and runs from the CLI only: raf vault scan PATH.';

/** A value redacted by the API (`ghp****OL8d`), labelled so it is never mistaken for the secret. */
export function RedactedValue({ value }: { value: unknown }) {
  const text = typeof value === 'string' && value ? value : '****';
  return (
    <span className="redacted" title="Redacted by R$F: the secret value is never stored or returned">
      <span className="redacted__label">redacted</span>
      <span className="mono">{text}</span>
    </span>
  );
}

function location(finding: Finding): string {
  const meta = finding.metadata;
  const path =
    typeof meta.relative_path === 'string'
      ? meta.relative_path
      : typeof meta.path === 'string'
        ? meta.path
        : '';
  const lines = Array.isArray(meta.lines) ? meta.lines.map(String).join(',') : '';
  return `${path}${lines ? `:${lines}` : ''}`;
}

const PAGE_SIZE = 50;

export function VaultFindingsView({
  selectedId,
  onOpen,
}: {
  selectedId: string | null;
  onOpen: (id: string) => void;
}) {
  const [status, setStatus] = useState('OPEN');
  const [severity, setSeverity] = useState('');
  const [offset, setOffset] = useState(0);
  const query = useVaultFindings({ status, severity: severity || undefined, limit: PAGE_SIZE, offset });
  const total = query.data?.total ?? 0;
  return (
    <Panel title="Secret findings" flush>
      <form
        className="filters filters--inline"
        aria-label="Secret finding filters"
        onSubmit={(e) => e.preventDefault()}
      >
        <Field label="Status">
          {(id) => (
            <Select
              id={id}
              value={status}
              options={[
                ...FINDING_STATUSES.map((value) => ({ value, label: value.replace('_', ' ') })),
                { value: 'all', label: 'All' },
              ]}
              onChange={(e) => {
                setStatus(e.target.value);
                setOffset(0);
              }}
            />
          )}
        </Field>
        <Field label="Min severity">
          {(id) => (
            <Select
              id={id}
              value={severity}
              options={[{ value: '', label: 'Any' }, ...SEVERITIES.map((value) => ({ value, label: value }))]}
              onChange={(e) => {
                setSeverity(e.target.value);
                setOffset(0);
              }}
            />
          )}
        </Field>
      </form>
      <QueryView query={query} feature="Vault">
        {(page) => (
          <>
            <Table<Finding>
              caption="Secret findings"
              rows={page.items}
              rowKey={(finding) => finding.id}
              selectedKey={selectedId}
              onRowClick={(finding) => onOpen(finding.id)}
              rowLabel={(finding) => `Open finding ${finding.title}`}
              empty={<span className="muted">No secret findings match these filters.</span>}
              columns={[
                {
                  key: 'severity',
                  header: 'Severity',
                  render: (f) => <SeverityBadge severity={f.severity} />,
                },
                {
                  key: 'confidence',
                  header: 'Confidence',
                  render: (f) => <ConfidenceBadge confidence={f.confidence} level={f.confidence_level} />,
                },
                { key: 'rule', header: 'Rule', render: (f) => <Mono className="small">{f.rule_id}</Mono> },
                {
                  key: 'location',
                  header: 'Location',
                  render: (f) => (
                    <span className="stack stack--tight">
                      <Mono className="small break">{location(f)}</Mono>
                      {typeof f.metadata.host === 'string' ? (
                        <span className="small muted">host {f.metadata.host}</span>
                      ) : null}
                    </span>
                  ),
                },
                {
                  key: 'value',
                  header: 'Value',
                  render: (f) => <RedactedValue value={f.metadata.redacted} />,
                },
                {
                  key: 'fingerprint',
                  header: 'Fingerprint',
                  render: (f) => (
                    <Mono
                      className="small"
                      title={typeof f.metadata.fingerprint === 'string' ? f.metadata.fingerprint : undefined}
                    >
                      {shortHash(
                        typeof f.metadata.fingerprint === 'string' ? f.metadata.fingerprint : null,
                        16,
                      )}
                    </Mono>
                  ),
                },
                { key: 'status', header: 'Status', render: (f) => <FindingStatusBadge status={f.status} /> },
              ]}
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
        )}
      </QueryView>
    </Panel>
  );
}

export function VaultSecretsView() {
  const [includeRemoved, setIncludeRemoved] = useState(false);
  const query = useVaultSecrets(includeRemoved);
  return (
    <Panel
      title="Discovered secrets"
      flush
      actions={
        <Checkbox label="Include removed secrets" checked={includeRemoved} onChange={setIncludeRemoved} />
      }
    >
      <QueryView query={query} feature="Vault secrets">
        {(page) => (
          <>
            <Table<VaultSecret>
              caption="Secret objects (redacted)"
              dense
              rows={page.items}
              rowKey={(secret) => secret.id}
              empty={<span className="muted">No secrets recorded.</span>}
              columns={[
                {
                  key: 'name',
                  header: 'Secret',
                  render: (s) => (
                    <span className="stack stack--tight">
                      <span className="break">{s.name}</span>
                      <span className="small muted">{s.kind}</span>
                    </span>
                  ),
                },
                {
                  key: 'severity',
                  header: 'Severity',
                  render: (s) => <SeverityBadge severity={s.severity} />,
                },
                {
                  key: 'confidence',
                  header: 'Confidence',
                  render: (s) => <ConfidenceBadge confidence={s.confidence} />,
                },
                { key: 'value', header: 'Value', render: (s) => <RedactedValue value={s.redacted} /> },
                {
                  key: 'fingerprint',
                  header: 'Fingerprint',
                  render: (s) => (
                    <Mono className="small" title={s.fingerprint}>
                      {shortHash(s.fingerprint, 16)}
                    </Mono>
                  ),
                },
                {
                  key: 'where',
                  header: 'Where',
                  render: (s) => (
                    <span className="stack stack--tight">
                      <Mono className="small break">
                        {s.relative_path ?? s.path ?? '—'}
                        {s.line !== null ? `:${s.line}` : ''}
                      </Mono>
                      {s.host ? <span className="small muted">host {s.host}</span> : null}
                    </span>
                  ),
                },
                {
                  key: 'seen',
                  header: 'Last seen',
                  render: (s) => <Time value={s.last_seen} className="small" />,
                },
                {
                  key: 'state',
                  header: 'State',
                  render: (s) =>
                    s.removed ? (
                      <Badge tone="good" outline>
                        REMOVED
                      </Badge>
                    ) : (
                      <Badge tone="bad" outline>
                        PRESENT
                      </Badge>
                    ),
                },
              ]}
            />
            {(page.total ?? 0) > page.items.length ? (
              <p className="small muted panel__pad">
                Showing {formatNumber(page.items.length)} of {formatNumber(page.total ?? 0)} secrets.
              </p>
            ) : null}
          </>
        )}
      </QueryView>
    </Panel>
  );
}

export function VaultRulesView() {
  const query = useVaultRules();
  return (
    <Panel title="Detection rules" flush>
      <QueryView query={query} feature="Vault rules">
        {(data) => (
          <Table<VaultRule>
            caption="Secret detection rules"
            dense
            rows={data.items}
            rowKey={(rule) => rule.id}
            columns={[
              {
                key: 'rule',
                header: 'Rule',
                render: (r) => (
                  <span className="stack stack--tight">
                    <span>{r.title}</span>
                    <Mono className="small muted">{r.id}</Mono>
                  </span>
                ),
              },
              { key: 'severity', header: 'Severity', render: (r) => <SeverityBadge severity={r.severity} /> },
              {
                key: 'confidence',
                header: 'Confidence',
                render: (r) => (
                  <span className="stack stack--tight">
                    <ConfidenceBadge confidence={r.confidence} />
                    <span className="small muted">precision {r.precision}</span>
                  </span>
                ),
              },
              {
                key: 'description',
                header: 'Detects',
                render: (r) => <span className="small break">{r.description}</span>,
              },
              {
                key: 'recommendation',
                header: 'Recommendation',
                render: (r) => <span className="small break">{r.recommendation}</span>,
              },
            ]}
          />
        )}
      </QueryView>
    </Panel>
  );
}

export function VaultView({
  selectedId,
  onOpen,
}: {
  selectedId: string | null;
  onOpen: (id: string) => void;
}) {
  return (
    <div className="stack">
      <Callout tone="info" title="Values are never shown">
        {VAULT_NOTE}
      </Callout>
      <VaultFindingsView selectedId={selectedId} onOpen={onOpen} />
      <VaultSecretsView />
      <VaultRulesView />
    </div>
  );
}
