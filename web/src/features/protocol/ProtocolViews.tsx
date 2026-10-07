import { useQueryClient } from '@tanstack/react-query';
import { useId, useState } from 'react';
import {
  apiKey,
  useCaptureFlows,
  useCapturePacket,
  useCaptureSummary,
  useConfig,
  useInspectCapture,
} from '../../api/hooks';
import type {
  CaptureDns,
  CaptureFlow,
  CaptureHttp,
  CaptureSummary,
  CaptureTls,
  PacketDetail,
  PacketField,
  PacketLayer,
} from '../../api/types';
import { useWorkspaceName } from '../../app/workspace';
import { Badge } from '../../components/Badge';
import { Button, IconButton } from '../../components/Button';
import { CopyButton, KeyValueList, Meter, Mono, StatTile, Time } from '../../components/Data';
import { Field, Select, TextInput } from '../../components/Form';
import { Icon } from '../../components/Icon';
import { Callout, Panel } from '../../components/Panel';
import { EmptyState, ErrorState, QueryView } from '../../components/States';
import { Table } from '../../components/Table';
import { displayValue, formatBytes, formatDuration, formatNumber, shortHash } from '../../lib/format';

export const UPLOAD_ID_RE = /^[0-9a-f]{32}$/;
const SUMMARY_LIMIT = 50;
const PROTOCOLS = ['eth', 'vlan', 'sll', 'ip', 'ipv6', 'tcp', 'udp', 'icmp', 'icmpv6', 'dns', 'http', 'tls'];
export const FLOW_SORTS = ['id', 'bytes', 'packets', 'duration'] as const;

/** A decoded field value as text (lists are joined; nested values are JSON text, never markup). */
export function fieldValue(value: unknown): string {
  if (Array.isArray(value)) return value.map((item) => displayValue(item)).join(', ');
  if (typeof value === 'boolean') return value ? 'yes' : 'no';
  return displayValue(value);
}

function seconds(value: number | null | undefined): string {
  return value === null || value === undefined ? '—' : formatDuration(value * 1000);
}

// ------------------------------------------------------------------ upload / open

export function CaptureUploadForm({ onUploaded }: { onUploaded: (summary: CaptureSummary) => void }) {
  const inspect = useInspectCapture();
  const client = useQueryClient();
  const workspace = useWorkspaceName();
  const config = useConfig();
  const [file, setFile] = useState<File | null>(null);
  const [inputKey, setInputKey] = useState(0);
  const fileId = useId();
  const limit = config.data?.items.find((item) => item.key === 'api.max_upload_mb')?.value;
  return (
    <form
      className="stack"
      aria-label="Upload a capture"
      onSubmit={(event) => {
        event.preventDefault();
        if (!file) return;
        inspect.mutate(
          { file },
          {
            onSuccess: (summary) => {
              // The upload answer is the unfiltered summary: seed it so the view needs no second read.
              client.setQueryData(
                apiKey(workspace, '/protocol/inspect', { upload: summary.upload.id, limit: SUMMARY_LIMIT }),
                summary,
              );
              setFile(null);
              setInputKey((key) => key + 1);
              onUploaded(summary);
            },
          },
        );
      }}
    >
      <div className="field">
        <label className="field__label" htmlFor={fileId}>
          Capture file (.pcap, .pcapng, .cap)
        </label>
        <input
          key={inputKey}
          id={fileId}
          type="file"
          className="input input--file"
          accept=".pcap,.pcapng,.cap,application/vnd.tcpdump.pcap"
          onChange={(event) => setFile(event.target.files?.[0] ?? null)}
        />
        <p className="field__hint">
          Stored in the workspace under a generated ID and addressed only by that ID
          {typeof limit === 'number' ? `; at most ${formatNumber(limit)} MB (api.max_upload_mb)` : ''}. R$F
          never captures live traffic, sends packets or decrypts anything.
        </p>
      </div>
      {inspect.isError ? (
        <ErrorState title="The capture was not inspected" error={inspect.error} compact />
      ) : null}
      <div>
        <Button type="submit" variant="primary" icon="upload" loading={inspect.isPending} disabled={!file}>
          Upload and inspect
        </Button>
      </div>
    </form>
  );
}

export function OpenUploadForm({ onOpen }: { onOpen: (upload: string) => void }) {
  const [value, setValue] = useState('');
  const [problem, setProblem] = useState<string | null>(null);
  return (
    <form
      className="row row--wrap row--top"
      aria-label="Open an earlier upload"
      onSubmit={(event) => {
        event.preventDefault();
        const id = value.trim().toLowerCase();
        if (!UPLOAD_ID_RE.test(id)) {
          setProblem('Upload IDs are 32 hexadecimal characters.');
          return;
        }
        setProblem(null);
        onOpen(id);
      }}
    >
      <Field label="Upload ID" className="grow" hint="Returned by an earlier upload to this workspace">
        {(id) => (
          <>
            <TextInput
              id={id}
              className="mono"
              value={value}
              maxLength={32}
              placeholder="6ff14b609e7cbb28010e696a45c1da5b"
              onChange={(e) => setValue(e.target.value)}
            />
            {problem ? (
              <p className="field__error" role="alert">
                {problem}
              </p>
            ) : null}
          </>
        )}
      </Field>
      <div className="filters__actions">
        <Button type="submit" disabled={!value.trim()}>
          Open
        </Button>
      </div>
    </form>
  );
}

// ------------------------------------------------------------------ summary

export interface CaptureFilterState {
  protocol: string;
  host: string;
  port: string;
  flow: string;
}

export const NO_FILTERS: CaptureFilterState = { protocol: '', host: '', port: '', flow: '' };

function FiltersForm({
  value,
  onApply,
}: {
  value: CaptureFilterState;
  onApply: (next: CaptureFilterState) => void;
}) {
  const [draft, setDraft] = useState(value);
  const set = (patch: Partial<CaptureFilterState>) => setDraft((current) => ({ ...current, ...patch }));
  return (
    <form
      className="filters filters--inline"
      aria-label="Capture filters"
      onSubmit={(event) => {
        event.preventDefault();
        onApply(draft);
      }}
    >
      <Field label="Protocol">
        {(id) => (
          <Select
            id={id}
            value={draft.protocol}
            options={[{ value: '', label: 'Any' }, ...PROTOCOLS.map((p) => ({ value: p, label: p }))]}
            onChange={(e) => set({ protocol: e.target.value })}
          />
        )}
      </Field>
      <Field label="Host (IP)">
        {(id) => (
          <TextInput
            id={id}
            value={draft.host}
            placeholder="10.30.0.5"
            onChange={(e) => set({ host: e.target.value })}
          />
        )}
      </Field>
      <Field label="Port">
        {(id) => (
          <TextInput
            id={id}
            value={draft.port}
            inputMode="numeric"
            placeholder="443"
            onChange={(e) => set({ port: e.target.value })}
          />
        )}
      </Field>
      <Field label="Flow ID">
        {(id) => (
          <TextInput
            id={id}
            value={draft.flow}
            inputMode="numeric"
            placeholder="4"
            onChange={(e) => set({ flow: e.target.value })}
          />
        )}
      </Field>
      <div className="filters__actions">
        <Button type="submit" variant="primary" icon="filter">
          Apply
        </Button>
        <Button
          variant="ghost"
          onClick={() => {
            setDraft(NO_FILTERS);
            onApply(NO_FILTERS);
          }}
        >
          Clear
        </Button>
      </div>
    </form>
  );
}

function numberOrNull(value: string): number | null {
  const parsed = Number(value.trim());
  return value.trim() && Number.isInteger(parsed) && parsed >= 0 ? parsed : null;
}

function ListCell({ values }: { values: readonly (string | number)[] }) {
  if (values.length === 0) return <span className="muted">—</span>;
  return <span className="mono small break">{values.join(', ')}</span>;
}

function DnsTable({ rows }: { rows: readonly CaptureDns[] }) {
  return (
    <Table<CaptureDns>
      caption="DNS names"
      dense
      rows={rows}
      rowKey={(row) => `${row.name}|${row.type}`}
      empty={<span className="muted">No DNS traffic.</span>}
      columns={[
        { key: 'name', header: 'Name', render: (r) => <Mono className="break">{r.name}</Mono> },
        { key: 'type', header: 'Type', render: (r) => <span className="tag">{r.type}</span> },
        { key: 'answers', header: 'Answers', render: (r) => <ListCell values={r.answers} /> },
        { key: 'rcodes', header: 'Response', render: (r) => <ListCell values={r.rcodes} /> },
        { key: 'clients', header: 'Clients', render: (r) => <ListCell values={r.clients} /> },
        { key: 'servers', header: 'Resolvers', render: (r) => <ListCell values={r.servers} /> },
      ]}
    />
  );
}

function TlsTable({ rows }: { rows: readonly CaptureTls[] }) {
  return (
    <Table<CaptureTls>
      caption="TLS handshakes"
      dense
      rows={rows}
      rowKey={(row) => `${row.sni ?? ''}|${row.servers.join(',')}`}
      empty={<span className="muted">No TLS handshakes.</span>}
      columns={[
        {
          key: 'sni',
          header: 'Server name (SNI)',
          render: (r) =>
            r.sni ? <Mono className="break">{r.sni}</Mono> : <span className="muted">no SNI</span>,
        },
        { key: 'servers', header: 'Servers', render: (r) => <ListCell values={r.servers} /> },
        { key: 'versions', header: 'Version', render: (r) => <ListCell values={r.versions} /> },
        { key: 'alpn', header: 'ALPN', render: (r) => <ListCell values={r.alpn} /> },
        { key: 'ciphers', header: 'Cipher', render: (r) => <ListCell values={r.ciphers} /> },
        { key: 'clients', header: 'Clients', render: (r) => <ListCell values={r.clients} /> },
      ]}
    />
  );
}

function HttpTable({ rows }: { rows: readonly CaptureHttp[] }) {
  return (
    <Table<CaptureHttp>
      caption="HTTP hosts"
      dense
      rows={rows}
      rowKey={(row) => `${row.host ?? ''}|${row.servers.join(',')}`}
      empty={<span className="muted">No HTTP requests.</span>}
      columns={[
        { key: 'host', header: 'Host', render: (r) => <Mono className="break">{r.host ?? '—'}</Mono> },
        { key: 'requests', header: 'Requests', align: 'right', render: (r) => formatNumber(r.requests) },
        { key: 'methods', header: 'Methods', render: (r) => <ListCell values={r.methods} /> },
        { key: 'paths', header: 'Paths', render: (r) => <ListCell values={r.paths} /> },
        { key: 'statuses', header: 'Status', render: (r) => <ListCell values={r.statuses} /> },
        { key: 'agents', header: 'User agents', render: (r) => <ListCell values={r.user_agents} /> },
      ]}
    />
  );
}

/** The flow table shared by the summary and the flows view. */
export function FlowTable({
  flows,
  onFilterFlow,
}: {
  flows: readonly CaptureFlow[];
  onFilterFlow?: (id: number) => void;
}) {
  return (
    <Table<CaptureFlow>
      caption="Flows"
      dense
      rows={flows}
      rowKey={(flow) => String(flow.id)}
      empty={<span className="muted">No flows.</span>}
      columns={[
        { key: 'id', header: 'ID', align: 'right', render: (f) => <span className="tabular">{f.id}</span> },
        { key: 'proto', header: 'Proto', render: (f) => <span className="tag">{f.protocol}</span> },
        {
          key: 'endpoints',
          header: 'Client → server',
          render: (f) => (
            <span className="stack stack--tight">
              <Mono className="small break">
                {f.client}
                {f.client_port !== null ? `:${f.client_port}` : ''} → {f.server}
                {f.server_port !== null ? `:${f.server_port}` : ''}
              </Mono>
              <span className="small muted break" title="How the server side was inferred">
                {f.server_reason}
              </span>
            </span>
          ),
        },
        {
          key: 'app',
          header: 'App',
          render: (f) => (
            <span
              title={
                f.app_evidence === 'payload' ? 'Decoded from the payload' : 'Guessed from the server port'
              }
            >
              {f.app}
              {f.app_evidence !== 'payload' ? '?' : ''}
            </span>
          ),
        },
        {
          key: 'packets',
          header: 'Packets out/in',
          align: 'right',
          render: (f) => (
            <span className="tabular small">
              {formatNumber(f.packets_out)} / {formatNumber(f.packets_in)}
            </span>
          ),
        },
        {
          key: 'bytes',
          header: 'Bytes out/in',
          align: 'right',
          render: (f) => (
            <span className="tabular small">
              {formatBytes(f.bytes_out)} / {formatBytes(f.bytes_in)}
            </span>
          ),
        },
        { key: 'duration', header: 'Duration', align: 'right', render: (f) => seconds(f.duration_s) },
        { key: 'flags', header: 'TCP flags', render: (f) => <ListCell values={f.tcp_flags} /> },
        {
          key: 'community',
          header: 'Community ID',
          render: (f) =>
            f.community_id ? (
              <span className="row">
                <Mono className="small" title={f.community_id}>
                  {shortHash(f.community_id, 14)}
                </Mono>
                <CopyButton value={f.community_id} label="Copy Community ID" />
              </span>
            ) : (
              <span className="muted">—</span>
            ),
        },
        ...(onFilterFlow
          ? [
              {
                key: 'filter',
                header: '',
                render: (f: CaptureFlow) => (
                  <IconButton
                    size="sm"
                    icon="filter"
                    label={`Show only flow ${f.id}`}
                    onClick={() => onFilterFlow(f.id)}
                  />
                ),
              },
            ]
          : []),
      ]}
    />
  );
}

function SummaryBody({
  summary,
  onFilterFlow,
}: {
  summary: CaptureSummary;
  onFilterFlow: (id: number) => void;
}) {
  const total = summary.packets.total || 1;
  return (
    <div className="stack">
      {summary.warnings.length > 0 || summary.truncated || summary.limit_reached ? (
        <Callout tone="warn" title="Warnings">
          <ul className="stack stack--tight">
            {summary.truncated ? (
              <li>The file is truncated: it was read up to the last complete packet.</li>
            ) : null}
            {summary.limit_reached ? (
              <li>A resource limit was reached: some packets or records are not counted.</li>
            ) : null}
            {summary.warnings.slice(0, 20).map((warning, index) => (
              <li key={index} className="break">
                {warning}
              </li>
            ))}
            {summary.warnings.length > 20 ? (
              <li className="muted">+{summary.warnings.length - 20} more</li>
            ) : null}
          </ul>
        </Callout>
      ) : null}
      <div className="stats" aria-label="Capture statistics">
        <StatTile
          label="Packets"
          value={formatNumber(summary.packets.matched)}
          detail={
            summary.packets.matched !== summary.packets.total
              ? `of ${formatNumber(summary.packets.total)}`
              : undefined
          }
        />
        <StatTile label="Bytes" value={formatBytes(summary.packets.bytes)} />
        <StatTile label="Duration" value={seconds(summary.packets.duration_s)} />
        <StatTile label="Flows" value={formatNumber(summary.flows_total)} />
        <StatTile label="Malformed" value={formatNumber(summary.packets.malformed)} />
      </div>
      <div className="split">
        <Panel title="File">
          <KeyValueList
            entries={[
              ['Name', <span className="break">{summary.file.name}</span>],
              [
                'Upload ID',
                <span className="row">
                  <Mono>{summary.upload.id}</Mono>
                  <CopyButton value={summary.upload.id} label="Copy upload ID" />
                </span>,
              ],
              ['Format', `${summary.file.format}${summary.file.version ? ` ${summary.file.version}` : ''}`],
              ['Link types', summary.file.link_types.join(', ') || '—'],
              ['Size', formatBytes(summary.file.size)],
              ['SHA-256', <Mono title={summary.upload.sha256}>{shortHash(summary.upload.sha256, 24)}</Mono>],
              ['First packet', <Time value={summary.packets.first} />],
              ['Last packet', <Time value={summary.packets.last} />],
            ]}
          />
        </Panel>
        <Panel title="Protocols">
          {summary.protocols.length === 0 ? (
            <p className="muted small">No packets matched.</p>
          ) : (
            <ul className="protocol-bars" aria-label="Packets per protocol">
              {summary.protocols.map((row) => (
                <li key={row.protocol} className="protocol-bars__row">
                  <span className="mono">{row.protocol}</span>
                  <Meter value={row.packets / total} label={`${row.protocol}: ${row.packets} packets`} />
                  <span className="tabular small">
                    {formatNumber(row.packets)} · {formatBytes(row.bytes)}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>
      <Panel
        title={`Flows (${formatNumber(summary.flows.length)} of ${formatNumber(summary.flows_total)})`}
        flush
      >
        <FlowTable flows={summary.flows} onFilterFlow={onFilterFlow} />
      </Panel>
      <Panel title={`DNS (${formatNumber(summary.dns_total)})`} flush>
        <DnsTable rows={summary.dns} />
      </Panel>
      <div className="split">
        <Panel title={`TLS (${formatNumber(summary.tls_total)})`} flush>
          <TlsTable rows={summary.tls} />
        </Panel>
        <Panel title={`HTTP (${formatNumber(summary.http_total)})`} flush>
          <HttpTable rows={summary.http} />
        </Panel>
      </div>
      <p className="small muted">
        Captured text (DNS names, SNI, HTTP paths and user agents) is sanitized by the server and shown as
        text. Encrypted TLS payloads are labelled and counted, never opened.
      </p>
    </div>
  );
}

export function CaptureSummaryView({
  upload,
  filters,
  onFilters,
}: {
  upload: string;
  filters: CaptureFilterState;
  onFilters: (next: CaptureFilterState) => void;
}) {
  const query = useCaptureSummary(upload, {
    protocol: filters.protocol || null,
    host: filters.host.trim() || null,
    port: numberOrNull(filters.port),
    flow: numberOrNull(filters.flow),
    limit: SUMMARY_LIMIT,
  });
  return (
    <div className="stack">
      <Panel flush>
        <FiltersForm key={JSON.stringify(filters)} value={filters} onApply={onFilters} />
      </Panel>
      <QueryView query={query} feature="Protocol" loadingLabel="Reading the capture…">
        {(summary) => (
          <SummaryBody
            summary={summary}
            onFilterFlow={(id) => onFilters({ ...NO_FILTERS, flow: String(id) })}
          />
        )}
      </QueryView>
    </div>
  );
}

// ------------------------------------------------------------------ flows

export function FlowsView({ upload }: { upload: string }) {
  const [sort, setSort] = useState<string>('bytes');
  const query = useCaptureFlows(upload, sort, 500);
  return (
    <Panel
      title="Flows"
      flush
      actions={
        <Select
          aria-label="Sort flows by"
          value={sort}
          options={FLOW_SORTS.map((value) => ({ value, label: `Sort by ${value}` }))}
          onChange={(event) => setSort(event.target.value)}
        />
      }
    >
      <QueryView query={query} feature="Protocol flows">
        {(data) => (
          <>
            <FlowTable flows={data.flows} />
            {data.flows_total > data.flows.length ? (
              <p className="small muted panel__pad">
                Showing {formatNumber(data.flows.length)} of {formatNumber(data.flows_total)} flows.
              </p>
            ) : null}
          </>
        )}
      </QueryView>
    </Panel>
  );
}

// ------------------------------------------------------------------ packet

function FieldsTable({ fields }: { fields: readonly PacketField[] }) {
  if (fields.length === 0) return <p className="small muted">No fields decoded.</p>;
  return (
    <table className="table table--dense packet-fields">
      <thead>
        <tr>
          <th scope="col">Field</th>
          <th scope="col">Value</th>
          <th scope="col">Meaning</th>
        </tr>
      </thead>
      <tbody>
        {fields.map((field, index) => (
          <tr key={`${index}:${field.name}`}>
            <td>
              <span className="mono small">{field.name}</span>
            </td>
            <td>
              <span className="mono small break">{fieldValue(field.value)}</span>
            </td>
            <td>
              <span className="small break">{field.explanation}</span>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/** One decoded layer with its explained fields; nested layers follow. */
export function LayerView({ layer, depth = 0 }: { layer: PacketLayer; depth?: number }) {
  return (
    <section
      className="packet-layer"
      aria-label={`${layer.name} layer`}
      style={{ marginLeft: Math.min(depth, 6) * 12 }}
    >
      <header className="row row--wrap packet-layer__head">
        <strong>{layer.name}</strong>
        {layer.summary ? <span className="mono small break">{layer.summary}</span> : null}
        {layer.malformed ? (
          <Badge tone="bad" title={layer.malformed}>
            MALFORMED
          </Badge>
        ) : null}
      </header>
      {layer.malformed ? (
        <p className="small packet-layer__malformed break">
          <Icon name="warning" size={13} /> {layer.malformed} (fields decoded before the problem are kept)
        </p>
      ) : null}
      <FieldsTable fields={layer.fields} />
      {layer.children.map((child, index) => (
        <LayerView key={`${index}:${child.name}`} layer={child} depth={depth + 1} />
      ))}
    </section>
  );
}

function PacketBody({ packet }: { packet: PacketDetail }) {
  return (
    <div className="stack">
      <KeyValueList
        entries={[
          ['Packet', <span className="tabular">#{packet.number}</span>],
          ['Time', <Time value={packet.timestamp} />],
          [
            'Length',
            `${formatNumber(packet.captured_length)} captured / ${formatNumber(packet.original_length)} on the wire`,
          ],
          ['Link type', packet.link_type ?? '—'],
          ['Flow', packet.flow ? <Mono>{`#${packet.flow_id ?? '?'} ${packet.flow}`}</Mono> : '—'],
          ['Protocols', packet.protocols.join(' / ') || '—'],
          ['Info', <span className="break">{packet.info}</span>],
        ]}
      />
      {packet.malformed.length > 0 ? (
        <Callout tone="warn" title="Malformed">
          <ul className="stack stack--tight">
            {packet.malformed.map((reason, index) => (
              <li key={index} className="break">
                {reason}
              </li>
            ))}
          </ul>
        </Callout>
      ) : null}
      {packet.tree.length > 0 ? (
        <pre className="packet-tree" aria-label="Layer tree">
          {packet.tree.join('\n')}
        </pre>
      ) : null}
      {packet.layers ? (
        <LayerView layer={packet.layers} />
      ) : (
        <p className="muted small">No layer could be decoded.</p>
      )}
    </div>
  );
}

export function PacketView({
  upload,
  packet,
  total,
  onPacket,
}: {
  upload: string;
  packet: number;
  total: number | null;
  onPacket: (n: number) => void;
}) {
  const query = useCapturePacket(upload, packet);
  const [draft, setDraft] = useState(String(packet));
  const max = total ?? Number.MAX_SAFE_INTEGER;
  return (
    <Panel
      title="Packet"
      actions={
        <form
          className="row"
          aria-label="Go to packet"
          onSubmit={(event) => {
            event.preventDefault();
            const n = Number(draft);
            if (Number.isInteger(n) && n >= 1 && n <= max) onPacket(n);
          }}
        >
          <IconButton
            icon="chevronLeft"
            label="Previous packet"
            disabled={packet <= 1}
            onClick={() => onPacket(packet - 1)}
          />
          <label className="sr-only" htmlFor="packet-number">
            Packet number
          </label>
          <TextInput
            id="packet-number"
            className="input--compact packet-number"
            inputMode="numeric"
            value={draft}
            onChange={(event) => setDraft(event.target.value)}
          />
          {total !== null ? <span className="small muted">of {formatNumber(total)}</span> : null}
          <Button size="sm" type="submit">
            Go
          </Button>
          <IconButton
            icon="chevronRight"
            label="Next packet"
            disabled={packet >= max}
            onClick={() => onPacket(packet + 1)}
          />
        </form>
      }
    >
      <QueryView query={query} feature="Protocol packet" loadingLabel="Decoding packet…">
        {(data) => <PacketBody packet={data} />}
      </QueryView>
    </Panel>
  );
}

export function NoCapture() {
  return (
    <EmptyState icon="protocol" title="No capture selected">
      <p>
        Upload a capture above, or open an earlier upload by its ID. Captures are addressed by upload ID only:
        the API never reads a server path.
      </p>
    </EmptyState>
  );
}
