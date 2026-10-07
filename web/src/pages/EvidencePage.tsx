import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { isApiError } from '../api/client';
import {
  useCreateCase,
  useEvidenceCase,
  useEvidenceCases,
  useEvidenceItem,
  useVerifyCase,
} from '../api/hooks';
import type { CustodyEntry, EvidenceCase, EvidenceItem, EvidenceVerifyResult } from '../api/types';
import { Badge } from '../components/Badge';
import { Button } from '../components/Button';
import { Chain } from '../components/Chain';
import { CopyButton, KeyValueList, MetadataList, Mono, Time } from '../components/Data';
import { Drawer } from '../components/Drawer';
import { Field, TextInput } from '../components/Form';
import { Icon } from '../components/Icon';
import { ObjectChip } from '../components/ObjectChip';
import { Callout, PageHeader, Panel } from '../components/Panel';
import { EmptyState, isUnavailableError, QueryView, UnavailableState } from '../components/States';
import { Table } from '../components/Table';
import { useToast } from '../components/Toast';
import { formatBytes, formatNumber, shortHash } from '../lib/format';

function itemName(item: EvidenceItem): string {
  return item.name ?? item.filename ?? item.path ?? item.id;
}

function custodyOf(item: EvidenceItem): CustodyEntry[] {
  return item.custody ?? item.chain ?? [];
}

function CreateCaseForm() {
  const [name, setName] = useState('');
  const [title, setTitle] = useState('');
  const create = useCreateCase();
  const { notify } = useToast();
  return (
    <form
      className="stack"
      onSubmit={(event) => {
        event.preventDefault();
        create.mutate(
          { name: name.trim(), title: title.trim() || undefined },
          {
            onSuccess: () => {
              notify({ tone: 'good', title: `Case ${name.trim()} created` });
              setName('');
              setTitle('');
            },
            onError: (error) =>
              notify({
                tone: isApiError(error) && error.isUnavailable ? 'warn' : 'bad',
                title:
                  isApiError(error) && error.isUnavailable
                    ? 'Evidence is not available yet'
                    : 'Could not create case',
                description: isApiError(error) ? error.message : undefined,
              }),
          },
        );
      }}
    >
      <Field label="Case name">
        {(id) => (
          <TextInput
            id={id}
            value={name}
            placeholder="case-2026-001"
            onChange={(e) => setName(e.target.value)}
          />
        )}
      </Field>
      <Field label="Title (optional)">
        {(id) => <TextInput id={id} value={title} onChange={(e) => setTitle(e.target.value)} />}
      </Field>
      <div>
        <Button type="submit" icon="plus" loading={create.isPending} disabled={!name.trim()}>
          Create case
        </Button>
      </div>
    </form>
  );
}

function VerifyResults({ result }: { result: EvidenceVerifyResult }) {
  return (
    <div className="stack stack--tight">
      <Callout
        tone={result.verified ? 'info' : 'bad'}
        title={result.verified ? 'All items verified' : 'Integrity check failed'}
      >
        {result.verified
          ? 'Every item still matches its recorded SHA-256.'
          : 'At least one item no longer matches the hash recorded at acquisition. Treat it as altered until explained.'}
      </Callout>
      <ul className="stack stack--tight">
        {result.items.map((item) => (
          <li key={item.id} className="row row--wrap">
            <Badge tone={item.ok ? 'good' : 'bad'}>{item.ok ? 'OK' : 'MISMATCH'}</Badge>
            <Mono>{item.id}</Mono>
            {!item.ok ? (
              <span className="small mono muted break">
                expected {shortHash(item.expected, 16)} · actual {shortHash(item.actual, 16)}
              </span>
            ) : null}
          </li>
        ))}
      </ul>
    </div>
  );
}

function CaseView({
  name,
  objectFilter,
  onOpenItem,
}: {
  name: string;
  objectFilter: string | null;
  onOpenItem: (id: string) => void;
}) {
  const query = useEvidenceCase(name);
  const verify = useVerifyCase();
  const { notify } = useToast();
  return (
    <QueryView query={query} feature="Evidence case">
      {(evidenceCase) => {
        const allItems = evidenceCase.items ?? [];
        const items = objectFilter
          ? allItems.filter((item) => (item.objects ?? []).includes(objectFilter))
          : allItems;
        return (
          <Panel
            title={`${evidenceCase.name}${evidenceCase.title ? ` — ${evidenceCase.title}` : ''}`}
            actions={
              <Button
                size="sm"
                icon="check"
                loading={verify.isPending}
                onClick={() =>
                  verify.mutate(evidenceCase.name, {
                    onError: (error) =>
                      notify({
                        tone: 'bad',
                        title: 'Verification failed',
                        description: isApiError(error) ? error.message : undefined,
                      }),
                  })
                }
              >
                Verify integrity
              </Button>
            }
          >
            <div className="stack">
              {verify.data ? <VerifyResults result={verify.data} /> : null}
              {objectFilter && items.length !== allItems.length ? (
                <p className="small muted">
                  Showing {items.length} of {allItems.length} items linked to <ObjectChip id={objectFilter} />
                  .
                </p>
              ) : null}
              <Table<EvidenceItem>
                caption="Evidence items"
                rows={items}
                rowKey={(item) => item.id}
                onRowClick={(item) => onOpenItem(item.id)}
                empty={<span className="muted">No items in this case.</span>}
                columns={[
                  {
                    key: 'name',
                    header: 'Item',
                    render: (item) => <span className="break">{itemName(item)}</span>,
                  },
                  {
                    key: 'sha',
                    header: 'SHA-256',
                    render: (item) =>
                      item.sha256 ? (
                        <span className="row">
                          <Mono title={item.sha256}>{shortHash(item.sha256, 16)}</Mono>
                          <CopyButton value={item.sha256} label="Copy SHA-256" />
                        </span>
                      ) : (
                        <span className="muted">—</span>
                      ),
                  },
                  { key: 'size', header: 'Size', align: 'right', render: (item) => formatBytes(item.size) },
                  {
                    key: 'acquired',
                    header: 'Acquired',
                    render: (item) => (
                      <Time value={item.acquired_at ?? item.added_at ?? null} className="small" />
                    ),
                  },
                  {
                    key: 'custody',
                    header: 'Custody',
                    align: 'right',
                    render: (item) => formatNumber(custodyOf(item).length),
                  },
                ]}
              />
            </div>
          </Panel>
        );
      }}
    </QueryView>
  );
}

function ItemDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const query = useEvidenceItem(id);
  return (
    <Drawer
      title={query.data ? itemName(query.data) : 'Evidence item'}
      subtitle="Evidence item"
      onClose={onClose}
    >
      <QueryView query={query} feature="Evidence item">
        {(item) => (
          <div className="stack">
            <KeyValueList
              entries={[
                ['ID', <Mono>{item.id}</Mono>],
                [
                  'SHA-256',
                  item.sha256 ? (
                    <span className="row">
                      <Mono>{item.sha256}</Mono>
                      <CopyButton value={item.sha256} label="Copy SHA-256" />
                    </span>
                  ) : (
                    '—'
                  ),
                ],
                ['Size', formatBytes(item.size)],
                ['Media type', item.media_type ?? '—'],
                ['Acquired', <Time value={item.acquired_at ?? item.added_at ?? null} />],
                ['Case', item.case ?? '—'],
              ]}
            />
            {item.objects && item.objects.length > 0 ? (
              <section className="stack stack--tight">
                <h4>Linked objects</h4>
                <div className="row row--wrap">
                  {item.objects.map((objectId) => (
                    <ObjectChip key={objectId} id={objectId} />
                  ))}
                </div>
              </section>
            ) : null}
            <section className="stack stack--tight">
              <h4>Chain of custody</h4>
              {custodyOf(item).length === 0 ? (
                <p className="muted small">No custody entries recorded.</p>
              ) : (
                <Chain
                  label="Chain of custody"
                  items={custodyOf(item).map((entry, index) => ({
                    key: `${index}`,
                    node: (
                      <div className="stack stack--tight">
                        <span>
                          <strong>{entry.action ?? 'entry'}</strong>{' '}
                          {entry.actor ? <span className="muted">by {entry.actor}</span> : null}
                        </span>
                        <Time value={entry.at ?? entry.timestamp ?? null} className="small" />
                        {entry.note ? <span className="small break">{entry.note}</span> : null}
                        {entry.sha256 ? (
                          <Mono className="small muted">{shortHash(entry.sha256, 20)}</Mono>
                        ) : null}
                      </div>
                    ),
                    link:
                      index < custodyOf(item).length - 1 ? (
                        <span className="small muted">then</span>
                      ) : undefined,
                  }))}
                />
              )}
            </section>
            {item.metadata && Object.keys(item.metadata).length > 0 ? (
              <section className="stack stack--tight">
                <h4>Metadata</h4>
                <MetadataList metadata={item.metadata} />
              </section>
            ) : null}
          </div>
        )}
      </QueryView>
    </Drawer>
  );
}

function caseList(data: unknown): EvidenceCase[] {
  if (Array.isArray(data)) return data as EvidenceCase[];
  if (data && typeof data === 'object' && Array.isArray((data as { items?: unknown }).items)) {
    return (data as { items: EvidenceCase[] }).items;
  }
  return [];
}

export default function EvidencePage() {
  const [params, setParams] = useSearchParams();
  const objectFilter = params.get('object');
  const selectedCase = params.get('case');
  const [openItem, setOpenItem] = useState<string | null>(null);
  const cases = useEvidenceCases();

  const setParam = (key: string, value: string | null) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next);
  };

  const header = <PageHeader title="Evidence" subtitle="Cases, hashed items and chain of custody" />;
  if (isUnavailableError(cases.error)) {
    return (
      <div className="page">
        {header}
        <UnavailableState feature="Evidence" error={cases.error} />
      </div>
    );
  }
  return (
    <div className="page">
      {header}
      {objectFilter ? (
        <Callout tone="info">
          <span className="row row--wrap">
            <Icon name="filter" size={14} /> Evidence linked to <ObjectChip id={objectFilter} />
            <Button size="sm" variant="ghost" onClick={() => setParam('object', null)}>
              Show all
            </Button>
          </span>
        </Callout>
      ) : null}
      <div className="split split--narrow-left">
        <div className="stack">
          <Panel title="Cases" flush>
            <QueryView query={cases} feature="Evidence">
              {(data) => {
                const items = caseList(data);
                return items.length === 0 ? (
                  <div className="panel__pad">
                    <EmptyState title="No cases yet">
                      <p>
                        Create a case below or with <code>raf evidence case create</code>.
                      </p>
                    </EmptyState>
                  </div>
                ) : (
                  <Table<EvidenceCase>
                    caption="Evidence cases"
                    dense
                    rows={items}
                    rowKey={(c) => c.name}
                    selectedKey={selectedCase}
                    onRowClick={(c) => setParam('case', c.name)}
                    columns={[
                      {
                        key: 'name',
                        header: 'Case',
                        render: (c) => <strong className="break">{c.name}</strong>,
                      },
                      {
                        key: 'title',
                        header: 'Title',
                        render: (c) => <span className="break">{c.title ?? '—'}</span>,
                      },
                      {
                        key: 'items',
                        header: 'Items',
                        align: 'right',
                        render: (c) => formatNumber(c.item_count ?? c.items?.length ?? null),
                      },
                    ]}
                  />
                );
              }}
            </QueryView>
          </Panel>
          <Panel title="New case">
            <CreateCaseForm />
          </Panel>
        </div>
        <div>
          {selectedCase ? (
            <CaseView
              key={selectedCase}
              name={selectedCase}
              objectFilter={objectFilter}
              onOpenItem={setOpenItem}
            />
          ) : (
            <Panel>
              <EmptyState icon="evidence" title="Select a case">
                <p>
                  Items show their SHA-256, size and chain of custody; “Verify integrity” re-hashes every
                  item.
                </p>
              </EmptyState>
            </Panel>
          )}
        </div>
      </div>
      {openItem ? <ItemDrawer key={openItem} id={openItem} onClose={() => setOpenItem(null)} /> : null}
    </div>
  );
}
