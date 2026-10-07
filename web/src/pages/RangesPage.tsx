import { useState } from 'react';
import { isApiError } from '../api/client';
import { useCreateRange, useRangeAction, useRanges } from '../api/hooks';
import type { RangeInfo } from '../api/types';
import { Button } from '../components/Button';
import { Time } from '../components/Data';
import { Field, TextInput } from '../components/Form';
import { PageHeader, Panel } from '../components/Panel';
import { EmptyState, isUnavailableError, QueryView, UnavailableState } from '../components/States';
import { Table } from '../components/Table';
import { useToast } from '../components/Toast';
import { LifecycleActions, LifecycleState } from '../features/lifecycle/Lifecycle';
import { displayValue } from '../lib/format';

function CreateRangeForm() {
  const [name, setName] = useState('');
  const [preset, setPreset] = useState('');
  const [seed, setSeed] = useState('');
  const create = useCreateRange();
  const { notify } = useToast();
  return (
    <form
      className="filters filters--inline"
      onSubmit={(event) => {
        event.preventDefault();
        const seedNumber = seed.trim() ? Number(seed) : undefined;
        create.mutate(
          {
            name: name.trim(),
            preset: preset.trim() || undefined,
            seed: Number.isFinite(seedNumber) ? seedNumber : undefined,
          },
          {
            onSuccess: () => {
              notify({ tone: 'good', title: `Range ${name.trim()} created` });
              setName('');
            },
            onError: (error) =>
              notify({
                tone: isApiError(error) && error.isUnavailable ? 'warn' : 'bad',
                title:
                  isApiError(error) && error.isUnavailable
                    ? 'Ranges are not available yet'
                    : 'Could not create range',
                description: isApiError(error) ? error.message : undefined,
              }),
          },
        );
      }}
    >
      <Field label="Name">
        {(id) => (
          <TextInput
            id={id}
            value={name}
            placeholder="training-1"
            onChange={(e) => setName(e.target.value)}
          />
        )}
      </Field>
      <Field label="Preset (optional)">
        {(id) => (
          <TextInput
            id={id}
            value={preset}
            placeholder="small-company"
            onChange={(e) => setPreset(e.target.value)}
          />
        )}
      </Field>
      <Field label="Seed (optional)">
        {(id) => (
          <TextInput
            id={id}
            value={seed}
            inputMode="numeric"
            placeholder="42"
            onChange={(e) => setSeed(e.target.value)}
          />
        )}
      </Field>
      <div className="filters__actions">
        <Button
          type="submit"
          icon="plus"
          variant="primary"
          loading={create.isPending}
          disabled={!name.trim()}
        >
          Create range
        </Button>
      </div>
    </form>
  );
}

export default function RangesPage() {
  const ranges = useRanges();
  const action = useRangeAction();
  const header = (
    <PageHeader
      title="Ranges"
      subtitle="Synthetic organizations for training, testing detections and what-if analysis (all data is fictional)"
    />
  );
  if (isUnavailableError(ranges.error)) {
    return (
      <div className="page">
        {header}
        <UnavailableState feature="Ranges" error={ranges.error} />
      </div>
    );
  }
  return (
    <div className="page">
      {header}
      <Panel title="New range">
        <CreateRangeForm />
      </Panel>
      <Panel title="Ranges" flush>
        <QueryView query={ranges} feature="Ranges">
          {(data) =>
            (data.items ?? []).length === 0 ? (
              <div className="panel__pad">
                <EmptyState title="No ranges yet">
                  <p>
                    Create one above or with <code>raf range create &lt;name&gt;</code>.
                  </p>
                </EmptyState>
              </div>
            ) : (
              <Table<RangeInfo>
                caption="Ranges"
                rows={data.items}
                rowKey={(range) => range.name}
                columns={[
                  { key: 'name', header: 'Name', render: (r) => <strong className="break">{r.name}</strong> },
                  {
                    key: 'state',
                    header: 'State',
                    render: (r) => <LifecycleState state={r.status ?? r.state} />,
                  },
                  {
                    key: 'preset',
                    header: 'Preset',
                    render: (r) => <span className="mono small">{r.preset ?? '—'}</span>,
                  },
                  {
                    key: 'seed',
                    header: 'Seed',
                    render: (r) => <span className="mono small">{displayValue(r.seed ?? '—')}</span>,
                  },
                  {
                    key: 'created',
                    header: 'Created',
                    render: (r) => <Time value={r.created_at ?? null} className="small" />,
                  },
                  {
                    key: 'actions',
                    header: 'Lifecycle',
                    render: (r) => (
                      <LifecycleActions
                        name={r.name}
                        kind="range"
                        actions={['start', 'stop', 'reset', 'destroy']}
                        busy={action.isPending}
                        run={(lifecycle) => action.mutateAsync({ name: r.name, action: lifecycle })}
                      />
                    ),
                  },
                ]}
              />
            )
          }
        </QueryView>
      </Panel>
    </div>
  );
}
