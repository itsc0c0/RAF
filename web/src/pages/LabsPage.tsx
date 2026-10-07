import { useState } from 'react';
import { isApiError } from '../api/client';
import { useCreateLab, useLabAction, useLabs, useLabStatus } from '../api/hooks';
import type { LabInfo } from '../api/types';
import { Badge } from '../components/Badge';
import { Button } from '../components/Button';
import { Time } from '../components/Data';
import { Field, TextInput } from '../components/Form';
import { Callout, PageHeader, Panel } from '../components/Panel';
import { EmptyState, isUnavailableError, QueryView, UnavailableState } from '../components/States';
import { Table } from '../components/Table';
import { useToast } from '../components/Toast';
import { LifecycleActions, LifecycleState } from '../features/lifecycle/Lifecycle';

function BackendStatus() {
  const status = useLabStatus();
  return (
    <QueryView query={status} feature="Lab backend" compact>
      {(data) =>
        data.available ? (
          <Callout tone="info" title="Lab backend available">
            <span className="row row--wrap">
              <Badge tone="good">AVAILABLE</Badge>
              <span className="mono">{data.backend}</span>
            </span>
          </Callout>
        ) : (
          <Callout tone="warn" title="Lab backend unavailable">
            <span className="row row--wrap">
              <Badge tone="bad" outline>
                UNAVAILABLE
              </Badge>
              <span className="mono">{data.backend}</span>
              {data.reason ? <span className="break">{data.reason}</span> : null}
            </span>
          </Callout>
        )
      }
    </QueryView>
  );
}

function CreateLabForm({ disabled }: { disabled: boolean }) {
  const [name, setName] = useState('');
  const [template, setTemplate] = useState('');
  const create = useCreateLab();
  const { notify } = useToast();
  return (
    <form
      className="filters filters--inline"
      onSubmit={(event) => {
        event.preventDefault();
        create.mutate(
          { name: name.trim(), template: template.trim() || undefined },
          {
            onSuccess: () => {
              notify({ tone: 'good', title: `Lab ${name.trim()} created` });
              setName('');
            },
            onError: (error) =>
              notify({
                tone: 'bad',
                title: 'Could not create lab',
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
            placeholder="phishing-lab"
            onChange={(e) => setName(e.target.value)}
          />
        )}
      </Field>
      <Field label="Template (optional)">
        {(id) => <TextInput id={id} value={template} onChange={(e) => setTemplate(e.target.value)} />}
      </Field>
      <div className="filters__actions">
        <Button
          type="submit"
          variant="primary"
          icon="plus"
          loading={create.isPending}
          disabled={disabled || !name.trim()}
        >
          Create lab
        </Button>
      </div>
    </form>
  );
}

export default function LabsPage() {
  const status = useLabStatus();
  const labs = useLabs();
  const action = useLabAction();
  const backendDown = status.data ? !status.data.available : false;
  const header = (
    <PageHeader
      title="Labs"
      subtitle="Isolated lab environments (containers); nothing touches production systems"
    />
  );
  if (isUnavailableError(labs.error) && (status.isError || !status.data)) {
    return (
      <div className="page">
        {header}
        <UnavailableState feature="Labs" error={labs.error} />
      </div>
    );
  }
  return (
    <div className="page">
      {header}
      <BackendStatus />
      <Panel title="New lab">
        <CreateLabForm disabled={backendDown} />
      </Panel>
      <Panel title="Labs" flush>
        <QueryView query={labs} feature="Labs">
          {(data) =>
            (data.items ?? []).length === 0 ? (
              <div className="panel__pad">
                <EmptyState title="No labs yet">
                  <p>
                    Create one above or with <code>raf lab create &lt;name&gt;</code>.
                  </p>
                </EmptyState>
              </div>
            ) : (
              <Table<LabInfo>
                caption="Labs"
                rows={data.items}
                rowKey={(lab) => lab.name}
                columns={[
                  { key: 'name', header: 'Name', render: (l) => <strong className="break">{l.name}</strong> },
                  {
                    key: 'state',
                    header: 'State',
                    render: (l) => <LifecycleState state={l.status ?? l.state} />,
                  },
                  {
                    key: 'backend',
                    header: 'Backend',
                    render: (l) => <span className="mono small">{l.backend ?? '—'}</span>,
                  },
                  {
                    key: 'template',
                    header: 'Template',
                    render: (l) => <span className="mono small">{l.template ?? '—'}</span>,
                  },
                  {
                    key: 'created',
                    header: 'Created',
                    render: (l) => <Time value={l.created_at ?? null} className="small" />,
                  },
                  {
                    key: 'actions',
                    header: 'Lifecycle',
                    render: (l) => (
                      <LifecycleActions
                        name={l.name}
                        kind="lab"
                        actions={['start', 'stop', 'destroy']}
                        busy={action.isPending}
                        run={(lifecycle) => action.mutateAsync({ name: l.name, action: lifecycle })}
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
