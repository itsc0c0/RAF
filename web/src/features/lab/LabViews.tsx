import { useState } from 'react';
import { useConfig, useCreateLab, useLab, useLabAction, useLabs, useLabStatus } from '../../api/hooks';
import type { Lab, LabStatus } from '../../api/types';
import { Badge } from '../../components/Badge';
import { Button, IconButton } from '../../components/Button';
import { CommandList, CopyButton, KeyValueList, Mono, Time } from '../../components/Data';
import { Drawer } from '../../components/Drawer';
import { Checkbox, Field, Select, TextInput } from '../../components/Form';
import { ConfirmDialog } from '../../components/Modal';
import { Callout, Panel } from '../../components/Panel';
import { EmptyState, ErrorState, errorSummary, QueryView } from '../../components/States';
import { Table } from '../../components/Table';
import { useToast } from '../../components/Toast';
import { displayValue, pluralize } from '../../lib/format';
import { LifecycleActions, LifecycleState } from '../lifecycle/Lifecycle';
import {
  EMPTY_LAB_FORM,
  formatCommand,
  LAB_BACKENDS,
  labCreateBody,
  MAX_DESCRIPTION,
  MAX_MOUNTS,
  validateLabForm,
  type LabFormField,
  type LabFormState,
} from './labForm';

export const OUTBOUND_WARNING =
  'The lab gets the container runtime’s default bridge network: it can reach the host’s networks and the internet, without any egress filtering. The choice is fixed for the lab and recorded in the audit log.';

export const ROOT_WARNING =
  'The lab runs as uid 0 inside the container. All capabilities stay dropped and no-new-privileges stays on, but use root only when the experiment needs it.';

export const FORGET_EXPLANATION =
  'Deletes the R$F definition even when the container cannot be removed (container backend unavailable, or an invalid stored definition). An existing container is then left in place.';

/** Commands run in a lab only through the local CLI: the API has deliberately no exec/shell route. */
export function labCliCommands(name: string): string[] {
  return [`raf lab exec ${name} -- ls -la /lab/input`, `raf lab shell ${name}`];
}

export function NoExecNotice({ name }: { name?: string }) {
  return (
    <div className="stack stack--tight">
      <p className="small">
        Commands run through the local CLI: <code>raf lab exec</code> and <code>raf lab shell</code>. The API
        has deliberately no exec or shell route: running commands over HTTP would turn it into a remote
        command execution service.
      </p>
      <CommandList commands={labCliCommands(name ?? '<name>')} label="Lab CLI commands" />
    </div>
  );
}

/** `GET /lab/status`: which backend (Docker/Podman) would run the containers, and whether it answers. */
export function BackendStatus() {
  const status = useLabStatus();
  return (
    <Panel title="Container backend">
      <QueryView query={status} feature="Lab backend status" compact>
        {(data) =>
          data.available ? (
            <div className="stack stack--tight">
              <span className="row row--wrap">
                <Badge tone="good">AVAILABLE</Badge>
                <Mono>{data.backend}</Mono>
                {data.version ? <span className="small muted">version {data.version}</span> : null}
              </span>
              <p className="small muted">Labs can be started and stopped.</p>
            </div>
          ) : (
            <Callout tone="warn" title={`${data.backend} is not available`}>
              <p className="break">{data.reason ?? 'The container backend does not answer.'}</p>
              <p>
                Labs can still be created, listed and destroyed (destroy with “forget” if a container exists);
                start and stop need Docker or Podman with a running daemon.
              </p>
            </Callout>
          )
        }
      </QueryView>
    </Panel>
  );
}

function FieldError({ message }: { message: string | undefined }) {
  if (!message) return null;
  return (
    <p className="field__error" role="alert">
      {message}
    </p>
  );
}

function configValue(items: Array<{ key: string; value: unknown }> | undefined, key: string): string | null {
  const entry = items?.find((item) => item.key === key);
  return entry && entry.value !== null && entry.value !== undefined ? displayValue(entry.value) : null;
}

export function CreateLabForm({ onCreated }: { onCreated?: (lab: Lab) => void }) {
  const [form, setForm] = useState<LabFormState>(EMPTY_LAB_FORM);
  const [problems, setProblems] = useState<Partial<Record<LabFormField, string>>>({});
  const create = useCreateLab();
  const config = useConfig();
  const { notify } = useToast();
  const defaults = config.data?.items;
  const defaultImage = configValue(defaults, 'lab.default_image') ?? 'alpine:3.20';
  const defaultMemory = configValue(defaults, 'lab.memory') ?? '512m';
  const defaultCpus = configValue(defaults, 'lab.cpus') ?? '1';
  const defaultBackend = configValue(defaults, 'lab.backend') ?? 'auto';

  const update = (patch: Partial<LabFormState>) => setForm((current) => ({ ...current, ...patch }));
  const setMount = (index: number, value: string) =>
    update({ mounts: form.mounts.map((mount, i) => (i === index ? value : mount)) });

  return (
    <form
      className="lab-form"
      aria-label="New lab"
      onSubmit={(event) => {
        event.preventDefault();
        const found = validateLabForm(form);
        setProblems(found);
        if (Object.keys(found).length > 0) return;
        create.mutate(labCreateBody(form), {
          onSuccess: (lab) => {
            notify({
              tone: 'good',
              title: `Lab ${lab.name} created`,
              description: 'No container exists until it is started.',
            });
            setForm(EMPTY_LAB_FORM);
            onCreated?.(lab);
          },
        });
      }}
    >
      <div className="lab-form__grid">
        <Field label="Name" hint="2–41 characters: a-z, 0-9 and “-”">
          {(id) => (
            <>
              <TextInput
                id={id}
                value={form.name}
                placeholder="protocol-test"
                aria-invalid={problems.name ? true : undefined}
                onChange={(event) => update({ name: event.target.value })}
              />
              <FieldError message={problems.name} />
            </>
          )}
        </Field>
        <Field label="Image (optional)" hint={`Default: ${defaultImage} (lab.default_image)`}>
          {(id) => (
            <>
              <TextInput
                id={id}
                className="mono"
                value={form.image}
                placeholder={defaultImage}
                onChange={(event) => update({ image: event.target.value })}
              />
              <FieldError message={problems.image} />
            </>
          )}
        </Field>
        <Field label="Memory (optional)" hint={`32m–16g · default ${defaultMemory}`}>
          {(id) => (
            <>
              <TextInput
                id={id}
                value={form.memory}
                placeholder={defaultMemory}
                onChange={(event) => update({ memory: event.target.value })}
              />
              <FieldError message={problems.memory} />
            </>
          )}
        </Field>
        <Field label="CPUs (optional)" hint={`0.1–16 · default ${defaultCpus}`}>
          {(id) => (
            <>
              <TextInput
                id={id}
                inputMode="decimal"
                value={form.cpus}
                placeholder={defaultCpus}
                onChange={(event) => update({ cpus: event.target.value })}
              />
              <FieldError message={problems.cpus} />
            </>
          )}
        </Field>
        <Field label="Backend">
          {(id) => (
            <Select
              id={id}
              value={form.backend}
              options={[
                { value: '', label: `Default (${defaultBackend})` },
                ...LAB_BACKENDS.map((value) => ({ value, label: value })),
              ]}
              onChange={(event) => update({ backend: event.target.value })}
            />
          )}
        </Field>
        <Field label="Description (optional)" className="lab-form__wide">
          {(id) => (
            <>
              <TextInput
                id={id}
                value={form.description}
                maxLength={MAX_DESCRIPTION}
                placeholder="What this lab is for"
                onChange={(event) => update({ description: event.target.value })}
              />
              <FieldError message={problems.description} />
            </>
          )}
        </Field>
      </div>

      <fieldset className="lab-form__mounts">
        <legend className="field__label">
          Read-only mounts ({form.mounts.length}/{MAX_MOUNTS})
        </legend>
        <p className="field__hint">
          Absolute paths on the R$F server, mounted read-only at <code>/lab/input/&lt;name&gt;</code>. The
          server refuses sensitive locations (system directories, credential stores, the R$F home) and
          directories containing sockets or device files.
        </p>
        {form.mounts.map((mount, index) => (
          <div key={index} className="row">
            <label className="sr-only" htmlFor={`lab-mount-${index}`}>
              Mount path {index + 1}
            </label>
            <TextInput
              id={`lab-mount-${index}`}
              className="mono grow"
              value={mount}
              placeholder="/srv/samples"
              onChange={(event) => setMount(index, event.target.value)}
            />
            <IconButton
              icon="close"
              label={`Remove mount ${index + 1}`}
              onClick={() => update({ mounts: form.mounts.filter((_, i) => i !== index) })}
            />
          </div>
        ))}
        <FieldError message={problems.mounts} />
        <div>
          <Button
            size="sm"
            icon="plus"
            disabled={form.mounts.length >= MAX_MOUNTS}
            onClick={() => update({ mounts: [...form.mounts, ''] })}
          >
            Add mount
          </Button>
        </div>
      </fieldset>

      <div className="lab-form__flags">
        <Checkbox
          label="Allow outbound network access"
          checked={form.allowOutbound}
          onChange={(allowOutbound) => update({ allowOutbound })}
        />
        {form.allowOutbound ? (
          <Callout tone="warn" title="Outbound network access">
            {OUTBOUND_WARNING}
          </Callout>
        ) : (
          <p className="small muted">No network by default (only loopback inside the lab).</p>
        )}
        <Checkbox
          label="Run as root inside the container"
          checked={form.root}
          onChange={(root) => update({ root })}
        />
        {form.root ? (
          <Callout tone="warn" title="Root inside the lab">
            {ROOT_WARNING}
          </Callout>
        ) : (
          <p className="small muted">Runs as the unprivileged user 1000:1000 by default.</p>
        )}
      </div>

      {create.isError ? <ErrorState title="The lab was not created" error={create.error} compact /> : null}

      <div className="row">
        <Button
          type="submit"
          variant="primary"
          icon="plus"
          loading={create.isPending}
          disabled={!form.name.trim()}
        >
          Create lab
        </Button>
        <span className="small muted">
          Creating only records the definition; the container is created on start.
        </span>
      </div>
    </form>
  );
}

function NetworkBadge({ lab }: { lab: Lab }) {
  return lab.allow_outbound ? (
    <Badge tone="warn" title="Bridge network: can reach the host's networks and the internet">
      OUTBOUND
    </Badge>
  ) : (
    <Badge tone="neutral" outline title="No network interface except loopback">
      ISOLATED
    </Badge>
  );
}

function UserBadge({ lab }: { lab: Lab }) {
  return (
    <span className="row">
      <Mono className="small">{lab.user}</Mono>
      {lab.root ? (
        <Badge tone="warn" title={ROOT_WARNING}>
          ROOT
        </Badge>
      ) : null}
    </span>
  );
}

function resources(lab: Lab): string {
  return `${lab.memory} · ${lab.cpus} CPU · ${lab.pids_limit} pids`;
}

/** Why start/stop cannot run (backend known to be down for this lab), or undefined. */
function backendDown(lab: Lab, status: LabStatus | undefined): string | undefined {
  if (!status || status.available) return undefined;
  if (lab.backend !== 'auto' && lab.backend !== status.backend) return undefined;
  return `Container backend ${status.backend} is not available`;
}

function LabLifecycle({ lab, onDestroyed }: { lab: Lab; onDestroyed?: () => void }) {
  const action = useLabAction();
  const status = useLabStatus();
  const down = backendDown(lab, status.data);
  return (
    <LifecycleActions
      name={lab.name}
      kind="lab"
      actions={['start', 'stop', 'destroy'] as const}
      busy={action.isPending}
      disabled={down ? { start: down, stop: down } : undefined}
      forgetOption={FORGET_EXPLANATION}
      run={(lifecycle, options) =>
        action.mutateAsync({ name: lab.name, action: lifecycle, forget: options.forget }).then((result) => {
          if (lifecycle === 'destroy') onDestroyed?.();
          return result;
        })
      }
    />
  );
}

function StateCell({ lab }: { lab: Lab }) {
  return (
    <span className="stack stack--tight">
      <span className="row row--wrap">
        <LifecycleState state={lab.state} />
        <span
          className="small muted"
          title={lab.live ? 'Observed from the container backend just now' : 'Last state R$F recorded'}
        >
          {lab.live ? 'live' : 'recorded'}
        </span>
      </span>
      {lab.note ? <span className="small muted break">{lab.note}</span> : null}
    </span>
  );
}

function InvalidDefinitions({ names }: { names: readonly string[] }) {
  const [pending, setPending] = useState<string | null>(null);
  const action = useLabAction();
  const { notify } = useToast();
  return (
    <Callout tone="bad" title={`${pluralize(names.length, 'stored definition')} failed validation`}>
      <p>
        R$F refuses to use these labs (for example an edited, unsafe definition). They can only be removed:
        forgetting deletes the definition and leaves any container in place.
      </p>
      <ul className="row row--wrap">
        {names.map((name) => (
          <li key={name} className="row">
            <Mono>{name}</Mono>
            <Button size="sm" variant="danger" icon="trash" onClick={() => setPending(name)}>
              Forget
            </Button>
          </li>
        ))}
      </ul>
      {pending ? (
        <ConfirmDialog
          title={`Forget lab “${pending}”?`}
          danger
          confirmLabel="Forget definition"
          requireText={pending}
          busy={action.isPending}
          onCancel={() => setPending(null)}
          onConfirm={() => {
            const name = pending;
            action.mutateAsync({ name, action: 'destroy', forget: true }).then(
              () => {
                notify({ tone: 'good', title: `Definition of lab ${name} removed` });
                setPending(null);
              },
              (error: unknown) => {
                notify({ tone: 'bad', title: 'Could not forget the lab', description: errorSummary(error) });
                setPending(null);
              },
            );
          }}
        >
          <p>{FORGET_EXPLANATION}</p>
        </ConfirmDialog>
      ) : null}
    </Callout>
  );
}

export function LabTable({ selected, onOpen }: { selected: string | null; onOpen: (name: string) => void }) {
  const labs = useLabs();
  return (
    <QueryView query={labs} feature="Labs">
      {(data) => (
        <div className="stack">
          {data.invalid && data.invalid.length > 0 ? (
            <div className="panel__pad">
              <InvalidDefinitions names={data.invalid} />
            </div>
          ) : null}
          {data.items.length === 0 ? (
            <div className="panel__pad">
              <EmptyState title="No labs yet">
                <p>
                  Create one above or with <code>raf lab create &lt;name&gt;</code>.
                </p>
              </EmptyState>
            </div>
          ) : (
            <Table<Lab>
              caption="Labs"
              rows={data.items}
              rowKey={(lab) => lab.name}
              selectedKey={selected}
              onRowClick={(lab) => onOpen(lab.name)}
              rowLabel={(lab) => `Open lab ${lab.name}`}
              columns={[
                {
                  key: 'name',
                  header: 'Lab',
                  render: (l) => (
                    <span className="stack stack--tight">
                      <strong className="break">{l.name}</strong>
                      {l.description ? <span className="small muted break">{l.description}</span> : null}
                    </span>
                  ),
                },
                { key: 'state', header: 'State', render: (l) => <StateCell lab={l} /> },
                { key: 'image', header: 'Image', render: (l) => <Mono className="small">{l.image}</Mono> },
                { key: 'network', header: 'Network', render: (l) => <NetworkBadge lab={l} /> },
                {
                  key: 'mounts',
                  header: 'Mounts',
                  align: 'right',
                  render: (l) => (
                    <span title={l.mounts.map((m) => `${m.source} → ${m.target} (read-only)`).join('\n')}>
                      {l.mounts.length}
                    </span>
                  ),
                },
                {
                  key: 'resources',
                  header: 'Resources',
                  render: (l) => <span className="small">{resources(l)}</span>,
                },
                { key: 'user', header: 'User', render: (l) => <UserBadge lab={l} /> },
                { key: 'actions', header: 'Lifecycle', render: (l) => <LabLifecycle lab={l} /> },
              ]}
            />
          )}
        </div>
      )}
    </QueryView>
  );
}

function LabDetail({ lab, onDestroyed }: { lab: Lab; onDestroyed: () => void }) {
  const command = lab.container_args ? formatCommand(lab.container_args) : null;
  return (
    <div className="stack">
      <div className="row row--wrap">
        <LifecycleState state={lab.state} />
        <NetworkBadge lab={lab} />
        {lab.root ? <Badge tone="warn">ROOT</Badge> : null}
        <span className="small muted">{lab.live ? 'live state' : 'last recorded state'}</span>
      </div>
      {lab.note ? (
        <Callout tone="info" title="Note">
          <span className="break">{lab.note}</span>
        </Callout>
      ) : null}
      {lab.allow_outbound ? (
        <Callout tone="warn" title="Outbound network access">
          {OUTBOUND_WARNING}
        </Callout>
      ) : null}
      {lab.description ? <p className="break">{lab.description}</p> : null}
      <KeyValueList
        entries={[
          ['Image', <Mono>{lab.image}</Mono>],
          ['Network', <Mono>{lab.network}</Mono>],
          ['User', <UserBadge lab={lab} />],
          ['Memory', lab.memory],
          ['CPUs', lab.cpus],
          ['Process limit', String(lab.pids_limit)],
          ['Backend', <Mono>{lab.backend}</Mono>],
          ['Container', <Mono>{lab.container}</Mono>],
          ['Container ID', lab.container_id ? <Mono>{lab.container_id}</Mono> : '—'],
          ['Created', <Time value={lab.created_at} />],
          ['Updated', <Time value={lab.updated_at} />],
          ['State recorded', <Time value={lab.state_at} />],
        ]}
      />
      <section className="stack stack--tight">
        <h4>Mounts (read-only)</h4>
        {lab.mounts.length === 0 ? (
          <p className="small muted">No host files are mounted.</p>
        ) : (
          <ul className="stack stack--tight">
            {lab.mounts.map((mount) => (
              <li key={mount.target} className="lab-mount">
                <Mono className="small">{mount.source}</Mono>
                <span aria-hidden="true">→</span>
                <Mono className="small">{mount.target}</Mono>
                <Badge tone="neutral" outline>
                  {mount.read_only ? 'READ-ONLY' : 'READ-WRITE'}
                </Badge>
              </li>
            ))}
          </ul>
        )}
      </section>
      {command ? (
        <section className="stack stack--tight">
          <div className="row row--between">
            <h4>Container command</h4>
            <CopyButton value={command} label="Copy container command" />
          </div>
          <p className="small muted">
            The exact arguments R$F uses to create the container (secure defaults: no capabilities, read-only
            root filesystem, no new privileges, resource limits).
          </p>
          <pre className="lab-command">{command}</pre>
        </section>
      ) : null}
      <section className="stack stack--tight">
        <h4>Running commands</h4>
        <NoExecNotice name={lab.name} />
      </section>
      <section className="stack stack--tight">
        <h4>Lifecycle</h4>
        <LabLifecycle lab={lab} onDestroyed={onDestroyed} />
      </section>
    </div>
  );
}

export function LabDrawer({ name, onClose }: { name: string; onClose: () => void }) {
  const query = useLab(name);
  return (
    <Drawer
      title={<span className="break">{name}</span>}
      subtitle="Lab"
      onClose={onClose}
      closeLabel="Close lab"
    >
      <QueryView query={query} feature="Lab" loadingLabel="Loading lab…">
        {(lab) => <LabDetail lab={lab} onDestroyed={onClose} />}
      </QueryView>
    </Drawer>
  );
}
