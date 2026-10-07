import { useMemo, useState } from 'react';
import { isApiError } from '../api/client';
import { useConfig, useOracleStatus, useVersion } from '../api/hooks';
import type { ConfigEntry, WorkspaceInfo } from '../api/types';
import { useTheme, type Theme } from '../app/theme';
import { useWorkspace } from '../app/workspace';
import { Badge, type Tone } from '../components/Badge';
import { Button } from '../components/Button';
import { KeyValueList, Mono, Time } from '../components/Data';
import { Field, TextInput } from '../components/Form';
import { PageHeader, Panel } from '../components/Panel';
import { QueryView } from '../components/States';
import { Table } from '../components/Table';
import { useToast } from '../components/Toast';
import { displayValue } from '../lib/format';

const ORIGIN_TONES: Record<string, Tone> = {
  default: 'neutral',
  user: 'accent',
  global: 'accent',
  workspace: 'violet',
  env: 'warn',
  environment: 'warn',
  cli: 'good',
  override: 'good',
};

function Appearance() {
  const { theme, setTheme } = useTheme();
  return (
    <Panel title="Appearance">
      <fieldset className="radio-row">
        <legend className="sr-only">Theme</legend>
        {(['dark', 'light'] as Theme[]).map((value) => (
          <label key={value} className="radio">
            <input
              type="radio"
              name="theme"
              value={value}
              checked={theme === value}
              onChange={() => setTheme(value)}
            />
            {value === 'dark' ? 'Dark (default)' : 'Light'}
          </label>
        ))}
      </fieldset>
      <p className="small muted">Stored in this browser only.</p>
    </Panel>
  );
}

function Workspaces() {
  const { workspace, workspaces, serverCurrent, switchTo, create } = useWorkspace();
  const { notify } = useToast();
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [busy, setBusy] = useState(false);
  return (
    <Panel title="Workspaces" flush>
      <Table<WorkspaceInfo>
        caption="Workspaces"
        rows={workspaces}
        rowKey={(item) => item.name}
        selectedKey={workspace}
        columns={[
          {
            key: 'name',
            header: 'Name',
            render: (w) => (
              <span className="row row--wrap">
                <strong>{w.name}</strong>
                {w.name === workspace ? <Badge tone="accent">selected</Badge> : null}
                {w.name === serverCurrent ? (
                  <Badge tone="neutral" outline title="Current for the CLI">
                    CLI current
                  </Badge>
                ) : null}
              </span>
            ),
          },
          {
            key: 'description',
            header: 'Description',
            render: (w) => <span className="break">{w.description || '—'}</span>,
          },
          {
            key: 'created',
            header: 'Created',
            render: (w) => <Time value={w.created_at} className="small" />,
          },
          { key: 'path', header: 'Path', render: (w) => <Mono className="small muted">{w.path}</Mono> },
          {
            key: 'use',
            header: '',
            render: (w) =>
              w.name === workspace ? null : (
                <Button
                  size="sm"
                  onClick={() =>
                    switchTo(w.name).then(
                      () => notify({ tone: 'good', title: `Workspace ${w.name} selected` }),
                      (error: unknown) =>
                        notify({
                          tone: 'bad',
                          title: 'Could not switch',
                          description: isApiError(error) ? error.message : undefined,
                        }),
                    )
                  }
                >
                  Use
                </Button>
              ),
          },
        ]}
      />
      <form
        className="filters filters--inline panel__pad"
        onSubmit={(event) => {
          event.preventDefault();
          setBusy(true);
          create(name.trim(), description.trim()).then(
            () => {
              notify({ tone: 'good', title: `Workspace ${name.trim()} created` });
              setName('');
              setDescription('');
              setBusy(false);
            },
            (error: unknown) => {
              notify({
                tone: 'bad',
                title: 'Could not create workspace',
                description: isApiError(error)
                  ? [error.message, error.hint].filter(Boolean).join(' ')
                  : undefined,
              });
              setBusy(false);
            },
          );
        }}
      >
        <Field label="New workspace" hint="lowercase letters, digits, - and _">
          {(id) => (
            <TextInput
              id={id}
              value={name}
              placeholder="case-2026-001"
              onChange={(e) => setName(e.target.value)}
            />
          )}
        </Field>
        <Field label="Description" className="grow">
          {(id) => <TextInput id={id} value={description} onChange={(e) => setDescription(e.target.value)} />}
        </Field>
        <div className="filters__actions">
          <Button type="submit" icon="plus" loading={busy} disabled={!name.trim()}>
            Create
          </Button>
        </div>
      </form>
    </Panel>
  );
}

function ConfigTable() {
  const query = useConfig();
  const [filter, setFilter] = useState('');
  const text = filter.trim().toLowerCase();
  const rows = useMemo(
    () =>
      (query.data?.items ?? []).filter(
        (entry) =>
          !text || entry.key.toLowerCase().includes(text) || entry.description.toLowerCase().includes(text),
      ),
    [query.data, text],
  );
  return (
    <Panel
      title="Effective configuration"
      flush
      actions={
        <span className="row">
          <label className="sr-only" htmlFor="config-filter">
            Filter settings
          </label>
          <TextInput
            id="config-filter"
            value={filter}
            placeholder="Filter keys"
            onChange={(e) => setFilter(e.target.value)}
          />
        </span>
      }
    >
      <QueryView query={query} feature="Configuration">
        {() => (
          <Table<ConfigEntry>
            caption="Effective configuration (read-only)"
            dense
            rows={rows}
            rowKey={(entry) => entry.key}
            columns={[
              { key: 'key', header: 'Key', render: (e) => <Mono>{e.key}</Mono> },
              {
                key: 'value',
                header: 'Value',
                render: (e) =>
                  e.secret ? (
                    <Badge tone={e.value === 'set' ? 'good' : 'neutral'} outline>
                      secret {displayValue(e.value)}
                    </Badge>
                  ) : (
                    <Mono>{displayValue(e.value)}</Mono>
                  ),
              },
              {
                key: 'origin',
                header: 'Origin',
                render: (e) => (
                  <Badge
                    tone={ORIGIN_TONES[e.origin.toLowerCase()] ?? 'neutral'}
                    outline
                    title="Configuration layer that set this value"
                  >
                    {e.origin}
                  </Badge>
                ),
              },
              {
                key: 'description',
                header: 'Description',
                render: (e) => <span className="small break">{e.description}</span>,
              },
            ]}
          />
        )}
      </QueryView>
      <p className="small muted panel__pad">
        Read-only. Change values with <code>raf config set &lt;key&gt; &lt;value&gt;</code>; secrets are never
        shown.
      </p>
    </Panel>
  );
}

function OracleSettings() {
  const query = useOracleStatus();
  return (
    <Panel title="Oracle (AI assistant)">
      <QueryView query={query} feature="Oracle" compact>
        {(status) => (
          <KeyValueList
            entries={Object.keys(status)
              .sort()
              .map(
                (key) =>
                  [
                    <Mono>{key}</Mono>,
                    <span className="break">{displayValue(status[key])}</span>,
                    key,
                  ] as const,
              )}
          />
        )}
      </QueryView>
      <p className="small muted">API keys are never returned by the API. AI output is not authoritative.</p>
    </Panel>
  );
}

function About() {
  const version = useVersion();
  return (
    <Panel title="About">
      <QueryView query={version} feature="Version" compact>
        {(data) => (
          <KeyValueList
            entries={Object.keys(data)
              .sort()
              .map((key) => [key.replace('_', ' '), <Mono>{data[key]}</Mono>, key] as const)}
          />
        )}
      </QueryView>
    </Panel>
  );
}

export default function SettingsPage() {
  return (
    <div className="page">
      <PageHeader title="Settings" subtitle="Appearance, workspaces, configuration and Oracle" />
      <div className="grid-2">
        <Appearance />
        <About />
      </div>
      <Workspaces />
      <OracleSettings />
      <ConfigTable />
    </div>
  );
}
