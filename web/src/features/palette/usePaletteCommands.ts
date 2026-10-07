import { useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { isApiError } from '../../api/client';
import { useCreateSnapshot, useIncidents, useSearch } from '../../api/hooks';
import { useAnalyze } from '../../app/analyze';
import { NAV_ITEMS } from '../../app/navigation';
import { useInspector, useOracle } from '../../app/shellState';
import { useTheme } from '../../app/theme';
import { useWorkspace } from '../../app/workspace';
import type { IconName } from '../../components/Icon';
import { useToast } from '../../components/Toast';
import { routeTo } from '../../lib/routes';

export interface PromptSpec {
  title: string;
  label: string;
  initial: string;
  submitLabel: string;
  submit: (value: string) => Promise<void>;
}

export interface PaletteCommand {
  id: string;
  group: string;
  label: string;
  detail?: string;
  keywords?: string;
  icon: IconName;
  /** Runs and closes the palette. */
  run?: () => void;
  /** Switches the palette into a one-field form (e.g. snapshot name). */
  prompt?: () => PromptSpec;
}

function defaultSnapshotName(now: Date): string {
  const pad = (n: number) => String(n).padStart(2, '0');
  return `snapshot-${now.getUTCFullYear()}${pad(now.getUTCMonth() + 1)}${pad(now.getUTCDate())}-${pad(
    now.getUTCHours(),
  )}${pad(now.getUTCMinutes())}${pad(now.getUTCSeconds())}`;
}

/** Static commands plus live object results for `liveQuery` (debounced by the caller). */
export function usePaletteCommands(liveQuery: string) {
  const navigate = useNavigate();
  const inspector = useInspector();
  const oracle = useOracle();
  const analyze = useAnalyze();
  const theme = useTheme();
  const workspace = useWorkspace();
  const { notify } = useToast();
  const incidents = useIncidents();
  const createSnapshot = useCreateSnapshot();
  const search = useSearch(liveQuery);
  const { mutateAsync: createSnapshotAsync } = createSnapshot;

  const commands = useMemo<PaletteCommand[]>(() => {
    const list: PaletteCommand[] = NAV_ITEMS.map((item) => ({
      id: `nav:${item.path}`,
      group: 'Navigation',
      label: `Open ${item.label}`,
      detail: item.description,
      keywords: `go ${item.label} ${item.description}`,
      icon: item.icon,
      run: () => void navigate(item.path),
    }));
    list.push(
      {
        id: 'action:snapshot',
        group: 'Actions',
        label: 'Create Snapshot',
        detail: 'Freeze the current workspace state',
        keywords: 'snapshot save state diff',
        icon: 'database',
        prompt: () => ({
          title: 'Create snapshot',
          label: 'Snapshot name',
          initial: defaultSnapshotName(new Date()),
          submitLabel: 'Create',
          submit: async (name) => {
            try {
              await createSnapshotAsync({ name });
              notify({ tone: 'good', title: `Snapshot ${name} created` });
            } catch (error) {
              notify({
                tone: 'bad',
                title: 'Snapshot failed',
                description: isApiError(error)
                  ? [error.message, error.hint].filter(Boolean).join(' ')
                  : undefined,
              });
              throw error;
            }
          },
        }),
      },
      {
        id: 'action:analyze',
        group: 'Actions',
        label: 'Analyze Evidence',
        detail: 'Upload a file for analysis',
        keywords: 'upload import ingest file logs analyze',
        icon: 'upload',
        run: () => analyze.pickFile(),
      },
      {
        id: 'action:oracle',
        group: 'Actions',
        label: 'Ask Oracle',
        detail: 'Questions about this workspace',
        keywords: 'ai assistant question ask',
        icon: 'oracle',
        run: () => oracle.open(),
      },
      {
        id: 'action:theme',
        group: 'Actions',
        label: theme.theme === 'dark' ? 'Switch to Light Theme' : 'Switch to Dark Theme',
        keywords: 'theme dark light appearance',
        icon: theme.theme === 'dark' ? 'sun' : 'moon',
        run: () => theme.toggle(),
      },
      {
        id: 'action:workspace-create',
        group: 'Workspaces',
        label: 'Create Workspace',
        keywords: 'workspace new',
        icon: 'plus',
        prompt: () => ({
          title: 'Create workspace',
          label: 'Workspace name (lowercase letters, digits, - and _)',
          initial: '',
          submitLabel: 'Create',
          submit: async (name) => {
            try {
              await workspace.create(name, '');
              notify({ tone: 'good', title: `Workspace ${name} created` });
            } catch (error) {
              notify({
                tone: 'bad',
                title: 'Could not create workspace',
                description: isApiError(error) ? error.message : undefined,
              });
              throw error;
            }
          },
        }),
      },
    );
    for (const item of workspace.workspaces) {
      if (item.name === workspace.workspace) continue;
      list.push({
        id: `ws:${item.name}`,
        group: 'Workspaces',
        label: `Switch Workspace: ${item.name}`,
        detail: item.description,
        keywords: 'workspace switch use',
        icon: 'database',
        run: () => {
          workspace.switchTo(item.name).then(
            () => notify({ tone: 'good', title: `Workspace ${item.name} selected` }),
            (error: unknown) =>
              notify({
                tone: 'bad',
                title: 'Could not switch workspace',
                description: isApiError(error) ? error.message : undefined,
              }),
          );
        },
      });
    }
    for (const incident of incidents.data?.items ?? []) {
      list.push(
        {
          id: `replay:${incident.id}`,
          group: 'Incidents',
          label: `Replay Incident ${incident.name}`,
          detail: incident.title,
          keywords: `${incident.title} replay incident`,
          icon: 'replay',
          run: () => void navigate(routeTo.replay(incident.id)),
        },
        {
          id: `timeline:${incident.id}`,
          group: 'Incidents',
          label: `Timeline of ${incident.name}`,
          detail: incident.title,
          keywords: `${incident.title} timeline incident events`,
          icon: 'timeline',
          run: () => void navigate(routeTo.timeline(incident.id)),
        },
      );
    }
    return list;
  }, [navigate, analyze, oracle, theme, workspace, notify, incidents.data, createSnapshotAsync]);

  const live = useMemo<PaletteCommand[]>(() => {
    if (!liveQuery.trim() || !search.data) return [];
    const results: PaletteCommand[] = [];
    for (const object of [...search.data.incidents, ...search.data.objects]) {
      results.push({
        id: `object:${object.id}`,
        group: 'Objects',
        label: `Open ${object.name}`,
        detail: `${object.type} · ${object.id}`,
        icon: 'eye',
        run: () => inspector.open(object.id),
      });
    }
    for (const finding of search.data.findings) {
      results.push({
        id: `finding:${finding.id}`,
        group: 'Findings',
        label: `Open finding: ${finding.title}`,
        detail: `${finding.severity} · ${finding.product}`,
        icon: 'findings',
        run: () => void navigate(routeTo.finding(finding.id)),
      });
    }
    return results;
  }, [liveQuery, search.data, inspector, navigate]);

  return { commands, live, liveLoading: search.isFetching };
}
