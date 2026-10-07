import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import type { GhostModel, GhostOp } from '../../api/types';
import GhostPage from '../../pages/GhostPage';
import { mockFetch, renderWithApp } from '../../test/utils';

const OPERATIONS = {
  items: [
    { op: 'remove-access', argument: 'A:B', effect: 'cut every control path from A to B (minimum-cost cut)' },
    { op: 'isolate', argument: 'HOST', effect: 'remove every network relationship of a host' },
  ],
};

const APPLIED: GhostOp = {
  op: 'remove-access',
  arg: 'alice:production',
  summary: 'cut 3 relationship(s) so that alice no longer controls production',
  explanation: [
    'remove DEV-01 USES svc-deploy (credential exposure): credentials of svc-deploy are present on DEV-01',
    "remove dave LOGGED_INTO DEV-01 (credential exposure): whoever controls DEV-01 may capture dave's session",
  ],
  effects: {
    removed_relationships: ['rel:910696e79ad7101e0385ae67', 'rel:e5c569e4e47b3572ad1594c1'],
    added_relationships: [],
    added_objects: [],
    patched_objects: {},
  },
  applied_at: '2026-10-07T13:14:30.283050Z',
};

function model(ops: GhostOp[]): GhostModel {
  return {
    name: 'exp',
    base_snapshot: 'ghost-exp-base',
    base_label: 'current at 2026-10-07T13:13:18+00:00',
    parent: null,
    description: '',
    created_at: '2026-10-07T13:13:18.657733Z',
    updated_at: '2026-10-07T13:14:30.283133Z',
    ops,
  };
}

describe('Ghost', () => {
  it('applies a what-if operation and shows it in the operations log', async () => {
    const user = userEvent.setup();
    let ops: GhostOp[] = [];
    const { calls } = mockFetch([
      {
        path: '/ghost/models',
        body: () => ({
          items: [
            {
              name: 'exp',
              base_snapshot: 'ghost-exp-base',
              base_label: 'current at 2026-10-07T13:13:18Z',
              parent: null,
              ops_count: ops.length,
              created_at: '2026-10-07T13:13:18.657733Z',
              updated_at: '2026-10-07T13:14:30.283133Z',
              description: '',
            },
          ],
        }),
      },
      { path: '/ghost/models/exp', body: () => model(ops) },
      { path: '/ghost/operations', body: OPERATIONS },
      { path: '/snapshots', body: { items: [] } },
      {
        method: 'POST',
        path: '/ghost/models/exp/ops',
        body: () => {
          ops = [APPLIED];
          return { model: model(ops), applied: [APPLIED] };
        },
      },
    ]);
    renderWithApp(<></>, {
      route: '/ghost?model=exp',
      extraRoutes: [{ path: 'ghost', element: <GhostPage /> }],
    });

    const form = await screen.findByRole('form', { name: 'Apply a what-if operation' });
    expect(
      await screen.findByText('No operations yet: the model equals its base state.'),
    ).toBeInTheDocument();
    await waitFor(() => expect(within(form).getByLabelText('Operation')).toHaveValue('remove-access'));
    expect(
      within(form).getByText('cut every control path from A to B (minimum-cost cut)', { exact: false }),
    ).toBeInTheDocument();

    await user.type(within(form).getByLabelText('Argument'), 'alice:production');
    await user.click(within(form).getByRole('button', { name: 'Apply' }));

    await waitFor(() => expect(calls.some((call) => call.method === 'POST')).toBe(true));
    const post = calls.find((call) => call.method === 'POST')!;
    expect(post.path).toBe('/ghost/models/exp/ops');
    expect(post.body).toEqual({ op: 'remove-access', arg: 'alice:production' });

    // The answer's summary, then the refreshed log with the explanation of every removal.
    expect(await within(form).findByText(APPLIED.summary)).toBeInTheDocument();
    const log = await screen.findByRole('list', { name: 'Operations log' });
    expect(within(log).getByText('alice:production')).toBeInTheDocument();
    expect(within(log).getByText(APPLIED.explanation[1]!)).toBeInTheDocument();
    expect(within(log).getByText(/rel:910696e79ad7101e0385ae67/)).toBeInTheDocument();
  });

  it('compares the model with current and shows metric deltas, assets and users', async () => {
    const user = userEvent.setup();
    const comparison = {
      a: {
        label: 'current',
        metrics: {
          entry_points: 13,
          reachable_assets: 23,
          exposed_critical_assets: 12,
          attack_paths: 135,
          critical_paths: 59,
        },
        levels: { CRITICAL: 6, HIGH: 8, MEDIUM: 8, LOW: 3 },
        user_control: { 'user:alice': 8 },
      },
      b: {
        label: 'ghost:exp',
        metrics: {
          entry_points: 13,
          reachable_assets: 23,
          exposed_critical_assets: 11,
          attack_paths: 115,
          critical_paths: 49,
        },
        levels: { CRITICAL: 5, HIGH: 6, MEDIUM: 11, LOW: 3 },
        user_control: { 'user:alice': 0 },
      },
      delta: {
        entry_points: 0,
        reachable_assets: 0,
        exposed_critical_assets: -1,
        attack_paths: -20,
        critical_paths: -10,
      },
      assets: [
        {
          id: 'host:dev-01',
          name: 'DEV-01',
          before: { score: 62, level: 'HIGH' },
          after: { score: 32, level: 'MEDIUM' },
        },
      ],
      users: [{ id: 'user:alice', name: 'alice', before: 8, after: 0, lost: ['host:db-01'], gained: [] }],
      relationships_removed: 3,
      relationships_added: 0,
    };
    const { calls } = mockFetch([
      { path: '/ghost/models', body: { items: [] } },
      { path: '/ghost/models/exp', body: model([APPLIED]) },
      { path: '/ghost/operations', body: OPERATIONS },
      { path: '/snapshots', body: { items: [] } },
      { path: '/ghost/compare', body: comparison },
    ]);
    renderWithApp(<></>, {
      route: '/ghost?model=exp&view=compare',
      extraRoutes: [{ path: 'ghost', element: <GhostPage /> }],
    });
    const metrics = await screen.findByRole('table', { name: 'Exposure metrics, baseline and experiment' });
    const attack = within(metrics).getByText('Attack paths').closest('tr')!;
    expect(attack).toHaveTextContent('135');
    expect(attack).toHaveTextContent('115');
    expect(within(attack).getByTitle('20 fewer')).toHaveTextContent('−20');
    const compare = calls.find((call) => call.path === '/ghost/compare')!;
    expect(compare.url.searchParams.get('a')).toBe('current');
    expect(compare.url.searchParams.get('b')).toBe('exp');
    expect(screen.getByRole('table', { name: 'Assets whose exposure changed' })).toHaveTextContent('DEV-01');
    const users = screen.getByRole('table', { name: 'Users whose control changed' });
    expect(users).toHaveTextContent('8 → 0');
    expect(within(users).getByTitle('Inspect host:db-01')).toBeInTheDocument();
    await user.click(screen.getByRole('tab', { name: /Operations/ }));
    expect(await screen.findByRole('list', { name: 'Operations log' })).toBeInTheDocument();
  });
});
