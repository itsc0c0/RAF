import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import DiffPage from '../../pages/DiffPage';
import { mockFetch, renderWithApp } from '../../test/utils';

const SNAPSHOTS = {
  items: [
    {
      id: 'snapshot:a',
      name: 'a',
      source: 'workspace',
      description: '',
      created_at: '2026-10-07T13:13:19.568063Z',
      stats: { objects: 387, relationships: 772, findings: 29 },
      content_hash: '636102bcb67af401a56212ff4501bf1c8d34f9d4741bbe5e5b933823d218f03b',
    },
  ],
};

/** Shape of GET /diff observed from `raf serve` (a snapshot vs. a Ghost model saved as a snapshot). */
const DIFF = {
  a: 'a',
  b: 'current',
  generated_at: '2026-10-07T13:14:21.596585Z',
  summary: {
    privileges: { added: 1, removed: 1, changed: 0 },
    objects: { added: 0, removed: 0, changed: 1 },
  },
  importance: { HIGH: 1, MEDIUM: 0, LOW: 2 },
  totals: { objects_a: 387, objects_b: 387, relationships_a: 772, relationships_b: 772, changes: 3 },
  changes: [
    {
      category: 'privileges',
      change: 'added',
      item_kind: 'relationship',
      item_id: 'rel:1',
      label: 'dave -ADMIN_OF-> DB-01',
      importance: 'HIGH',
      reason: 'administrative rights granted',
      details: { type: 'ADMIN_OF', source: 'user:dave', target: 'host:db-01' },
    },
    {
      category: 'privileges',
      change: 'removed',
      item_kind: 'relationship',
      item_id: 'rel:910696e79ad7101e0385ae67',
      label: 'DEV-01 -USES-> svc-deploy',
      importance: 'LOW',
      reason: 'USES removed (privilege reduced)',
      details: { type: 'USES', source: 'host:dev-01', target: 'identity:svc-deploy' },
    },
    {
      category: 'objects',
      change: 'changed',
      item_kind: 'object',
      item_id: 'cloud_resource:backup-vault',
      label: 'backup-vault (cloud_resource)',
      importance: 'LOW',
      reason: 'metadata changed: synthetic',
      details: { fields: { synthetic: { from: true, to: false } } },
    },
  ],
  truncated: false,
};

describe('Snapshots & Diff', () => {
  it('renders the summary by category, importance counts and every change with its reason', async () => {
    const user = userEvent.setup();
    const { calls } = mockFetch([
      { path: '/snapshots', body: SNAPSHOTS },
      { path: '/diff', body: DIFF },
    ]);
    const { router } = renderWithApp(<></>, {
      route: '/diff?a=a&b=current',
      extraRoutes: [{ path: 'diff', element: <DiffPage /> }],
    });

    const changes = await screen.findByRole('table', { name: 'Changes' });
    const rows = within(changes).getAllByRole('row').slice(1);
    expect(rows).toHaveLength(3);
    expect(rows[0]).toHaveTextContent('added');
    expect(rows[0]).toHaveTextContent('HIGH');
    expect(rows[0]).toHaveTextContent('dave -ADMIN_OF-> DB-01');
    expect(rows[0]).toHaveTextContent('administrative rights granted');
    expect(within(rows[0]!).getByTitle('Inspect user:dave')).toBeInTheDocument();
    expect(rows[1]).toHaveTextContent('removed');
    expect(rows[1]).toHaveTextContent('USES removed (privilege reduced)');
    expect(rows[2]).toHaveTextContent('synthetic: true → false');

    const counts = screen.getByRole('list', { name: 'Changes by importance' });
    expect(counts).toHaveTextContent('HIGH1');
    expect(counts).toHaveTextContent('LOW2');

    const diffCall = calls.find((call) => call.path === '/diff')!;
    expect(diffCall.url.searchParams.get('a')).toBe('a');
    expect(diffCall.url.searchParams.get('b')).toBe('current');
    expect(diffCall.url.searchParams.get('limit')).toBe('500');

    // A category row narrows the list (deep-linkable).
    const categories = screen.getByRole('table', { name: 'Changes by category' });
    await user.click(within(categories).getByText('privileges'));
    await waitFor(() =>
      expect(new URLSearchParams(router.state.location.search).get('category')).toBe('privileges'),
    );
    await waitFor(() =>
      expect(
        calls.some((call) => call.path === '/diff' && call.url.searchParams.get('category') === 'privileges'),
      ).toBe(true),
    );
  });

  it('offers current, every snapshot and every Ghost model for comparison', async () => {
    const user = userEvent.setup();
    mockFetch([
      { path: '/snapshots', body: SNAPSHOTS },
      {
        path: '/ghost/models',
        body: {
          items: [
            {
              name: 'exp',
              base_snapshot: 'ghost-exp-base',
              base_label: 'current at 2026-10-07T13:13:18Z',
              parent: null,
              ops_count: 1,
              created_at: '2026-10-07T13:13:18Z',
              updated_at: '2026-10-07T13:14:30Z',
              description: '',
            },
          ],
        },
      },
    ]);
    const { router } = renderWithApp(<></>, {
      route: '/diff',
      extraRoutes: [{ path: 'diff', element: <DiffPage /> }],
    });
    expect(await screen.findByText('Choose two states to compare')).toBeInTheDocument();
    // The form starts over once the snapshot list has loaded (latest snapshot as A).
    await waitFor(() => expect(screen.getByLabelText('A (before)')).toHaveValue('a'));
    const form = screen.getByRole('form', { name: 'Compare security states' });
    expect(within(form).getByLabelText('B (after)')).toHaveValue('current');
    expect(await within(form).findAllByRole('option', { name: 'ghost:exp (what-if model)' })).toHaveLength(2);
    await user.click(within(form).getByRole('button', { name: 'Compare' }));
    await waitFor(() => expect(router.state.location.search).toBe('?a=a&b=current'));
  });
});
