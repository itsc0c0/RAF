import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { mockFetch, renderWithApp } from '../../test/utils';
import { CommandPaletteHost } from './CommandPalette';

const INCIDENTS = {
  items: [
    {
      id: 'incident:inc-001',
      name: 'INC-001',
      title: 'Suspicious production data access',
      status: 'investigating',
      severity: 'HIGH',
      start: '2026-10-06T22:40:00Z',
      end: '2026-10-06T23:45:00Z',
      description: '',
      source: 'raven-events.jsonl',
      event_count: 37,
      created_at: '2026-10-07T11:05:48Z',
      updated_at: '2026-10-07T11:05:48Z',
    },
  ],
};

function setup() {
  const api = mockFetch([
    { path: '/incidents', body: INCIDENTS },
    { path: '/search', body: { query: '', objects: [], incidents: [], findings: [] } },
  ]);
  const view = renderWithApp(<CommandPaletteHost />, {
    extraRoutes: [
      { path: 'graph', element: <p>graph view</p> },
      { path: 'replay', element: <p>replay view</p> },
    ],
  });
  return { ...view, api };
}

describe('command palette', () => {
  it('opens on Ctrl+K, filters fuzzily and executes the active command', async () => {
    const user = userEvent.setup();
    const { router } = setup();
    await screen.findByText('home view');
    expect(screen.queryByRole('dialog', { name: 'Command palette' })).not.toBeInTheDocument();

    await user.keyboard('{Control>}k{/Control}');
    const dialog = await screen.findByRole('dialog', { name: 'Command palette' });
    const input = within(dialog).getByRole('combobox');
    expect(input).toHaveFocus();

    await user.type(input, 'opn grph');
    const options = within(dialog).getAllByRole('option');
    expect(options[0]).toHaveTextContent('Open Graph');
    expect(options[0]).toHaveAttribute('aria-selected', 'true');
    expect(options.some((option) => option.textContent?.includes('Open Settings'))).toBe(false);

    await user.keyboard('{Enter}');
    await waitFor(() => expect(router.state.location.pathname).toBe('/graph'));
    expect(screen.getByText('graph view')).toBeInTheDocument();
    expect(screen.queryByRole('dialog', { name: 'Command palette' })).not.toBeInTheDocument();
  });

  it('opens on Meta+K (macOS), navigates with arrow keys and closes on Escape', async () => {
    const user = userEvent.setup();
    const { router } = setup();
    await screen.findByText('home view');

    await user.keyboard('{Meta>}k{/Meta}');
    const dialog = await screen.findByRole('dialog', { name: 'Command palette' });
    const input = within(dialog).getByRole('combobox');

    // Incident commands come from GET /incidents.
    await user.type(input, 'replay inc');
    await waitFor(() =>
      expect(within(dialog).getAllByRole('option')[0]).toHaveTextContent('Replay Incident INC-001'),
    );

    await user.clear(input);
    await user.type(input, 'open');
    const before = within(dialog).getAllByRole('option');
    expect(before[0]).toHaveAttribute('aria-selected', 'true');
    await user.keyboard('{ArrowDown}');
    const after = within(dialog).getAllByRole('option');
    expect(after[0]).toHaveAttribute('aria-selected', 'false');
    expect(after[1]).toHaveAttribute('aria-selected', 'true');
    expect(input).toHaveAttribute('aria-activedescendant', after[1]!.id);

    await user.keyboard('{Escape}');
    await waitFor(() =>
      expect(screen.queryByRole('dialog', { name: 'Command palette' })).not.toBeInTheDocument(),
    );
    expect(router.state.location.pathname).toBe('/');
  });

  it('runs the incident replay command and toggles closed with a second Ctrl+K', async () => {
    const user = userEvent.setup();
    const { router } = setup();
    await screen.findByText('home view');

    await user.keyboard('{Control>}k{/Control}');
    await user.keyboard('{Control>}k{/Control}');
    await waitFor(() =>
      expect(screen.queryByRole('dialog', { name: 'Command palette' })).not.toBeInTheDocument(),
    );

    await user.keyboard('{Control>}k{/Control}');
    const dialog = await screen.findByRole('dialog', { name: 'Command palette' });
    await user.type(within(dialog).getByRole('combobox'), 'INC-001 replay');
    await waitFor(() =>
      expect(within(dialog).getAllByRole('option')[0]).toHaveTextContent('Replay Incident INC-001'),
    );
    await user.click(within(dialog).getAllByRole('option')[0]!);
    await waitFor(() => expect(router.state.location.pathname).toBe('/replay'));
    expect(router.state.location.search).toBe('?incident=incident%3Ainc-001');
  });

  it('offers live object results that open the inspector', async () => {
    const user = userEvent.setup();
    mockFetch([
      { path: '/incidents', body: { items: [] } },
      {
        path: '/search',
        body: {
          query: 'ws',
          incidents: [],
          findings: [],
          objects: [
            {
              id: 'host:ws-04',
              type: 'host',
              name: 'WS-04',
              created_at: '2026-10-07T11:05:48Z',
              updated_at: '2026-10-07T11:05:48Z',
              first_seen: null,
              last_seen: null,
              valid_from: null,
              valid_to: null,
              source: 'x',
              confidence: 0.9,
              confidence_level: 'HIGH',
              tags: [],
              metadata: {},
              observations: 1,
              synthetic: true,
            },
          ],
        },
      },
    ]);
    renderWithApp(<CommandPaletteHost />);
    await screen.findByText('home view');
    await user.keyboard('{Control>}k{/Control}');
    const dialog = await screen.findByRole('dialog', { name: 'Command palette' });
    await user.type(within(dialog).getByRole('combobox'), 'ws-04');
    const option = await within(dialog).findByRole('option', { name: /Open WS-04/ });
    expect(option).toHaveTextContent('host:ws-04');
  });
});
