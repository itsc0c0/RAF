import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import type { SecurityObject } from '../../api/types';
import { mockFetch, renderWithApp } from '../../test/utils';
import { InspectorHost } from '../inspector/InspectorHost';
import { GlobalSearch } from './GlobalSearch';

function object(id: string, name: string): SecurityObject {
  return {
    id,
    type: id.split(':')[0]!,
    name,
    created_at: '2026-10-07T11:05:48Z',
    updated_at: '2026-10-07T11:05:48Z',
    first_seen: null,
    last_seen: null,
    valid_from: null,
    valid_to: null,
    source: 'raven-events.jsonl',
    confidence: 0.9,
    confidence_level: 'HIGH',
    tags: [],
    metadata: {},
    observations: 1,
    synthetic: true,
  };
}

function detail(target: SecurityObject) {
  return { object: target, notes: [], activity: null, relationship_count: 0, findings: [], pivots: [] };
}

const WS04 = object('host:ws-04', 'WS-04');
const WS05 = object('host:ws-05', 'WS-05');
const ALICE = object('user:alice', 'alice');

function setup() {
  const api = mockFetch([
    { path: '/search', body: { query: 'ws', objects: [WS04, WS05], incidents: [], findings: [] } },
    { path: '/objects/host:ws-05', body: detail(WS05) },
    { path: '/objects/alice', body: detail(ALICE) },
    { path: /\/relationships$/, body: { object_id: 'x', total: 0, items: [] } },
    { path: /\/provenance$/, body: { object_id: 'x', total: 0, items: [] } },
  ]);
  renderWithApp(
    <>
      <GlobalSearch />
      <InspectorHost />
    </>,
  );
  return api;
}

describe('global search', () => {
  it('focuses on "/", navigates results with arrow keys and opens the inspector on Enter', async () => {
    const user = userEvent.setup();
    setup();
    const input = await screen.findByRole('combobox', { name: 'Search R$F' });
    await screen.findByText('home view');
    await user.keyboard('/');
    expect(input).toHaveFocus();

    await user.type(input, 'ws');
    const options = await screen.findAllByRole('option');
    expect(options).toHaveLength(2);
    expect(options[0]).toHaveAttribute('aria-selected', 'true');
    await user.keyboard('{ArrowDown}');
    expect(screen.getAllByRole('option')[1]).toHaveAttribute('aria-selected', 'true');
    expect(input).toHaveAttribute('aria-activedescendant', screen.getAllByRole('option')[1]!.id);

    await user.keyboard('{Enter}');
    expect(await screen.findByRole('dialog', { name: 'WS-05' })).toBeInTheDocument();
    expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
  });

  it('opens the typed reference directly when Enter beats the search results', async () => {
    const user = userEvent.setup();
    const { calls } = setup();
    const input = await screen.findByRole('combobox', { name: 'Search R$F' });
    await user.type(input, 'alice{Enter}');
    expect(await screen.findByRole('dialog', { name: 'alice' })).toBeInTheDocument();
    await waitFor(() => expect(calls.some((call) => call.path === '/objects/alice')).toBe(true));
  });
});
