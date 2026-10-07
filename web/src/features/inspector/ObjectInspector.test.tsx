import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { useInspector } from '../../app/shellState';
import { mockFetch, renderWithApp } from '../../test/utils';
import { InspectorHost } from './InspectorHost';

const MALICIOUS = '<img src=x onerror=alert(1)>';
const SCRIPT = '<script>alert("xss")</script>';

const OBJECT = {
  id: 'host:evil',
  type: 'host',
  name: MALICIOUS,
  created_at: '2026-10-07T11:05:48Z',
  updated_at: '2026-10-07T11:05:48Z',
  first_seen: '2026-10-06T08:14:08Z',
  last_seen: '2026-10-06T18:22:30Z',
  valid_from: null,
  valid_to: null,
  source: '<b>imported.jsonl</b>',
  confidence: 0.42,
  confidence_level: 'LOW',
  tags: ['<i>tag</i>'],
  metadata: {
    criticality: 'critical',
    note: SCRIPT,
    nested: { html: '<a href="javascript:alert(1)">x</a>' },
  },
  observations: 3,
  synthetic: false,
};

const DETAIL = {
  object: OBJECT,
  notes: [],
  activity: { first_event: '2026-10-06T08:14:08Z', last_event: '2026-10-06T18:22:30Z', events: 12 },
  relationship_count: 1,
  findings: [
    {
      id: 'finding:1',
      title: MALICIOUS,
      description: 'd',
      severity: 'HIGH',
      confidence: 0.3,
      confidence_level: 'LOW',
      product: 'iam',
      rule_id: 'r1',
      status: 'OPEN',
      affected_objects: ['host:evil'],
      evidence: [],
      recommendation: '',
      explanation: [],
      created_at: '2026-10-07T11:05:48Z',
      updated_at: '2026-10-07T11:05:48Z',
      tags: [],
      metadata: {},
    },
  ],
  pivots: [
    {
      key: 'G',
      product: 'graph',
      label: 'Graph',
      command: 'raf graph host:evil',
      view: '/graph?focus=host:evil',
    },
    { key: 'Z', product: 'evil', label: 'Exfiltrate', command: '', view: 'javascript:alert(1)' },
    { key: 'Y', product: 'evil', label: 'Offsite', command: '', view: '//evil.example/steal' },
  ],
};

function OpenButton() {
  const { open } = useInspector();
  return (
    <button type="button" onClick={() => open('host:evil')}>
      inspect
    </button>
  );
}

describe('object inspector', () => {
  it('renders hostile names and metadata as literal text, never as markup', async () => {
    const user = userEvent.setup();
    mockFetch([
      { path: '/objects/host:evil', body: DETAIL },
      {
        path: '/objects/host:evil/relationships',
        body: {
          object_id: 'host:evil',
          total: 1,
          items: [
            {
              id: 'rel:1',
              relationship_type: 'LOGGED_INTO',
              source_object: 'user:<img src=y onerror=alert(2)>',
              target_object: 'host:evil',
              timestamp: null,
              first_seen: null,
              last_seen: null,
              valid_from: null,
              valid_to: null,
              confidence: 0.8,
              confidence_level: 'HIGH',
              source: 'x',
              metadata: {},
              observations: 1,
              created_at: '2026-10-07T11:05:48Z',
              updated_at: '2026-10-07T11:05:48Z',
              synthetic: false,
            },
          ],
        },
      },
      {
        path: '/objects/host:evil/provenance',
        body: {
          object_id: 'host:evil',
          total: 1,
          items: [
            {
              subject_id: 'host:evil',
              subject_kind: 'object',
              source: MALICIOUS,
              parser: 'jsonl/1.0',
              record: 'line 1',
              event_id: null,
              observed_at: null,
              evidence_id: null,
              source_sha256: null,
              note: SCRIPT,
            },
          ],
        },
      },
    ]);
    renderWithApp(
      <>
        <OpenButton />
        <InspectorHost />
      </>,
    );
    await user.click(await screen.findByRole('button', { name: 'inspect' }));
    const drawer = await screen.findByRole('dialog', { name: MALICIOUS });

    // The hostile string is displayed verbatim (title, details, finding, provenance)...
    await waitFor(() => expect(within(drawer).getAllByText(MALICIOUS).length).toBeGreaterThanOrEqual(3));
    expect(within(drawer).getAllByText(SCRIPT).length).toBeGreaterThanOrEqual(1);
    expect(within(drawer).getByText('<i>tag</i>')).toBeInTheDocument();
    expect(await within(drawer).findByText('<img src=y onerror=alert(2)>')).toBeInTheDocument();

    // ...and never becomes markup.
    expect(document.querySelector('img')).toBeNull();
    expect(document.querySelector('script')).toBeNull();
    expect(document.querySelector('a[href^="javascript"]')).toBeNull();
    expect(document.querySelector('b, i')).toBeNull();
  });

  it('only offers pivots that resolve to internal routes', async () => {
    const user = userEvent.setup();
    mockFetch([
      { path: '/objects/host:evil', body: DETAIL },
      { path: '/objects/host:evil/relationships', body: { object_id: 'host:evil', total: 0, items: [] } },
      { path: '/objects/host:evil/provenance', body: { object_id: 'host:evil', total: 0, items: [] } },
    ]);
    const { router } = renderWithApp(
      <>
        <OpenButton />
        <InspectorHost />
      </>,
    );
    await user.click(await screen.findByRole('button', { name: 'inspect' }));
    const pivots = await screen.findByRole('navigation', { name: 'Pivot to another view' });
    const buttons = within(pivots).getAllByRole('button');
    expect(buttons.map((button) => button.textContent)).toEqual(['GraphG']);
    await user.click(buttons[0]!);
    await waitFor(() => expect(router.state.location.pathname).toBe('/graph'));
    expect(router.state.location.search).toBe('?focus=host%3Aevil');
  });
});
