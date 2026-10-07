import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import AnalysesPage from '../../pages/AnalysesPage';
import { mockFetch, renderWithApp } from '../../test/utils';
import { displaySuggestions } from './analysisModel';

/** Shape of GET /analyses/{id} observed from `raf serve` (pcap upload, --no-correlate). */
const RECORD = {
  id: 'analysis-2',
  input: 'raven-inc001.pcap',
  input_sha256: '6ff14b609e7cbb28010e696a45c1da5bac10dc2785b4f527ecbd898517f1216c',
  detected_type: 'pcap',
  status: 'completed',
  steps: [
    {
      name: 'Detect',
      product: null,
      status: 'ok',
      detail: 'PCAP: libpcap/pcapng magic number',
      duration_ms: 0,
      stats: {},
    },
    {
      name: 'Protocol',
      product: 'protocol',
      status: 'ok',
      detail: '9 of 9 records accepted (pcap/1.0 + raf-native/1.0); 4 flows, 2 dns.query',
      duration_ms: 41.1,
      stats: { job: 'job-5', accepted: 9, flows: 4, event_types: { 'network.flow': 4, 'dns.query': 2 } },
    },
    {
      name: 'IAM analysis',
      product: 'iam',
      status: 'skipped',
      detail: 'correlation disabled (--no-correlate)',
      duration_ms: 0,
      stats: {},
    },
    {
      name: 'Findings',
      product: null,
      status: 'failed',
      detail: 'the findings store is <b>locked</b>',
      duration_ms: 1500,
      stats: { high_or_critical: ['host:app-01', 'service:vpn'] },
    },
  ],
  stats: {
    scope_source: 'raven-inc001.pcap',
    flows: 4,
    events: 0,
    objects: 0,
    relationships: 0,
    findings: 0,
    job_ids: ['job-5', 'job-2'],
    incidents: ['incident:inc-001'],
    detected_label: 'PCAP',
    input_name: 'raven-inc001.pcap',
  },
  suggestions: [
    'raf lens analysis-2',
    'raf protocol inspect /srv/raf/workspaces/default/uploads/analyze/6ff14b609e7cbb28010e696a45c1da5b.pcap',
  ],
  job_id: 'job-5',
  created_at: '2026-10-07T13:13:52.959239Z',
  job_ids: ['job-5', 'job-2'],
};

describe('Analyses', () => {
  it('shows the detected type and every executed step with status, detail, duration and stats', async () => {
    const user = userEvent.setup();
    mockFetch([
      { path: '/analyses', body: { items: [RECORD], total: 1 } },
      { path: '/analyses/analysis-2', body: RECORD },
    ]);
    const { router } = renderWithApp(<></>, {
      route: '/analyses?analysis=analysis-2',
      extraRoutes: [{ path: 'analyses', element: <AnalysesPage /> }],
    });

    const steps = await screen.findByRole('list', { name: 'Analysis steps' });
    const items = within(steps).getAllByRole('listitem');
    expect(items).toHaveLength(4);
    expect(items[1]).toHaveTextContent('Protocol');
    expect(items[1]).toHaveTextContent('ok');
    expect(items[1]).toHaveTextContent('41 ms');
    expect(items[1]).toHaveTextContent('4 flows, 2 dns.query');
    expect(items[2]).toHaveTextContent('skipped');
    expect(items[2]).toHaveTextContent('correlation disabled (--no-correlate)');
    expect(items[3]).toHaveTextContent('failed');
    expect(items[3]).toHaveTextContent('1.5 s');
    // Step details are untrusted text: never markup.
    expect(within(items[3]!).getByText('the findings store is <b>locked</b>')).toBeInTheDocument();
    expect(document.querySelector('.step b')).toBeNull();
    // Step statistics (object IDs become inspector chips).
    expect(within(items[1]!).getByText('flows')).toBeInTheDocument();
    expect(within(items[3]!).getByTitle('Inspect host:app-01')).toBeInTheDocument();

    const detail = screen.getByRole('region', { name: 'analysis-2' });
    expect(detail).toHaveTextContent('PCAP');
    expect(detail).toHaveTextContent('raven-inc001.pcap');
    expect(detail).toHaveTextContent('job-5, job-2');

    // Server paths in suggestions are never shown.
    expect(screen.getByText('raf protocol inspect raven-inc001.pcap').tagName).toBe('CODE');
    expect(document.body.textContent).not.toContain('/srv/raf/workspaces');

    // Explore pivots are scoped to the analysis.
    const explore = screen.getByRole('navigation', { name: 'Explore analysis-2' });
    await user.click(within(explore).getByRole('button', { name: 'Graph' }));
    await waitFor(() => expect(router.state.location.pathname).toBe('/graph'));
    expect(router.state.location.search).toBe('?focus=analysis-2');
  });

  it('uploads a file with the incident and correlate fields and opens the result', async () => {
    const user = userEvent.setup();
    const created = { ...RECORD, id: 'analysis-3' };
    const { calls } = mockFetch([
      { path: '/analyses', body: { items: [], total: 0 } },
      { path: '/analyses/analysis-3', body: created },
      { path: '/products', body: { items: [] } },
      { path: '/config', body: { items: [] } },
      { method: 'POST', path: '/analyze', body: created },
    ]);
    const { router } = renderWithApp(<></>, {
      route: '/analyses',
      extraRoutes: [{ path: 'analyses', element: <AnalysesPage /> }],
    });
    const form = await screen.findByRole('form', { name: 'Analyze a file' });
    const file = new File(['{"event_type": "auth.login"}\n'], 'events.jsonl', {
      type: 'application/x-ndjson',
    });
    await user.upload(within(form).getByLabelText('File'), file);
    await user.type(within(form).getByLabelText('Incident (optional)'), 'INC-002');
    await user.click(within(form).getByLabelText(/Correlate/));
    await user.click(within(form).getByLabelText(/Synthetic data/));
    await user.click(within(form).getByRole('button', { name: 'Analyze' }));

    await waitFor(() => expect(router.state.location.search).toBe('?analysis=analysis-3'));
    const post = calls.find((call) => call.method === 'POST' && call.path === '/analyze')!;
    expect(post.rawBody).toBeInstanceOf(FormData);
    const sent = post.rawBody as FormData;
    expect((sent.get('file') as File).name).toBe('events.jsonl');
    expect(sent.get('incident')).toBe('INC-002');
    expect(sent.get('correlate')).toBe('false');
    expect(sent.get('synthetic')).toBe('true');
    expect(post.headers.get('Content-Type')).toBeNull();
  });

  it('replaces server paths in suggestions with the uploaded file name', () => {
    const { commands, redacted } = displaySuggestions(RECORD);
    expect(redacted).toBe(true);
    expect(commands).toEqual(['raf lens analysis-2', 'raf protocol inspect raven-inc001.pcap']);
    expect(displaySuggestions({ ...RECORD, suggestions: ['raf oracle ask "a/b path"'] }).redacted).toBe(
      false,
    );
  });
});
