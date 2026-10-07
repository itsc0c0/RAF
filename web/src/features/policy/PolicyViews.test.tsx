import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import ExposurePage from '../../pages/ExposurePage';
import { mockFetch, renderWithApp } from '../../test/utils';
import { hostFromFileName, inferPolicyFormat, ruleFieldText } from './policyModel';
import { CHECK_NOTICE } from './PolicyViews';

const HOSTILE = '<img src=x onerror=alert(1)> widened for the migration';

function rule(
  id: string,
  order: number,
  effect: string,
  sources: string[],
  destinations: string[],
  ports: string[],
) {
  return {
    id,
    policy: 'request',
    order,
    effect,
    sources,
    destinations,
    ports,
    actions: ['*'],
    enabled: true,
    metadata: {},
  };
}

/** Finding of POST /policy/check observed from `raf serve` (the CSV fixture), with hostile rule text. */
const BROAD = {
  id: 'finding:policy:overly-broad-rule:2b186d902c81',
  title: 'Overly broad rule r40-dev-to-prod in request',
  description: `Rule r40-dev-to-prod allows network:dev → network:prod ports any: every port open towards a critical-criticality destination. Stated purpose: ${HOSTILE}.`,
  severity: 'HIGH',
  confidence: 0.85,
  product: 'policy',
  rule_id: 'overly-broad-rule',
  status: 'OPEN',
  affected_objects: ['policy:request', 'network:dev', 'network:prod'],
  evidence: [
    {
      kind: 'policy',
      id: 'policy:request#r40-dev-to-prod',
      note: 'allow network:dev → network:prod ports any',
    },
  ],
  recommendation:
    'Restrict the rule to the sources, destinations, ports or actions that are actually required.',
  explanation: [
    {
      factor: 'overly-broad-rule',
      label: 'every port open towards a critical-criticality destination',
      sign: '+',
    },
  ],
  created_at: '2026-10-07T15:53:19.134177Z',
  updated_at: '2026-10-07T15:53:19.134177Z',
  tags: ['policy', 'network'],
  metadata: { policy: 'request', rules: ['r40-dev-to-prod'], revision: null },
  confidence_level: 'HIGH',
};

/** Shape of POST /policy/check observed from `raf serve` (a CSV firewall export; nothing stored). */
const CHECK_RESULT = {
  set: {
    name: 'request',
    format: 'csv-firewall',
    revision: null,
    source: 'request',
    policies: [
      {
        id: 'request',
        name: 'request',
        domain: 'network',
        evaluation: 'first-match',
        default: 'deny',
        revision: null,
        description: '',
        source: 'request',
        scope: [],
        rules: [
          {
            ...rule('r10-internet-to-dmz', 0, 'allow', ['network:internet'], ['network:dmz'], ['tcp/443']),
            description: 'Public website and VPN',
          },
          {
            ...rule('r40-dev-to-prod', 1, 'allow', ['network:dev'], ['network:prod'], ['any']),
            description: HOSTILE,
          },
        ],
      },
    ],
    warnings: ["CSV exports carry no default action; 'deny' is assumed"],
  },
  analysis: {
    policies: [
      {
        id: 'request',
        object_id: 'policy:request',
        name: 'request',
        domain: 'network',
        evaluation: 'first-match',
        default: 'deny',
        revision: null,
        rules: 2,
        active_rules: 2,
        findings: 1,
        digest: '3fb9252229a2e8e6',
        source: 'request',
      },
    ],
    findings: [BROAD],
    by_rule: { 'overly-broad-rule': 1 },
    warnings: ["CSV exports carry no default action; 'deny' is assumed", '<b>row 7</b>: zone not found'],
    workspace_aware: true,
  },
};

const SNAPSHOTS = {
  items: [
    {
      id: 'snapshot:before-sept',
      name: 'before-sept',
      source: 'workspace',
      description: 'Before the September policy import',
      created_at: '2026-10-07T15:52:31.184650Z',
      stats: { objects: 426, relationships: 849, findings: 42 },
      content_hash: 'caaa6962b0d7dbe484a45d65a355cf243cdfc720d3a9f150d81f1792150e9557',
    },
  ],
};

const SHADOWED = {
  ...BROAD,
  id: 'finding:policy:shadowed-rule:dd2ad3cc5754',
  title: 'Rule r85-deny-dev-to-prod-db in Raven firewall can never apply',
  rule_id: 'shadowed-rule',
  affected_objects: ['policy:raven-fw', 'network:dev', 'host:db-01'],
  metadata: {
    policy: 'raven-fw',
    rules: ['r85-deny-dev-to-prod-db', 'r40-dev-to-prod'],
    revision: '2026-10-01',
  },
};

/** Shape of GET /policy/diff observed from `raf serve` (snapshot before the September import → current). */
const DIFF = {
  before: 'before-sept',
  after: 'current',
  policies_added: ['legacy-fw'],
  policies_removed: [],
  defaults_changed: [{ policy: 'raven-access', before: 'deny', after: 'allow' }],
  changes: [
    {
      policy: 'raven-fw',
      rule: 'r40-dev-to-prod',
      change: 'modified',
      impact: 'access-expanded',
      fields: { ports: { before: ['tcp/22', 'tcp/8443'], after: ['any'] } },
      before: 'allow network:dev → network:prod ports tcp/22, tcp/8443',
      after: 'allow network:dev → network:prod ports any',
    },
    {
      policy: 'raven-fw',
      rule: 'r90-corp-to-dev-ssh',
      change: 'added',
      impact: 'access-expanded',
      fields: {},
      before: null,
      after: 'allow network:corp → network:dev ports tcp/22',
    },
    {
      policy: 'raven-fw',
      rule: 'r85-deny-dev-to-prod-db',
      change: 'moved',
      impact: 'changed',
      fields: { position: { before: 3, after: 5 } },
      before: null,
      after: null,
    },
  ],
  findings_introduced: [SHADOWED],
  findings_resolved: [],
  access_expanded: 2,
};

function renderExposure(route: string) {
  return renderWithApp(<></>, { route, extraRoutes: [{ path: 'exposure', element: <ExposurePage /> }] });
}

describe('Policy: check a document', () => {
  it('sends the picked file with the format from its extension and renders the analysis as text', async () => {
    const user = userEvent.setup();
    const { calls } = mockFetch([{ method: 'POST', path: '/policy/check', body: CHECK_RESULT }]);
    renderExposure('/exposure?view=policy-check');

    expect(await screen.findByRole('tab', { name: 'Check a document' })).toHaveAttribute(
      'aria-selected',
      'true',
    );
    const form = screen.getByRole('form', { name: 'Check a policy document' });
    expect(within(form).getByText('Nothing is stored')).toBeInTheDocument();
    expect(within(form).getByText(CHECK_NOTICE, { exact: false })).toBeInTheDocument();

    const csv = 'id,action,source,destination,port,description\nr40-dev-to-prod,allow,DEV,PROD,any,widened\n';
    await user.upload(
      within(form).getByLabelText('Policy file (optional)'),
      new File([csv], 'fw-export.csv', { type: 'text/csv' }),
    );
    await waitFor(() => expect(within(form).getByLabelText('Policy document')).toHaveValue(csv));
    expect(within(form).getByLabelText('Format')).toHaveValue('csv');
    await user.type(within(form).getByLabelText('Principal (optional)'), 'identity:svc-deploy');
    await user.click(within(form).getByRole('button', { name: 'Check' }));

    const result = await screen.findByRole('region', { name: 'Check result' });
    const post = calls.find((call) => call.method === 'POST')!;
    expect(post.path).toBe('/policy/check');
    expect(post.body).toEqual({ document: csv, format: 'csv', principal: 'identity:svc-deploy' });
    expect(within(result).getByText('NOT STORED')).toBeInTheDocument();
    expect(within(result).getByText(/csv-firewall · 1 policy · 2 rules · 1 finding/)).toBeInTheDocument();

    // The normalized policy and its rules; document text is untrusted and stays literal text.
    expect(
      within(result).getByRole('table', { name: 'Normalized policies of the checked document' }),
    ).toBeInTheDocument();
    const rules = within(result).getByRole('table', { name: 'Rules of request' });
    expect(within(rules).getByText('r10-internet-to-dmz')).toBeInTheDocument();
    expect(within(rules).getByText(HOSTILE)).toBeInTheDocument();
    expect(within(result).getByText('<b>row 7</b>: zone not found')).toBeInTheDocument();
    expect(result.querySelector('img, script, b')).toBeNull();

    // Computed findings have no status column and open in place, never through GET /findings/{id}.
    const findings = within(result).getByRole('table', { name: 'Findings' });
    expect(within(findings).queryByRole('columnheader', { name: 'Status' })).toBeNull();
    await user.click(within(findings).getByText(BROAD.title));
    const drawer = await screen.findByRole('dialog', { name: BROAD.title });
    expect(within(drawer).getByText('NOT STORED')).toBeInTheDocument();
    expect(within(drawer).queryByRole('button', { name: 'Save' })).toBeNull();
    expect(calls.some((call) => call.path.startsWith('/findings'))).toBe(false);
  });

  it('sends pasted text with the format chosen by hand and shows the API error', async () => {
    const user = userEvent.setup();
    const { calls } = mockFetch([
      {
        method: 'POST',
        path: '/policy/check',
        status: 422,
        body: {
          error: {
            code: 'raf.invalid_input',
            message: 'Policy document is not valid YAML: mapping values are not allowed here',
          },
        },
      },
    ]);
    renderExposure('/exposure?view=policy-check');

    const form = await screen.findByRole('form', { name: 'Check a policy document' });
    const text = 'policies:\n  - id: fw\n    rules: [a: b: c]\n';
    await user.click(within(form).getByLabelText('Policy document'));
    await user.paste(text);
    await user.selectOptions(within(form).getByLabelText('Format'), 'yaml');
    await user.click(within(form).getByRole('button', { name: 'Check' }));

    expect(await within(form).findByText(/mapping values are not allowed here/)).toBeInTheDocument();
    const post = calls.find((call) => call.method === 'POST')!;
    expect(post.body).toEqual({ document: text, format: 'yaml' });
    expect(screen.queryByRole('region', { name: 'Check result' })).toBeNull();
  });

  it('sends an iptables-save file with the host named after it, editable before the check', async () => {
    const user = userEvent.setup();
    const { calls } = mockFetch([{ method: 'POST', path: '/policy/check', body: CHECK_RESULT }]);
    renderExposure('/exposure?view=policy-check');

    const form = await screen.findByRole('form', { name: 'Check a policy document' });
    expect(within(form).queryByLabelText('Host (optional)')).toBeNull(); // only for iptables-save
    const rules =
      '*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n-A FORWARD -s 10.20.0.0/16 -j ACCEPT\nCOMMIT\n';
    await user.upload(
      within(form).getByLabelText('Policy file (optional)'),
      new File([rules], 'raven-edge.rules', { type: 'text/plain' }),
    );
    await waitFor(() => expect(within(form).getByLabelText('Policy document')).toHaveValue(rules));
    expect(within(form).getByLabelText('Format')).toHaveValue('iptables');
    const host = within(form).getByLabelText('Host (optional)');
    expect(host).toHaveValue('raven-edge');
    await user.clear(host);
    await user.type(host, 'VPN-01');
    await user.click(within(form).getByRole('button', { name: 'Check' }));

    await screen.findByRole('region', { name: 'Check result' });
    const post = calls.find((call) => call.method === 'POST')!;
    expect(post.body).toEqual({ document: rules, format: 'iptables', host: 'VPN-01' });
  });

  it('infers the document format from the file name', () => {
    expect(inferPolicyFormat('rules.YML')).toBe('yaml');
    expect(inferPolicyFormat('rules.yaml')).toBe('yaml');
    expect(inferPolicyFormat('export.CSV')).toBe('csv');
    expect(inferPolicyFormat('iam-policy.json')).toBe('json');
    expect(inferPolicyFormat('policy')).toBe('json');
    expect(inferPolicyFormat('edge.rules')).toBe('iptables');
    expect(inferPolicyFormat('etc/iptables/RULES.V4')).toBe('iptables');
    expect(hostFromFileName('C:\\exports\\raven-edge.rules')).toBe('raven-edge');
    expect(hostFromFileName('fw.backup.v4')).toBe('fw.backup');
    expect(hostFromFileName('.rules')).toBe('.rules');
    expect(ruleFieldText(['tcp/22', 'tcp/8443'])).toBe('tcp/22, tcp/8443');
    expect(ruleFieldText([])).toBe('(none)');
    expect(ruleFieldText(false)).toBe('false');
  });
});

describe('Policy: compare revisions', () => {
  it('offers current and the snapshots, then lists every change and whether access expanded', async () => {
    const user = userEvent.setup();
    const { calls } = mockFetch([
      { path: '/snapshots', body: SNAPSHOTS },
      { path: '/policy/diff', body: DIFF },
    ]);
    const { router } = renderExposure('/exposure?view=policy-diff');

    // The latest snapshot is the default "before" once the snapshots are loaded.
    await waitFor(() => expect(screen.getByLabelText('Before')).toHaveValue('before-sept'));
    const form = screen.getByRole('form', { name: 'Compare policy revisions' });
    const before = within(form).getByLabelText('Before');
    expect(
      within(before)
        .getAllByRole('option')
        .map((option) => option.textContent),
    ).toEqual(['current (live workspace)', 'before-sept (snapshot 2026-10-07 15:52:31Z)']);
    expect(within(form).getByLabelText('After')).toHaveValue('current');
    expect(calls.some((call) => call.path === '/policy/diff')).toBe(false);

    await user.click(within(form).getByRole('button', { name: 'Compare' }));
    await waitFor(() => {
      const params = new URLSearchParams(router.state.location.search);
      expect([params.get('view'), params.get('before'), params.get('after')]).toEqual([
        'policy-diff',
        'before-sept',
        'current',
      ]);
    });
    const result = await screen.findByRole('region', { name: 'Policy differences' });
    const request = calls.find((call) => call.path === '/policy/diff')!;
    expect(request.url.searchParams.get('before')).toBe('before-sept');
    expect(request.url.searchParams.get('after')).toBe('current');

    expect(within(result).getByText('Access expanded')).toBeInTheDocument();
    expect(within(result).getByText(/2 rule changes grant more access/)).toBeInTheDocument();
    expect(within(result).getByText(/The default action of/)).toHaveTextContent(
      'The default action of raven-access changed from deny to allow.',
    );
    expect(within(result).getByText('legacy-fw')).toBeInTheDocument();

    const changes = within(result).getByRole('table', { name: 'Rule changes' });
    const rows = within(changes).getAllByRole('row').slice(1);
    expect(rows).toHaveLength(3);
    expect(rows[0]).toHaveTextContent('ACCESS EXPANDED');
    expect(rows[0]).toHaveTextContent('modified');
    expect(rows[0]).toHaveTextContent('ports: tcp/22, tcp/8443 → any');
    expect(rows[0]).toHaveTextContent('after allow network:dev → network:prod ports any');
    expect(rows[1]).toHaveTextContent('added');
    expect(rows[2]).toHaveTextContent('CHANGED');
    expect(rows[2]).toHaveTextContent('position: #4 → #6');

    await user.click(within(result).getByText(SHADOWED.title));
    const drawer = await screen.findByRole('dialog', { name: SHADOWED.title });
    expect(within(drawer).getByText('NOT STORED')).toBeInTheDocument();
  });

  it('says so when the revisions do not differ', async () => {
    mockFetch([
      { path: '/snapshots', body: SNAPSHOTS },
      {
        path: '/policy/diff',
        body: {
          ...DIFF,
          policies_added: [],
          defaults_changed: [],
          changes: [],
          findings_introduced: [],
          access_expanded: 0,
        },
      },
    ]);
    renderExposure('/exposure?view=policy-diff&before=before-sept&after=current');

    const result = await screen.findByRole('region', { name: 'Policy differences' });
    expect(within(result).getByText('No policy differences')).toBeInTheDocument();
    expect(within(result).queryByRole('table', { name: 'Rule changes' })).toBeNull();
    expect(within(result).queryByText('Access expanded')).toBeNull();
  });
});
