import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import type { SurfaceTreeNode } from '../../api/types';
import SurfacePage from '../../pages/SurfacePage';
import { mockFetch, renderWithApp } from '../../test/utils';
import { inferSurfaceFormat } from './surfaceModel';
import { APPLY_SCOPE_EXPLANATION, NO_SCANNING, SurfaceTree } from './SurfaceViews';

function certificate(name: string, state: string, days: number | null, notAfter: string) {
  return {
    id: `certificate:${name}`,
    name,
    endpoint: '198.51.100.20:443',
    not_after: notAfter,
    state,
    days_remaining: days,
  };
}

/** Excerpt of GET /surface/summary `tree` from the Raven demo, plus hostile inventory text. */
const TREE: SurfaceTreeNode[] = [
  {
    id: 'domain:raven.example',
    name: 'raven.example',
    scope: 'in',
    scope_entry: 'raven.example',
    owners: ['IT operations'],
    claimed_owners: [],
    status: 'active',
    inventoried: true,
    records: [
      {
        type: 'A',
        value: '198.51.100.20',
        view: 'external',
        target: 'ip:198.51.100.20',
        hosts: ['WEB-01'],
        scope: 'in',
        internal: false,
        services: [
          {
            id: 'service:web',
            name: 'web',
            endpoint: '198.51.100.20:443',
            port: 443,
            transport: 'tcp',
            product: 'nginx 1.26 <script>alert(1)</script>',
            internet_facing: true,
            status: 'active',
          },
        ],
        certificates: [
          certificate('www.raven.example', 'valid', 100, '2027-01-15T23:59:59Z'),
          certificate('shop.raven.example', 'expired', -7, '2026-09-30T23:59:59Z'),
        ],
      },
    ],
    txt: ['v=spf1 include:mail.provider.example -all'],
    children: [
      {
        id: 'domain:api.raven.example',
        name: 'api.raven.example',
        scope: 'in',
        scope_entry: 'raven.example',
        owners: ['Platform'],
        claimed_owners: [],
        status: 'active',
        inventoried: true,
        records: [
          {
            type: 'CNAME',
            value: 'raven-api-lb.lb.examplecloud.example',
            view: 'external',
            target: 'domain:raven-api-lb.lb.examplecloud.example',
            status: 'active',
            services: [],
            certificates: [certificate('api.raven.example', 'expiring', 21, '2026-10-28T12:00:00Z')],
            cloud: [
              {
                id: 'cloud_resource:examplecloud/raven-prod/load_balancer/raven-api-lb',
                name: 'raven-api-lb',
                kind: 'load_balancer',
                provider: 'examplecloud',
                public: true,
              },
            ],
          },
        ],
        txt: [],
        children: [],
        findings: 0,
      },
    ],
    findings: 0,
  },
  {
    id: 'domain:raven-launch.example',
    name: 'raven-launch.example',
    scope: 'out',
    scope_entry: null,
    owners: [],
    claimed_owners: ['Marketing'],
    status: 'active',
    inventoried: true,
    records: [],
    txt: [],
    children: [],
    findings: 1,
  },
];

const SCOPE = {
  items: [
    {
      target: 'raven.example',
      kind: 'domain',
      owner: 'IT operations',
      authorization: 'SEC-2026-031',
      added_at: '2026-10-07T13:26:38.334210Z',
    },
    {
      target: '198.51.100.0/28',
      kind: 'cidr',
      owner: 'IT operations',
      authorization: 'SEC-2026-031',
      added_at: '2026-10-07T13:26:38.335779Z',
    },
  ],
  total: 2,
};

const IMPORT_RESULT = {
  source: 'inventory.json',
  path: null,
  sha256: '70f9a4e82a2376f69ee5163264e4aaceae7297b4cf3d2e9a3ce6c71c5e20efb6',
  size: 548,
  format: 'json',
  organization: 'Raven Industries',
  as_of: '2026-10-07T00:00:00Z',
  records: 4,
  accepted: 2,
  rejected: 2,
  by_kind: { dns: 1, domain: 1 },
  rejections: [
    {
      record: 'records[2]',
      reason: "'name': '<img src=x onerror=alert(1)>.raven-labs.example' is not a valid host name.",
      hint: null,
      source: 'inventory.json',
    },
  ],
  warnings: [],
  scope_declared: 1,
  scope_applied: false,
  scope_changes: [],
  job_id: 'job-9',
};

describe('Surface', () => {
  it('renders the domain tree with certificate states, scope and claimed owners as text', async () => {
    mockFetch([]);
    renderWithApp(<SurfaceTree nodes={TREE} />);
    const tree = await screen.findByRole('list', { name: 'Domain tree' });

    const valid = within(tree).getByTitle('Inspect certificate:www.raven.example').closest('li')!;
    expect(valid).toHaveTextContent('VALID');
    expect(valid).toHaveTextContent('100 days left');
    const expired = within(tree).getByTitle('Inspect certificate:shop.raven.example').closest('li')!;
    expect(expired).toHaveTextContent('EXPIRED');
    expect(expired).toHaveTextContent('expired 7 days ago');
    const expiring = within(tree).getByTitle('Inspect certificate:api.raven.example').closest('li')!;
    expect(expiring).toHaveTextContent('EXPIRING');
    expect(expiring).toHaveTextContent('expires in 21 days');

    expect(within(tree).getByText('INTERNET-FACING')).toBeInTheDocument();
    expect(within(tree).getByText('PUBLIC')).toBeInTheDocument();
    expect(within(tree).getByText('OUT OF SCOPE')).toBeInTheDocument();
    expect(within(tree).getByText('claimed by Marketing (not accepted)')).toBeInTheDocument();
    // Inventory text is untrusted: rendered literally.
    expect(within(tree).getByText('nginx 1.26 <script>alert(1)</script>')).toBeInTheDocument();
    expect(document.querySelector('script')).toBeNull();
  });

  it('removes a scope entry only after an explicit, typed confirmation', async () => {
    const user = userEvent.setup();
    const { calls } = mockFetch([
      { path: '/surface/scope', body: SCOPE },
      {
        method: 'DELETE',
        path: '/surface/scope/198.51.100.0/28',
        body: { entry: SCOPE.items[1], result: 'removed' },
      },
    ]);
    renderWithApp(<></>, {
      route: '/surface?view=scope',
      extraRoutes: [{ path: 'surface', element: <SurfacePage /> }],
    });

    expect(screen.getByText(NO_SCANNING)).toBeInTheDocument();
    expect(await screen.findByText(/Scope means explicit authorization/)).toBeInTheDocument();
    await user.click(await screen.findByRole('button', { name: 'Remove 198.51.100.0/28 from the scope' }));
    const dialog = await screen.findByRole('dialog', {
      name: 'Remove 198.51.100.0/28 from the authorized scope?',
    });
    const confirm = within(dialog).getByRole('button', { name: 'Remove from scope' });
    expect(confirm).toBeDisabled();
    expect(calls.some((call) => call.method === 'DELETE')).toBe(false);

    await user.type(within(dialog).getByLabelText(/to confirm/), '198.51.100.0/28');
    await user.click(confirm);
    await waitFor(() => expect(calls.some((call) => call.method === 'DELETE')).toBe(true));
    const deletion = calls.find((call) => call.method === 'DELETE')!;
    // CIDR targets contain "/": the reference is encoded, the API's path converter accepts it.
    expect(deletion.url.pathname).toBe('/api/v1/surface/scope/198.51.100.0%2F28');
  });

  it('sends the inventory as the request body, with apply_scope only when explicitly checked', async () => {
    const user = userEvent.setup();
    const { calls } = mockFetch([
      { path: '/surface/scope', body: SCOPE },
      { method: 'POST', path: '/surface/import', body: IMPORT_RESULT },
    ]);
    renderWithApp(<></>, {
      route: '/surface?view=import',
      extraRoutes: [{ path: 'surface', element: <SurfacePage /> }],
    });

    const form = await screen.findByRole('form', { name: 'Import a surface inventory' });
    const apply = within(form).getByLabelText('Apply the file’s scope section');
    expect(apply).not.toBeChecked();
    expect(within(form).getByText(APPLY_SCOPE_EXPLANATION)).toBeInTheDocument();

    const file = new File(['{"format": "raf-surface/1", "records": []}'], 'inventory.json', {
      type: 'application/json',
    });
    await user.upload(within(form).getByLabelText('Inventory file'), file);
    await user.click(within(form).getByRole('button', { name: 'Import' }));
    await waitFor(() => expect(calls.filter((call) => call.method === 'POST')).toHaveLength(1));

    const first = calls.filter((call) => call.method === 'POST')[0]!;
    expect(first.url.searchParams.has('apply_scope')).toBe(false);
    expect(first.url.searchParams.get('format')).toBe('json');
    expect(first.url.searchParams.get('source_name')).toBe('inventory.json');
    expect(first.rawBody).toBe(file);
    expect(first.headers.get('Content-Type')).toBe('application/json');
    // The result (rejections are inventory text: literal).
    expect(await screen.findByText(IMPORT_RESULT.rejections[0]!.reason)).toBeInTheDocument();
    expect(document.querySelector('img')).toBeNull();

    await user.click(apply);
    await user.click(within(form).getByRole('button', { name: 'Import' }));
    await waitFor(() => expect(calls.filter((call) => call.method === 'POST')).toHaveLength(2));
    const second = calls.filter((call) => call.method === 'POST')[1]!;
    expect(second.url.searchParams.get('apply_scope')).toBe('true');
  });

  it('infers the inventory format from the file name', () => {
    expect(inferSurfaceFormat('a.JSONL')).toBe('jsonl');
    expect(inferSurfaceFormat('a.ndjson')).toBe('jsonl');
    expect(inferSurfaceFormat('a.yml')).toBe('yaml');
    expect(inferSurfaceFormat('a.csv')).toBe('csv');
    expect(inferSurfaceFormat('inventory')).toBe('json');
  });
});
