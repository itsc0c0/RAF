import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import type { DependencyGraph, Finding } from '../../api/types';
import FindingsPage from '../../pages/FindingsPage';
import { mockFetch, renderWithApp } from '../../test/utils';
import { buildDependencyTree, findingFor } from '../dependency/dependencyModel';

function finding(overrides: Partial<Finding>): Finding {
  return {
    id: 'finding:vault:github-token:12aabb5b2e42',
    title: 'GitHub token in src/app.py',
    description: 'GitHub token found at src/app.py:1. Redacted value ghp****OL8d.',
    severity: 'HIGH',
    confidence: 0.95,
    confidence_level: 'HIGH',
    product: 'vault',
    rule_id: 'github-token',
    status: 'OPEN',
    affected_objects: ['secret:dev-01|/srv/shop/src/app.py|1|github-token'],
    evidence: [],
    recommendation: 'Revoke the token.',
    explanation: [{ label: 'high-precision pattern: GitHub token', sign: '+', points: 95 }],
    created_at: '2026-10-07T13:16:05.436458Z',
    updated_at: '2026-10-07T13:16:05.452004Z',
    tags: ['vault'],
    metadata: {
      rule: 'github-token',
      fingerprint: 'd2969f334b5a7f004125cbfa5f9a38fd',
      redacted: 'ghp****OL8d',
      host: 'dev-01',
      relative_path: 'src/app.py',
      lines: [1],
    },
    ...overrides,
  };
}

describe('Findings: Vault tab', () => {
  it('shows secrets only as redacted values with fingerprints, never the value', async () => {
    const user = userEvent.setup();
    const { calls } = mockFetch([
      { path: '/vault/findings', body: { items: [finding({})], total: 1, limit: 50, offset: 0 } },
      {
        path: '/vault/secrets',
        body: {
          items: [
            {
              id: 'secret:dev-01|/srv/shop/config/.env|1|password-assignment',
              name: 'DB_PASSWORD in config/.env:1',
              rule: 'password-assignment',
              kind: 'Hardcoded password or secret',
              severity: 'MEDIUM',
              redacted: 'S****91',
              fingerprint: '95160925f50d4a15d1ecdd07a0825a5f',
              host: 'dev-01',
              path: '/srv/shop/config/.env',
              relative_path: 'config/.env',
              line: 1,
              confidence: 0.65,
              first_seen: '2026-10-07T13:16:05.436458Z',
              last_seen: '2026-10-07T13:16:05.436458Z',
              removed: false,
            },
          ],
          total: 1,
          limit: 500,
          offset: 0,
        },
      },
      { path: '/vault/rules', body: { items: [] } },
      { path: '/findings/finding:vault:github-token:12aabb5b2e42', body: finding({}) },
    ]);
    const { router } = renderWithApp(<></>, {
      route: '/findings?tab=vault',
      extraRoutes: [{ path: 'findings', element: <FindingsPage /> }],
    });

    const findings = await screen.findByRole('table', { name: 'Secret findings' });
    const row = within(findings).getAllByRole('row')[1]!;
    expect(row).toHaveTextContent('redacted');
    expect(row).toHaveTextContent('ghp****OL8d');
    expect(row).toHaveTextContent('src/app.py:1');
    expect(within(findings).getByTitle('d2969f334b5a7f004125cbfa5f9a38fd')).toBeInTheDocument();
    const secrets = await screen.findByRole('table', { name: 'Secret objects (redacted)' });
    expect(secrets).toHaveTextContent('S****91');
    expect(screen.queryByRole('button', { name: /reveal|show value/i })).not.toBeInTheDocument();
    expect(calls.find((call) => call.path === '/vault/findings')!.url.searchParams.get('status')).toBe(
      'OPEN',
    );

    await user.click(within(row).getByText('github-token'));
    await waitFor(() =>
      expect(new URLSearchParams(router.state.location.search).get('finding')).toBe(
        'finding:vault:github-token:12aabb5b2e42',
      ),
    );
    expect(new URLSearchParams(router.state.location.search).get('tab')).toBe('vault');
    expect(await screen.findByRole('dialog', { name: 'GitHub token in src/app.py' })).toBeInTheDocument();
  });
});

describe('Dependency model', () => {
  it('builds a finite tree: direct packages, transitive children, cycles and repeats marked', () => {
    const graph: DependencyGraph = {
      project: { id: 'project:/srv/shop', name: 'shop' },
      packages: [
        { id: 'package:npm/a@1.0.0', ecosystem: 'npm', name: 'a', version: '1.0.0', direct: true },
        { id: 'package:npm/b@1.0.0', ecosystem: 'npm', name: 'b', version: '1.0.0', direct: true },
        {
          id: 'package:npm/c@1.0.0',
          ecosystem: 'npm',
          name: 'c',
          version: '1.0.0',
          direct: false,
          vulnerabilities: ['vulnerability:X'],
        },
      ],
      edges: [
        { source: 'project:/srv/shop', target: 'package:npm/b@1.0.0', type: 'DEPENDS_ON' },
        { source: 'project:/srv/shop', target: 'package:npm/a@1.0.0', type: 'DEPENDS_ON' },
        { source: 'package:npm/a@1.0.0', target: 'package:npm/c@1.0.0', type: 'DEPENDS_ON' },
        { source: 'package:npm/b@1.0.0', target: 'package:npm/c@1.0.0', type: 'DEPENDS_ON' },
        { source: 'package:npm/c@1.0.0', target: 'package:npm/a@1.0.0', type: 'DEPENDS_ON' },
      ],
    };
    const tree = buildDependencyTree(graph);
    expect(tree.map((node) => node.package?.name)).toEqual(['a', 'b']);
    const c = tree[0]!.children[0]!;
    expect(c.package?.name).toBe('c');
    expect(c.children[0]!.cycle).toBe(true);
    // c was expanded under a: under b it is listed, not expanded again.
    expect(tree[1]!.children[0]!.repeated).toBe(true);
    expect(tree[1]!.children[0]!.children).toEqual([]);
  });

  it('matches a vulnerable package to its finding (which carries the confidence)', () => {
    const match = finding({
      id: 'finding:dependency:vulnerable-package:1',
      product: 'dependency',
      confidence: 0.9,
      affected_objects: ['package:pypi/raven-auth@1.2.0', 'project:/srv/shop'],
      metadata: { advisory: 'RAFSIM-2026-0101', basis: 'exact' },
    });
    expect(findingFor([match], 'package:pypi/raven-auth@1.2.0', 'RAFSIM-2026-0101')?.confidence).toBe(0.9);
    expect(findingFor([match], 'package:pypi/raven-auth@1.2.0', 'RAFSIM-2026-0102')).toBeNull();
  });
});
