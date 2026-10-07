import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import type { Finding } from '../../api/types';
import FindingsPage from '../../pages/FindingsPage';
import { mockFetch, renderWithApp } from '../../test/utils';

const ID = 'finding:iam:credential-exposure-path:6409415f44c1';

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: ID,
    title: 'Credentials of svc-deploy exposed on DEV-01',
    description: 'Credentials for the privileged identity svc-deploy are present on DEV-01.',
    severity: 'HIGH',
    confidence: 0.75,
    confidence_level: 'MEDIUM',
    product: 'iam',
    rule_id: 'credential-exposure-path',
    status: 'OPEN',
    affected_objects: ['identity:svc-deploy', 'host:dev-01'],
    evidence: [],
    recommendation: 'Move the credential into a secret manager and rotate it.',
    explanation: [{ label: '/opt/deploy/.env', sign: '+' }],
    created_at: '2026-10-07T15:52:27Z',
    updated_at: '2026-10-07T15:52:27Z',
    tags: ['iam'],
    metadata: {},
    ...overrides,
  };
}

describe('Finding triage', () => {
  it('saves the status and the note, then confirms it although the saved finding remounts the form', async () => {
    const user = userEvent.setup();
    let current = finding();
    const { calls } = mockFetch([
      { path: '/findings', body: () => ({ items: [current], total: 1, limit: 50, offset: 0 }) },
      { path: `/findings/${ID}`, body: () => current },
      {
        method: 'PATCH',
        path: `/findings/${ID}`,
        handler: () => {
          current = finding({ status: 'ACKNOWLEDGED', updated_at: '2026-10-07T16:00:00Z' });
          return { body: current };
        },
      },
    ]);
    renderWithApp(<FindingsPage />, { route: `/findings?finding=${encodeURIComponent(ID)}` });

    const drawer = await screen.findByRole('dialog', { name: 'Credentials of svc-deploy exposed on DEV-01' });
    await user.selectOptions(await within(drawer).findByRole('combobox', { name: 'Status' }), 'ACKNOWLEDGED');
    await user.type(
      within(drawer).getByRole('textbox', { name: 'Note (recorded in the audit log)' }),
      'rotated',
    );
    await user.click(within(drawer).getByRole('button', { name: 'Save' }));

    // The refetched finding (new status and update time) re-keys the triage form.
    expect(await screen.findByText('Finding marked ACKNOWLEDGED')).toBeInTheDocument();
    expect(calls.find((call) => call.method === 'PATCH')?.body).toEqual({
      status: 'ACKNOWLEDGED',
      note: 'rotated',
    });
    expect(within(drawer).getByRole('combobox', { name: 'Status' })).toHaveValue('ACKNOWLEDGED');
    expect(within(drawer).getByRole('button', { name: 'Save' })).toBeDisabled();
  });
});
