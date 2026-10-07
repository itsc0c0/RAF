import { expect, isolatedTest as test } from './support/fixtures';

interface Finding {
  id: string;
  title: string;
  status: string;
  metadata: { status_history?: Array<{ from: string; to: string; note: string | null }> };
}

interface AuditEntry {
  operation: string;
  interface: string;
  affected: string[];
  details: Record<string, unknown>;
}

const NOTE = 'Triaged by the end-to-end suite';

// This test changes a finding, so it runs against a server and workspace of its own.
test('triage acknowledges a finding: the drawer, the list and the API agree', async ({ page, api }) => {
  const open = await api.get<{ items: Finding[]; total: number }>('/findings?status=OPEN&limit=1');
  const finding = open.items[0];
  if (!finding) throw new Error('the demo workspace has no open finding');

  await page.goto('/findings');
  await expect(page.getByRole('heading', { name: 'Findings', level: 1 })).toBeVisible();
  const table = page.getByRole('table', { name: 'Findings' });
  await expect(
    page.getByText(`1–${Math.min(open.total, 50)} of ${open.total}`, { exact: true }),
  ).toBeVisible();
  await expect(table.getByRole('row')).toHaveCount(Math.min(open.total, 50) + 1);

  const filters = page.getByRole('form', { name: 'Finding filters' });
  await filters.getByRole('textbox', { name: 'Search' }).fill(finding.title);
  const row = table.getByRole('row').filter({ hasText: finding.title });
  await expect(row).toHaveCount(1);
  await row.click();

  const drawer = page.getByRole('dialog', { name: finding.title });
  await expect(drawer).toContainText(finding.id);
  const status = drawer.getByRole('combobox', { name: 'Status' });
  await expect(status).toHaveValue('OPEN');
  await status.selectOption('ACKNOWLEDGED');
  await drawer.getByRole('textbox', { name: 'Note (recorded in the audit log)' }).fill(NOTE);
  await drawer.getByRole('button', { name: 'Save' }).click();

  await expect(page.getByRole('status').filter({ hasText: 'Finding marked ACKNOWLEDGED' })).toBeVisible();
  await expect(status).toHaveValue('ACKNOWLEDGED');
  await expect(drawer.getByRole('button', { name: 'Save' })).toBeDisabled();
  // Only open findings are listed by default: it is gone from the list, and listed as acknowledged.
  await expect(row).toHaveCount(0);
  await filters.getByRole('combobox', { name: 'Status' }).selectOption('ACKNOWLEDGED');
  await expect(row.getByRole('cell').nth(4)).toHaveText('ACKNOWLEDGED');

  const saved = await api.get<Finding>(`/findings/${encodeURIComponent(finding.id)}`);
  expect(saved.status).toBe('ACKNOWLEDGED');
  expect(saved.metadata.status_history?.at(-1)).toMatchObject({
    from: 'OPEN',
    to: 'ACKNOWLEDGED',
    note: NOTE,
  });
  const stillOpen = await api.get<{ total: number }>('/findings?status=OPEN&limit=1');
  expect(stillOpen.total).toBe(open.total - 1);
  // "Note (recorded in the audit log)"
  const audit = await api.get<{ items: AuditEntry[] }>('/audit?limit=20');
  expect(audit.items.find((entry) => entry.affected.includes(finding.id))).toMatchObject({
    operation: 'finding.status',
    interface: 'api',
    details: { status: 'ACKNOWLEDGED', note: NOTE },
  });
});
