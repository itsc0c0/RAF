import { expect, test } from './support/fixtures';

interface Status {
  workspace: string;
  raf_version: string;
  data: Record<string, number>;
  findings_by_severity: Record<string, number>;
  products: { available: number; total: number };
}

interface Incident {
  name: string;
  title: string;
  severity: string;
  event_count: number;
}

interface Product {
  name: string;
  display_name: string;
  status: string;
}

const COUNTS = [
  ['objects', 'Objects'],
  ['relationships', 'Relationships'],
  ['events', 'Events'],
  ['incidents', 'Incidents'],
  ['findings', 'Findings'],
] as const;

/** Counts under 10,000 are shown in full, with thousands separators. */
const shown = (value: number) => value.toLocaleString('en-US');

test('the overview shows the workspace, its open findings, INC-001 and every product status', async ({
  page,
  api,
}) => {
  const status = await api.get<Status>('/status');
  const { items: incidents } = await api.get<{ items: Incident[] }>('/incidents');
  const { items: products } = await api.get<{ items: Product[] }>('/products');
  const incident = incidents.find((item) => item.name === 'INC-001');
  expect(incident, 'the demo workspace has INC-001').toBeDefined();

  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Overview', level: 1 })).toBeVisible();
  await expect(page.getByText(`Workspace ${status.workspace} · R$F ${status.raf_version}`)).toBeVisible();

  // Each tile is a label followed by its value.
  const counts = page.getByLabel('Workspace counts');
  for (const [key, label] of COUNTS) {
    await expect(counts).toContainText(new RegExp(`${label}\\s*${shown(status.data[key] ?? 0)}(?!\\d)`));
  }
  await expect(counts).toContainText(
    new RegExp(`Products available\\s*${status.products.available}/${status.products.total}(?!\\d)`),
  );

  const bySeverity = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
    .map((severity) => `${severity} ${status.findings_by_severity[severity] ?? 0}`)
    .join(', ');
  await expect(page.getByRole('img', { name: bySeverity, exact: true })).toBeVisible();

  const row = page.getByRole('table', { name: 'Incidents' }).getByRole('row', { name: /INC-001/ });
  await expect(row).toContainText(incident!.title);
  await expect(row).toContainText(`Severity: ${incident!.severity}`);
  await expect(row.getByRole('cell').nth(4)).toHaveText(shown(incident!.event_count));
  await expect(row.getByRole('button', { name: 'Replay' })).toBeVisible();

  // The product registry, one click away, shows the status of every product.
  await counts.getByRole('button', { name: 'registry' }).click();
  await expect(page).toHaveURL(/\/products$/);
  const registry = page.getByRole('table', { name: 'Product registry' });
  await expect(registry.getByRole('row')).toHaveCount(products.length + 1);
  for (const product of products) {
    const productRow = registry.getByRole('row').filter({
      has: page.getByRole('cell', { name: `${product.display_name} ${product.name}`, exact: true }),
    });
    await expect(productRow.getByRole('cell').nth(1)).toHaveText(product.status.toUpperCase());
  }
});
