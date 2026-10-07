import { expect, test } from './support/fixtures';

interface TimelinePage {
  total: number;
}

test('Lens scopes the events of INC-001, and a group narrows them', async ({ page, api }) => {
  const incident = await api.get<TimelinePage>('/timeline?ref=INC-001&limit=1');
  const auth = await api.get<TimelinePage>('/timeline?ref=INC-001&filter=category:auth&limit=1');

  await page.goto('/investigate?object=INC-001');
  await expect(page.getByRole('tab', { name: 'Lens' })).toHaveAttribute('aria-selected', 'true');
  const lens = page.getByRole('tabpanel', { name: 'Lens' });
  const query = lens.getByRole('form', { name: 'Lens query' });
  await expect(query.getByRole('textbox', { name: 'Scope' })).toHaveValue('INC-001');
  await expect(lens.getByText(`${incident.total} events`, { exact: true })).toBeVisible();
  const events = lens.getByRole('region', { name: 'Matching events' }).getByRole('list', { name: 'Events' });
  await expect(events.getByRole('listitem').first()).toBeVisible();

  await lens
    .getByRole('list', { name: 'Event counts by category' })
    .getByRole('button', { name: `auth ${auth.total}`, exact: true })
    .click();
  await expect(lens.getByText(`${auth.total} events`, { exact: true })).toBeVisible();
  await expect(query.getByRole('textbox', { name: 'Filter' })).toHaveValue('category:auth');
  await expect(events.getByRole('listitem').first()).toContainText('auth.');
});

test('Trace follows alice backward and forward and opens the events behind its links', async ({ page }) => {
  await page.goto('/investigate');
  await page.getByRole('tab', { name: 'Trace' }).click();
  await page.getByRole('textbox', { name: 'Object (ID, name or alias)' }).fill('alice');
  await page.getByRole('button', { name: 'Trace', exact: true }).click();

  await expect(page).toHaveURL(/\/investigate\?trace=alice$/);
  await expect(
    page.getByRole('toolbar', { name: 'Trace options' }).getByRole('button', { name: 'user alice' }),
  ).toBeVisible();
  await expect(page.getByText('Correlation is not causation', { exact: true })).toBeVisible();
  const chain = page.getByRole('list', { name: 'Most supported causal chain' });
  await expect(chain.getByRole('listitem').first()).toBeVisible();
  await expect(page.getByRole('heading', { name: 'How alice became involved (backward)' })).toBeVisible();
  await expect(
    page.getByRole('list', { name: 'Backward trace' }).getByRole('listitem').first(),
  ).toBeVisible();
  await expect(page.getByRole('heading', { name: 'What alice did next (forward)' })).toBeVisible();
  await expect(page.getByRole('list', { name: 'Forward trace' }).getByRole('listitem').first()).toBeVisible();

  await chain.getByRole('button', { name: 'event', exact: true }).first().click();
  const event = page.getByRole('dialog').filter({ hasText: 'Event ID' });
  await expect(event).toContainText(/event:[0-9a-f]+/);
  await expect(event).toContainText('alice');
});
