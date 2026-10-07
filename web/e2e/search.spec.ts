import { expect, test } from './support/fixtures';

interface TimelinePage {
  total: number;
}

test('the global search finds alice, opens her in the inspector and pivots to her timeline', async ({
  page,
  api,
}) => {
  const timeline = await api.get<TimelinePage>('/timeline?ref=user:alice&limit=1');

  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Overview', level: 1 })).toBeVisible();
  await page.keyboard.press('/');
  const search = page.getByRole('combobox', { name: 'Search R$F' });
  await expect(search).toBeFocused();
  await search.fill('alice');

  const option = page
    .getByRole('listbox', { name: 'Search results' })
    .getByRole('option', { name: /user:alice/ });
  await expect(option).toBeVisible();
  await expect(option).toHaveAttribute('aria-selected', 'true');
  await search.press('Enter');

  const inspector = page.getByRole('dialog', { name: 'alice' });
  await expect(inspector).toContainText('Object inspector');
  await expect(inspector).toContainText('user:alice');
  await expect(inspector.getByRole('region', { name: 'Metadata' })).toContainText('alice@raven.example');
  await expect(
    inspector.getByRole('region', { name: 'Relationships' }).getByRole('listitem').first(),
  ).toBeVisible();

  await inspector
    .getByRole('navigation', { name: 'Pivot to another view' })
    .getByRole('button', { name: 'Timeline' })
    .click();
  await expect(page).toHaveURL(/\/timeline\?object=user%3Aalice$/);
  await expect(page.getByRole('heading', { name: 'Timeline', level: 1 })).toBeVisible();
  await expect(page.getByRole('main')).toContainText(`${timeline.total} events ·`);
});

test('the command palette opens alice and replays INC-001', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Overview', level: 1 })).toBeVisible();

  await page.keyboard.press('Control+K');
  const palette = page.getByRole('dialog', { name: 'Command palette' });
  const input = palette.getByRole('combobox', { name: 'Type a command or search objects' });
  await expect(input).toBeFocused();
  await input.fill('alice');
  // Live object results from GET /search come after the matching commands.
  await palette.getByRole('option', { name: /^Open alice user · user:alice/ }).click();
  await expect(palette).toBeHidden();
  const inspector = page.getByRole('dialog', { name: 'alice' });
  await expect(inspector).toContainText('user:alice');
  await inspector.getByRole('button', { name: 'Close inspector' }).click();
  await expect(inspector).toBeHidden();

  await page.keyboard.press('Control+K');
  await expect(input).toBeFocused();
  await input.fill('replay inc-001');
  const replay = palette.getByRole('option', { name: /^Replay Incident INC-001/ });
  await expect(replay).toHaveAttribute('aria-selected', 'true');
  await input.press('Enter');
  await expect(page).toHaveURL(/\/replay\?incident=incident%3Ainc-001$/);
  await expect(page.getByRole('group', { name: 'Playback controls' })).toBeVisible();
});
