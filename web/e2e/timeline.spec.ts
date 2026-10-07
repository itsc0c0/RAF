import { readFileSync } from 'node:fs';
import { expect, test } from './support/fixtures';

interface TimelinePage {
  total: number;
}

const FILTER = 'type:auth.* outcome:failure';

/** "<count> events ·" in the page header (counts under 10,000 are shown in full). */
const eventCount = (total: number) => new RegExp(`(?<!\\d)${total.toLocaleString('en-US')} events ·`);

test('a filter narrows the timeline, and the CSV export carries it', async ({ page, api }) => {
  const all = await api.get<TimelinePage>('/timeline?limit=1');
  const failures = await api.get<TimelinePage>(`/timeline?limit=1&filter=${encodeURIComponent(FILTER)}`);
  expect(failures.total).toBeGreaterThan(0);
  expect(failures.total).toBeLessThan(all.total);

  await page.goto('/timeline');
  await expect(page.getByRole('heading', { name: 'Timeline', level: 1 })).toBeVisible();
  const main = page.getByRole('main');
  await expect(main).toContainText(eventCount(all.total));

  const filters = page.getByRole('form', { name: 'Timeline filters' });
  await filters.getByRole('textbox', { name: 'Filter' }).fill(FILTER);
  await filters.getByRole('button', { name: 'Apply' }).click();

  await expect(main).toContainText(eventCount(failures.total));
  const list = page.getByRole('region', { name: 'Event list' });
  await expect(list).toContainText(`Showing ${failures.total} of ${failures.total} events`);
  for (const event of await list.getByRole('list', { name: 'Events' }).getByRole('listitem').all()) {
    await expect(event).toContainText('auth.');
  }
  const groups = page.getByRole('list', { name: 'Event counts by category' }).getByRole('button');
  await expect(groups).toHaveCount(1);
  await expect(groups).toHaveAccessibleName(`auth ${failures.total}`);

  // The CSV export is a same-origin link that carries the same filter.
  const download = page.waitForEvent('download');
  await page.getByRole('group', { name: 'Export timeline' }).getByRole('link', { name: 'CSV' }).click();
  const rows = readFileSync(await (await download).path(), 'utf8')
    .trim()
    .split(/\r?\n/);
  expect(rows[0]).toMatch(/^timestamp,event_id,event_type,/);
  expect(rows).toHaveLength(failures.total + 1);
  for (const row of rows.slice(1)) expect(row.split(',')[2]).toMatch(/^auth\./);
});
