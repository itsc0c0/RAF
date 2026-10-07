import { readFileSync } from 'node:fs';
import { expect, tokenTest as test } from './support/fixtures';

interface Status {
  data: Record<string, number>;
}

// A server that requires a bearer token for every API request (as `raf serve` does on a
// non-loopback address), bound to 127.0.0.1 like every server of the suite.
test('a token-protected server: the UI asks for the token and works once it is entered', async ({
  page,
  request,
  server,
  api,
}) => {
  const token = server.token!;
  expect((await request.get('/api/v1/status')).status()).toBe(401);
  const status = await api.get<Status>('/status');
  const timeline = await api.get<{ items: Array<{ id: string }> }>('/timeline?limit=1');

  await page.goto('/');
  const prompt = page.getByRole('dialog', { name: 'Access token required' });
  const input = prompt.getByLabel('Token', { exact: true });
  const submit = prompt.getByRole('button', { name: 'Use token' });
  await expect(input).toBeFocused();
  await expect(submit).toBeDisabled();

  // After Cancel the page says what is missing and the token can be entered later.
  await prompt.getByRole('button', { name: 'Cancel' }).click();
  await expect(prompt).toBeHidden();
  await expect(
    page.getByText('This R$F server requires a bearer token for every API request.'),
  ).toBeVisible();
  await expect(page.getByRole('button', { name: 'Access token required: enter token' })).toBeVisible();
  await page.getByRole('main').getByRole('button', { name: 'Enter token' }).click();

  // The server rejects a wrong token, and the prompt says so.
  await input.fill('not-the-token');
  await submit.click();
  await expect(prompt.getByText('The server rejected the current token')).toBeVisible();

  await input.fill(token);
  await submit.click();
  await expect(prompt).toBeHidden();
  await expect(page.getByRole('heading', { name: 'Overview', level: 1 })).toBeVisible();
  await expect(page.getByLabel('Workspace counts')).toContainText(
    new RegExp(`Objects\\s*${(status.data.objects ?? 0).toLocaleString('en-US')}(?!\\d)`),
  );
  await expect(page.getByRole('button', { name: 'Access token required: enter token' })).toBeHidden();

  // Kept for this browser tab only, and never shown.
  expect(await page.evaluate(() => sessionStorage.getItem('raf.api.token'))).toBe(token);
  expect(await page.evaluate(() => JSON.stringify(localStorage))).not.toContain(token);
  expect(await page.content()).not.toContain(token);

  // An export link cannot carry the header: the export is fetched with it and saved from the response.
  await page.getByRole('navigation', { name: 'Primary' }).getByRole('link', { name: 'Timeline' }).click();
  await expect(page.getByRole('heading', { name: 'Timeline', level: 1 })).toBeVisible();
  const download = page.waitForEvent('download');
  await page.getByRole('group', { name: 'Export timeline' }).getByRole('link', { name: 'CSV' }).click();
  const csv = readFileSync(await (await download).path(), 'utf8');
  expect(csv).toMatch(/^timestamp,event_id,event_type,/);
  expect(csv).toContain(timeline.items[0]!.id);
});
