import { expect, test } from './support/fixtures';

interface Replay {
  title: string;
  steps: Array<{ timestamp: string; summary: string }>;
  objects: Record<string, { name: string }>;
}

interface ReplayState {
  step_index: number;
  sessions: Array<{ user: string; host: string }>;
}

test('replay of INC-001 steps forward and rebuilds the state the server computes', async ({ page, api }) => {
  const replay = await api.get<Replay>('/replay/INC-001');
  const total = replay.steps.length;
  // The state after bob's login to DEV-01, computed by the server (the client replays the steps itself).
  const login = replay.steps.findIndex((step) => step.summary.startsWith('bob logged into DEV-01'));
  expect(login).toBeGreaterThan(0);
  const state = await api.get<ReplayState>(
    `/replay/INC-001/state?at=${encodeURIComponent(replay.steps[login]!.timestamp)}`,
  );
  expect(state.sessions.length).toBeGreaterThan(0);

  await page.goto('/replay');
  await page
    .getByRole('table', { name: 'Incidents' })
    .getByRole('row', { name: /INC-001/ })
    .click();
  await expect(page).toHaveURL(/\/replay\?incident=incident%3Ainc-001$/);
  await expect(page.getByText(replay.title, { exact: true })).toBeVisible();

  const controls = page.getByRole('group', { name: 'Playback controls' });
  const log = page.getByRole('list', { name: 'Replay event log' });
  await expect(controls).toContainText(`step 0 / ${total}`);
  await expect(controls.getByRole('button', { name: 'Step back (←)' })).toBeDisabled();
  await expect(page.getByText(/^Initial state at .* Press play or step forward\.$/)).toBeVisible();

  await controls.getByRole('button', { name: 'Step forward (→)' }).click();
  await expect(controls).toContainText(`step 1 / ${total}`);
  await expect(log.locator('[aria-current="step"]')).toContainText(replay.steps[0]!.summary);
  await expect(controls.getByRole('button', { name: 'Step back (←)' })).toBeEnabled();

  // → steps forward too, unless the focus is in a control.
  await page.getByRole('heading', { name: 'Replay', level: 1 }).click();
  await page.keyboard.press('ArrowRight');
  await expect(controls).toContainText(`step 2 / ${total}`);
  await expect(log.locator('[aria-current="step"]')).toContainText(replay.steps[1]!.summary);

  for (let step = 3; step <= state.step_index + 1; step += 1) {
    await controls.getByRole('button', { name: 'Step forward (→)' }).click();
    await expect(controls).toContainText(`step ${step} / ${total}`);
  }
  const sessions = page.getByRole('region', { name: 'Active sessions' });
  await expect(sessions.getByRole('heading')).toHaveText(`Active sessions ${state.sessions.length}`);
  for (const session of state.sessions) {
    await expect(sessions).toContainText(replay.objects[session.host]?.name ?? session.host);
  }
});
