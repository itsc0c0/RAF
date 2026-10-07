import { expect, test } from './support/fixtures';

interface Blast {
  reachable_assets: number;
  critical_assets: number;
  privileged_paths: number;
  max_depth: number;
  primary_path: Array<{ source_name?: string; target_name?: string; why: string }>;
  direct: unknown[];
  indirect: unknown[];
  risk: {
    score: number;
    level: string;
    factors: Array<{ label: string; sign: string; points: number }>;
  };
}

test('blast radius of alice: risk score with its factors and the primary path', async ({ page, api }) => {
  const blast = await api.get<Blast>('/blast/alice');
  expect(blast.risk.factors.length).toBeGreaterThan(0);

  await page.goto('/exposure?blast=alice');
  await expect(page.getByRole('tab', { name: 'Blast radius' })).toHaveAttribute('aria-selected', 'true');
  const panel = page.getByRole('tabpanel', { name: 'Blast radius' });
  await expect(panel.getByText('Blast radius of')).toBeVisible();
  await expect(panel.getByRole('button', { name: 'user alice' }).first()).toBeVisible();
  await expect(panel.getByTitle(`Severity: ${blast.risk.level}`).first()).toBeVisible();
  for (const [label, value] of [
    ['Reachable assets', blast.reachable_assets],
    ['Critical assets', blast.critical_assets],
    ['Privileged paths', blast.privileged_paths],
    ['Max depth', blast.max_depth],
  ] as const) {
    await expect(panel).toContainText(new RegExp(`${label}\\s*${value}(?!\\d)`));
  }

  // The score and every factor that makes it up, with its signed points.
  await expect(
    panel.getByRole('heading', { name: `Risk · score ${blast.risk.score}`, exact: true }),
  ).toBeVisible();
  for (const factor of blast.risk.factors) {
    const item = panel.getByRole('listitem').filter({ hasText: factor.label });
    await expect(item).toHaveCount(1);
    await expect(
      item.getByLabel(`${factor.sign === '-' ? 'minus' : 'plus'} ${factor.points} points`),
    ).toBeVisible();
  }

  // Each hop of the primary path says why it is traversable.
  const path = panel.getByRole('list', { name: 'Primary attack path' });
  await expect(path.getByRole('listitem')).toHaveCount(blast.primary_path.length + 1);
  for (const hop of blast.primary_path) await expect(path).toContainText(`Why traversable: ${hop.why}`);
  await expect(panel.getByRole('heading', { name: `Direct (${blast.direct.length})` })).toBeVisible();
  await expect(panel.getByRole('heading', { name: `Indirect (${blast.indirect.length})` })).toBeVisible();
});
