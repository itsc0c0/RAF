import { expect, test } from './support/fixtures';

interface GraphView {
  nodes: Array<{ id: string; type: string; name: string }>;
  edges: Array<{ id: string; source: string; target: string }>;
}

test("the graph renders alice's neighborhood, filters it by type and selects a node", async ({
  page,
  api,
}) => {
  const view = await api.get<GraphView>('/graph/view?ref=alice&depth=2');
  const processes = new Set(view.nodes.filter((node) => node.type === 'process').map((node) => node.id));
  const withoutProcesses = {
    nodes: view.nodes.length - processes.size,
    edges: view.edges.filter((edge) => !processes.has(edge.source) && !processes.has(edge.target)).length,
  };
  expect(processes.size).toBeGreaterThan(0);

  await page.goto('/graph?focus=alice');
  await expect(page.getByRole('heading', { name: 'Graph', level: 1 })).toBeVisible();
  const canvas = page.getByRole('application', {
    name: `Graph of alice: ${view.nodes.length} nodes, ${view.edges.length} edges.`,
  });
  await expect(canvas).toBeVisible();
  // Cytoscape draws on canvas elements inside the container.
  await expect(canvas.locator('canvas').first()).toBeVisible();

  const tools = page.getByRole('complementary', { name: 'Graph filters and tools' });
  await tools.getByRole('checkbox', { name: `process ${processes.size}`, exact: true }).uncheck();
  await expect(
    page.getByRole('application', {
      name: `Graph of alice: ${withoutProcesses.nodes} nodes, ${withoutProcesses.edges} edges.`,
    }),
  ).toBeVisible();
  await tools.getByRole('checkbox', { name: `process ${processes.size}`, exact: true }).check();
  await expect(canvas).toBeVisible();

  await tools.getByRole('tab', { name: `Objects ${view.nodes.length}` }).click();
  const objects = tools.getByRole('list', { name: 'Objects in view' });
  for (const name of ['user alice', 'host WS-01', 'host DEV-01']) {
    await expect(objects.getByRole('button', { name, exact: true })).toBeVisible();
  }
  await objects.getByRole('button', { name: 'host DEV-01', exact: true }).click();
  const selected = page.getByLabel('Selected object');
  await expect(selected).toContainText('DEV-01');
  await expect(selected.getByRole('button', { name: 'Expand' })).toBeVisible();
  await expect(page.getByRole('dialog', { name: 'DEV-01' })).toContainText('host:dev-01');
});
