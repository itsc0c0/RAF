import { expect, test } from './support/fixtures';

interface Citation {
  id: string;
  label: string;
  type: string;
}

interface Answer {
  citations: Citation[];
  invalid_references: string[];
}

const QUESTION = 'Explain the most important security path in INC-001';

test('an Oracle answer about INC-001 cites R$F data, and each citation opens what it cites', async ({
  page,
  api,
}) => {
  // The builtin reasoner is deterministic: the page gets the same citations as this request.
  const expected = await api.post<Answer>('/oracle/ask', { question: QUESTION });
  const cite = (type: string) => {
    const citation = expected.citations.find((item) => item.type === type);
    if (!citation) throw new Error(`the answer cites no ${type}`);
    return citation;
  };
  const host = cite('host');
  const event = cite('event');
  const finding = cite('finding');

  await page.goto('/oracle');
  await expect(page.getByRole('heading', { name: 'Oracle', level: 1 })).toBeVisible();
  await expect(page.getByText('AI output is not authoritative', { exact: false }).first()).toBeVisible();
  await page.getByRole('textbox', { name: 'Question' }).fill(QUESTION);
  await page.getByRole('button', { name: 'Ask', exact: true }).click();

  const exchange = page
    .getByRole('list', { name: 'Questions and answers' })
    .getByRole('listitem')
    .filter({ hasText: QUESTION });
  await expect(exchange).toContainText('Most important security path');
  await expect(exchange).toContainText('bob → DEV-01');
  await expect(exchange.getByText('Unverified references')).toHaveCount(
    expected.invalid_references.length ? 1 : 0,
  );

  // Objects, events and findings are buttons; relationships have no view of their own.
  const cited = exchange.getByRole('group', { name: 'Cited R$F data' });
  await expect(cited.getByRole('button')).toHaveCount(
    expected.citations.filter((citation) => citation.type !== 'relationship').length,
  );

  await cited.getByTitle(`Inspect ${host.id}`, { exact: true }).click();
  const inspector = page.getByRole('dialog', { name: host.label });
  await expect(inspector).toContainText('Object inspector');
  await expect(inspector).toContainText(host.id);
  await inspector.getByRole('button', { name: 'Close inspector' }).click();
  await expect(inspector).toBeHidden();

  await cited.getByTitle(`Inspect event ${event.id}`, { exact: true }).click();
  const eventView = page.getByRole('dialog').filter({ hasText: 'Event ID' });
  await expect(eventView).toContainText(event.id);
  await eventView.getByRole('button', { name: 'Close inspector' }).click();
  await expect(eventView).toBeHidden();

  await cited.getByTitle(`Open finding ${finding.id}`, { exact: true }).click();
  await expect(page).toHaveURL(`/findings?finding=${encodeURIComponent(finding.id)}`);
  const drawer = page.getByRole('dialog', { name: finding.label });
  await expect(drawer).toContainText('Finding');
  await expect(drawer).toContainText(finding.id);
});
