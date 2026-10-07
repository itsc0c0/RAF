import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { useOracle } from '../../app/shellState';
import { mockFetch, renderWithApp } from '../../test/utils';
import { InspectorHost } from '../inspector/InspectorHost';
import { ORACLE_DISCLAIMER, OracleHost } from './OraclePanel';

function OpenOracle() {
  const { open } = useOracle();
  return (
    <button type="button" onClick={() => open('What happened in INC-001?')}>
      open oracle
    </button>
  );
}

const ANSWER = {
  answer: 'bob logged into VPN-01 from 203.0.113.45 <img src=x onerror=alert(1)> and later...',
  provider: 'builtin',
  mode: 'facts',
  citations: [{ id: 'user:bob', label: 'bob' }],
  invalid_references: ['host:ghost-99'],
  facts: [{ key: 'f1', text: 'bob authenticated from 203.0.113.45', refs: ['ip:203.0.113.45'] }],
  suggestions: ['raf replay INC-001'],
};

describe('Oracle panel', () => {
  it('asks a question and renders the answer safely with citations and warnings', async () => {
    const user = userEvent.setup();
    const { calls } = mockFetch([
      { path: '/oracle/status', body: { provider: 'builtin', mode: 'facts', configured: true } },
      { method: 'POST', path: '/oracle/ask', body: ANSWER },
    ]);
    renderWithApp(
      <>
        <OpenOracle />
        <OracleHost />
        <InspectorHost />
      </>,
    );
    await user.click(await screen.findByRole('button', { name: 'open oracle' }));
    const panel = await screen.findByRole('dialog', { name: 'Oracle' });
    expect(within(panel).getByText(ORACLE_DISCLAIMER)).toBeInTheDocument();

    const question = within(panel).getByLabelText('Question');
    expect(question).toHaveValue('What happened in INC-001?');
    await user.click(within(panel).getByRole('button', { name: 'Ask' }));

    await within(panel).findByText(/bob logged into VPN-01/);
    expect(calls.find((call) => call.path === '/oracle/ask')?.body).toEqual({
      question: 'What happened in INC-001?',
    });
    expect(document.querySelector('img')).toBeNull();
    expect(within(panel).getByText(ANSWER.answer)).toBeInTheDocument();
    expect(within(panel).getByText('host:ghost-99')).toBeInTheDocument();
    expect(within(panel).getByText('Unverified references')).toBeInTheDocument();
    expect(within(panel).getByText('raf replay INC-001').tagName).toBe('CODE');

    // Citations are object chips that open the inspector.
    await user.click(within(panel).getByTitle('Inspect user:bob'));
    await waitFor(() => expect(screen.getByRole('dialog', { name: 'user:bob' })).toBeInTheDocument());
  });

  it('degrades to "not available yet" when the Oracle product is missing', async () => {
    const user = userEvent.setup();
    mockFetch([]);
    renderWithApp(
      <>
        <OpenOracle />
        <OracleHost />
      </>,
    );
    await user.click(await screen.findByRole('button', { name: 'open oracle' }));
    const panel = await screen.findByRole('dialog', { name: 'Oracle' });
    await user.click(within(panel).getByRole('button', { name: 'Ask' }));
    expect(await within(panel).findByText('Oracle is not available yet')).toBeInTheDocument();
  });
});
