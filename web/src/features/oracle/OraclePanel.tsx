import { useId, useState } from 'react';
import { useOracleAsk, useOracleStatus } from '../../api/hooks';
import type { OracleAnswer } from '../../api/types';
import { useOracle } from '../../app/shellState';
import { Button } from '../../components/Button';
import { Drawer } from '../../components/Drawer';
import { Icon } from '../../components/Icon';
import { Callout } from '../../components/Panel';
import { ErrorState, isUnavailableError, UnavailableState } from '../../components/States';
import { cx } from '../../lib/cx';
import { displayValue } from '../../lib/format';
import { OracleAnswerView } from './OracleAnswer';

export { OracleAnswerView } from './OracleAnswer';

interface Exchange {
  id: number;
  question: string;
  answer?: OracleAnswer;
  error?: unknown;
}

export const ORACLE_DISCLAIMER = 'AI output is not authoritative; verify against R$F data.';

export const EXAMPLE_QUESTIONS = [
  'What happened in INC-001?',
  'Which identities can reach DB-01?',
  'Explain the most important security path in INC-001',
];

export function StatusLine() {
  const status = useOracleStatus();
  if (status.isError) {
    return isUnavailableError(status.error) ? (
      <p className="small muted">Oracle status is not available yet.</p>
    ) : null;
  }
  if (!status.data) return null;
  const provider = status.data.provider ?? status.data.name;
  const mode = status.data.mode;
  return (
    <p className="small muted">
      Provider <span className="mono">{displayValue(provider ?? 'unknown')}</span>
      {mode !== undefined ? (
        <>
          {' '}
          · mode <span className="mono">{displayValue(mode)}</span>
        </>
      ) : null}
    </p>
  );
}

let exchangeId = 0;

/**
 * Question box and answer history (`POST /oracle/ask`), shared by the Oracle panel and the Oracle
 * page. Questions and answers stay in this view only; Oracle stores no answers.
 */
export function OracleConversation({
  initialQuestion = '',
  examples = false,
  wide = false,
}: {
  initialQuestion?: string;
  /** Offer example questions while the history is empty. */
  examples?: boolean;
  wide?: boolean;
}) {
  const [question, setQuestion] = useState(initialQuestion);
  const [history, setHistory] = useState<Exchange[]>([]);
  const ask = useOracleAsk();
  const inputId = useId();

  const submit = (text: string) => {
    const value = text.trim();
    if (!value || ask.isPending) return;
    exchangeId += 1;
    const id = exchangeId;
    ask.mutate(value, {
      onSuccess: (answer) => setHistory((items) => [...items, { id, question: value, answer }]),
      onError: (error) => setHistory((items) => [...items, { id, question: value, error }]),
    });
    setQuestion('');
  };

  return (
    <div className={cx('stack', wide && 'oracle-conversation--wide')}>
      {history.length === 0 ? (
        examples ? (
          <div className="stack stack--tight">
            <p className="muted small">Ask about this workspace, for example:</p>
            <div className="row row--wrap">
              {EXAMPLE_QUESTIONS.map((example) => (
                <Button
                  key={example}
                  size="sm"
                  variant="ghost"
                  icon="oracle"
                  onClick={() => setQuestion(example)}
                >
                  {example}
                </Button>
              ))}
            </div>
          </div>
        ) : (
          <p className="muted small">
            Ask about this workspace, e.g. “What happened in INC-001?” or “Which identities can reach DB-01?”
          </p>
        )
      ) : null}
      <ol className="oracle-history" aria-label="Questions and answers">
        {history.map((exchange) => (
          <li key={exchange.id} className="oracle-history__item">
            <p className="oracle-history__question">
              <Icon name="oracle" size={14} /> {exchange.question}
            </p>
            {exchange.answer ? <OracleAnswerView answer={exchange.answer} /> : null}
            {exchange.error ? (
              isUnavailableError(exchange.error) ? (
                <UnavailableState feature="Oracle" error={exchange.error} compact />
              ) : (
                <ErrorState error={exchange.error} compact />
              )
            ) : null}
          </li>
        ))}
      </ol>
      <form
        className="oracle-form"
        onSubmit={(event) => {
          event.preventDefault();
          submit(question);
        }}
      >
        <label htmlFor={inputId} className="field__label">
          Question
        </label>
        <textarea
          id={inputId}
          className="input textarea"
          rows={3}
          maxLength={2000}
          value={question}
          placeholder="Ask about objects, incidents, paths…"
          onChange={(event) => setQuestion(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) {
              event.preventDefault();
              submit(question);
            }
          }}
        />
        <div className="row row--between">
          <span className="small muted">Ctrl/⌘ + Enter to ask</span>
          <Button
            type="submit"
            variant="primary"
            icon="oracle"
            loading={ask.isPending}
            disabled={!question.trim()}
          >
            Ask
          </Button>
        </div>
      </form>
    </div>
  );
}

function OraclePanel({ onClose }: { onClose: () => void }) {
  const { draft } = useOracle();
  return (
    <Drawer
      title="Oracle"
      subtitle={<StatusLine />}
      onClose={onClose}
      closeLabel="Close Oracle"
      className="oracle"
    >
      <div className="stack">
        <Callout tone="warn">
          <strong>{ORACLE_DISCLAIMER}</strong> Answers are generated from facts in this workspace; check every
          cited object before acting on it.
        </Callout>
        <OracleConversation initialQuestion={draft} />
      </div>
    </Drawer>
  );
}

/** Mounted once by the shell. */
export function OracleHost() {
  const { isOpen, close } = useOracle();
  return isOpen ? <OraclePanel onClose={close} /> : null;
}
