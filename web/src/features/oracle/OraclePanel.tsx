import { useId, useState } from 'react';
import { useOracleAsk, useOracleStatus } from '../../api/hooks';
import type { OracleAnswer } from '../../api/types';
import { useOracle } from '../../app/shellState';
import { Badge } from '../../components/Badge';
import { Button } from '../../components/Button';
import { CopyButton } from '../../components/Data';
import { Drawer } from '../../components/Drawer';
import { Icon } from '../../components/Icon';
import { ObjectChip } from '../../components/ObjectChip';
import { Callout } from '../../components/Panel';
import { ErrorState, isUnavailableError, UnavailableState } from '../../components/States';
import { displayValue } from '../../lib/format';

interface Exchange {
  id: number;
  question: string;
  answer?: OracleAnswer;
  error?: unknown;
}

export const ORACLE_DISCLAIMER = 'AI output is not authoritative; verify against R$F data.';

/** Renders an Oracle answer. Everything is text; citations become inspector chips. */
export function OracleAnswerView({ answer }: { answer: OracleAnswer }) {
  const citations = Array.isArray(answer.citations) ? answer.citations : [];
  const invalid = Array.isArray(answer.invalid_references) ? answer.invalid_references : [];
  const facts = Array.isArray(answer.facts) ? answer.facts : [];
  const suggestions = Array.isArray(answer.suggestions) ? answer.suggestions : [];
  return (
    <div className="oracle-answer">
      <div className="row row--wrap small muted">
        <Badge tone="violet">AI</Badge>
        <span>
          {displayValue(answer.provider)} · {displayValue(answer.mode)}
        </span>
      </div>
      <p className="oracle-answer__text">{answer.answer}</p>
      {invalid.length > 0 ? (
        <div className="oracle-answer__invalid" role="note">
          <p className="row">
            <Icon name="warning" size={14} />
            <strong>Unverified references</strong>
          </p>
          <p className="small">These identifiers were mentioned but do not exist in this workspace:</p>
          <ul className="row row--wrap">
            {invalid.map((ref) => (
              <li key={ref}>
                <span className="tag tag--bad mono">{ref}</span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      {citations.length > 0 ? (
        <div className="stack stack--tight">
          <h4>Cited R$F data</h4>
          <div className="row row--wrap">
            {citations.map((citation) => (
              <ObjectChip key={citation.id} id={citation.id} name={citation.label} />
            ))}
          </div>
        </div>
      ) : null}
      {facts.length > 0 ? (
        <div className="stack stack--tight">
          <h4>Facts used</h4>
          <ul className="oracle-answer__facts">
            {facts.map((fact) => (
              <li key={fact.key}>
                <span>{fact.text}</span>
                {fact.refs?.length ? (
                  <span className="row row--wrap">
                    {fact.refs.map((ref) => (
                      <ObjectChip key={ref} id={ref} showType={false} />
                    ))}
                  </span>
                ) : null}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      {suggestions.length > 0 ? (
        <div className="stack stack--tight">
          <h4>Suggested commands</h4>
          <ul className="stack stack--tight">
            {suggestions.map((command) => (
              <li key={command} className="row">
                <code className="grow break">{command}</code>
                <CopyButton value={command} label="Copy command" />
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}

function StatusLine() {
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

function OraclePanel({ onClose }: { onClose: () => void }) {
  const { draft } = useOracle();
  const [question, setQuestion] = useState(draft);
  const [history, setHistory] = useState<Exchange[]>([]);
  const ask = useOracleAsk();
  const inputId = useId();

  const submit = () => {
    const text = question.trim();
    if (!text || ask.isPending) return;
    exchangeId += 1;
    const id = exchangeId;
    ask.mutate(text, {
      onSuccess: (answer) => setHistory((items) => [...items, { id, question: text, answer }]),
      onError: (error) => setHistory((items) => [...items, { id, question: text, error }]),
    });
    setQuestion('');
  };

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
        {history.length === 0 ? (
          <p className="muted small">
            Ask about this workspace, e.g. “What happened in INC-001?” or “Which identities can reach DB-01?”
          </p>
        ) : null}
        <ol className="oracle-history">
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
            submit();
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
                submit();
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
    </Drawer>
  );
}

/** Mounted once by the shell. */
export function OracleHost() {
  const { isOpen, close } = useOracle();
  return isOpen ? <OraclePanel onClose={close} /> : null;
}
