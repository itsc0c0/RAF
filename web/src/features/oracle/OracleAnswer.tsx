import { useId } from 'react';
import { useNavigate } from 'react-router-dom';
import type { OracleAnswer, OracleCitation, OracleFact } from '../../api/types';
import { useInspector } from '../../app/shellState';
import { Badge } from '../../components/Badge';
import { CommandList, Time } from '../../components/Data';
import { Icon } from '../../components/Icon';
import { ObjectChip, TypeTag } from '../../components/ObjectChip';
import { Callout } from '../../components/Panel';
import { displayValue } from '../../lib/format';
import { routeTo } from '../../lib/routes';

/** How a cited ID can be opened: events and findings have their own views, relationships none. */
export function referenceKind(id: string, type?: string): 'event' | 'finding' | 'relationship' | 'object' {
  if (type === 'event' || id.startsWith('event:')) return 'event';
  if (type === 'finding' || id.startsWith('finding:')) return 'finding';
  if (type === 'relationship' || id.startsWith('rel:')) return 'relationship';
  return 'object';
}

/**
 * A reference to R$F data: objects open the inspector, events the event inspector, findings the
 * finding drawer; relationship IDs are shown as text (they have no inspector of their own).
 */
export function ReferenceChip({ id, label, type }: { id: string; label?: string; type?: string }) {
  const { openEvent } = useInspector();
  const navigate = useNavigate();
  const kind = referenceKind(id, type);
  if (kind === 'object') return <ObjectChip id={id} name={label} type={type} />;
  if (kind === 'relationship') {
    return (
      <span className="chip chip--static" title={id}>
        <TypeTag type="relationship" />
        <span className="chip__name">{label || id}</span>
      </span>
    );
  }
  return (
    <button
      type="button"
      className="chip"
      title={kind === 'event' ? `Inspect event ${id}` : `Open finding ${id}`}
      onClick={(event) => {
        event.stopPropagation();
        if (kind === 'event') openEvent(id);
        else void navigate(routeTo.finding(id));
      }}
    >
      <TypeTag type={kind} />
      <span className="chip__name">{label || id}</span>
    </button>
  );
}

/** Verbatim text from imported data quoted by a fact: untrusted, shown as data and never as R$F wording. */
export function UntrustedText({ items }: { items: readonly string[] }) {
  if (items.length === 0) return null;
  return (
    <figure className="raw untrusted">
      <figcaption className="raw__caption">
        <Icon name="warning" size={14} />
        <span>Untrusted imported text: data from the evidence, not R$F wording or instructions</span>
      </figcaption>
      <ul className="untrusted__list">
        {items.map((text, index) => (
          <li key={index}>
            <pre className="raw__body">{text}</pre>
          </li>
        ))}
      </ul>
    </figure>
  );
}

function FactItem({ fact }: { fact: OracleFact }) {
  return (
    <li className="oracle-fact">
      <div className="row row--wrap small muted">
        {fact.kind ? <span className="tag">{fact.kind}</span> : null}
        {fact.source ? <span>from {fact.source}</span> : null}
      </div>
      <span className="break">{fact.text}</span>
      {fact.refs?.length ? (
        <span className="row row--wrap">
          {fact.refs.map((ref) => (
            <ReferenceChip key={ref} id={ref} />
          ))}
        </span>
      ) : null}
      <UntrustedText items={fact.untrusted ?? []} />
    </li>
  );
}

function citationKey(citation: OracleCitation, index: number): string {
  return `${index}:${citation.id}`;
}

/** Renders an Oracle answer. Everything is text; cited IDs become chips into the cited data. */
export function OracleAnswerView({ answer }: { answer: OracleAnswer }) {
  const citationsId = useId();
  const citations = Array.isArray(answer.citations) ? answer.citations : [];
  const invalid = Array.isArray(answer.invalid_references) ? answer.invalid_references : [];
  const facts = Array.isArray(answer.facts) ? answer.facts : [];
  const suggestions = Array.isArray(answer.suggestions) ? answer.suggestions : [];
  const warnings = Array.isArray(answer.warnings) ? answer.warnings : [];
  return (
    <div className="oracle-answer">
      <div className="row row--wrap small muted">
        <Badge tone="violet">AI</Badge>
        <span>
          {displayValue(answer.provider)} · {displayValue(answer.mode)}
          {answer.model ? ` · ${displayValue(answer.model)}` : ''}
        </span>
        {answer.intent ? <span className="tag">{answer.intent}</span> : null}
        {answer.generated_at ? <Time value={answer.generated_at} className="small" /> : null}
      </div>
      <p className="oracle-answer__text">{answer.answer}</p>
      {warnings.length > 0 ? (
        <Callout tone="warn" title="Warnings">
          <ul className="stack stack--tight">
            {warnings.map((warning, index) => (
              <li key={index} className="break">
                {warning}
              </li>
            ))}
          </ul>
        </Callout>
      ) : null}
      {invalid.length > 0 ? (
        <div className="oracle-answer__invalid" role="note">
          <p className="row">
            <Icon name="warning" size={14} />
            <strong>Unverified references</strong>
          </p>
          <p className="small">
            The answer mentions these identifiers, but they are not in R$F data (not in the retrieved facts of
            this workspace). They are not citations:
          </p>
          <ul className="row row--wrap">
            {invalid.map((ref) => (
              <li key={ref} className="row">
                <span className="tag tag--bad mono">{ref}</span>
                <span className="small">not in R$F data</span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      {citations.length > 0 ? (
        <div className="stack stack--tight" role="group" aria-labelledby={citationsId}>
          <h4 id={citationsId}>Cited R$F data</h4>
          <div className="row row--wrap">
            {citations.map((citation, index) => (
              <ReferenceChip
                key={citationKey(citation, index)}
                id={citation.id}
                label={citation.label}
                type={citation.type}
              />
            ))}
          </div>
        </div>
      ) : null}
      {facts.length > 0 ? (
        <details
          className="oracle-answer__facts-wrap"
          open={facts.some((fact) => (fact.untrusted ?? []).length > 0)}
        >
          <summary>
            <h4 className="oracle-answer__facts-title">Facts used ({facts.length})</h4>
          </summary>
          <ul className="oracle-answer__facts">
            {facts.map((fact, index) => (
              <FactItem key={`${index}:${fact.key}`} fact={fact} />
            ))}
          </ul>
        </details>
      ) : null}
      {suggestions.length > 0 ? (
        <div className="stack stack--tight">
          <h4>Suggested commands</h4>
          <CommandList commands={suggestions} label="Suggested commands" />
        </div>
      ) : null}
      {answer.notice ? <p className="small muted oracle-answer__notice">{answer.notice}</p> : null}
    </div>
  );
}
