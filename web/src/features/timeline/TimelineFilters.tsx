import { useState } from 'react';
import { SEVERITIES } from '../../api/types';
import { Button } from '../../components/Button';
import { Field, Select, TextInput } from '../../components/Form';
import { inputFromIso, isoFromInput } from '../../lib/format';
import { EMPTY_FILTERS, GROUP_FIELDS, type GroupField, type TimelineFilterState } from './filters';

export const FILTER_HELP =
  'Keys: type, category, actor, target, object, severity (>=), outcome, source, after, before, incident, job, synthetic. Free text matches messages. Example: type:auth.* actor:bob severity>=medium after:2026-10-06T22:00Z';

/**
 * Timeline filter form. Edits are local until "Apply" (or Enter), so typing never triggers a
 * request per keystroke. Remount it (key) when the applied state changes elsewhere.
 */
export function TimelineFilters({
  value,
  onApply,
  scopeLabel = 'Scope',
}: {
  value: TimelineFilterState;
  onApply: (next: TimelineFilterState) => void;
  scopeLabel?: string;
}) {
  const [draft, setDraft] = useState(value);
  const [startInput, setStartInput] = useState(inputFromIso(value.start));
  const [endInput, setEndInput] = useState(inputFromIso(value.end));
  const set = <K extends keyof TimelineFilterState>(key: K, next: TimelineFilterState[K]) =>
    setDraft((current) => ({ ...current, [key]: next }));

  return (
    <form
      className="filters"
      aria-label="Timeline filters"
      onSubmit={(event) => {
        event.preventDefault();
        onApply({ ...draft, start: isoFromInput(startInput), end: isoFromInput(endInput) });
      }}
    >
      <Field label={scopeLabel} className="filters__scope">
        {(id) => (
          <TextInput
            id={id}
            value={draft.scope}
            placeholder="workspace, INC-001, host:ws-04, alice…"
            onChange={(event) => set('scope', event.target.value)}
          />
        )}
      </Field>
      <Field label="Event types">
        {(id) => (
          <TextInput
            id={id}
            value={draft.types}
            placeholder="auth.login, process.start"
            onChange={(event) => set('types', event.target.value)}
          />
        )}
      </Field>
      <Field label="Category">
        {(id) => (
          <TextInput
            id={id}
            value={draft.category}
            placeholder="auth, network"
            onChange={(event) => set('category', event.target.value)}
          />
        )}
      </Field>
      <Field label="Min severity">
        {(id) => (
          <Select
            id={id}
            value={draft.severity}
            options={[
              { value: '', label: 'Any' },
              ...SEVERITIES.map((severity) => ({ value: severity, label: severity })),
            ]}
            onChange={(event) => set('severity', event.target.value)}
          />
        )}
      </Field>
      <Field
        label="Filter"
        className="filters__query"
        hint={<span title={FILTER_HELP}>R$F filter language · hover for keys</span>}
      >
        {(id) => (
          <TextInput
            id={id}
            className="mono"
            value={draft.filter}
            placeholder='type:auth.* actor:bob severity>=medium "exfil"'
            title={FILTER_HELP}
            onChange={(event) => set('filter', event.target.value)}
          />
        )}
      </Field>
      <Field label="From (UTC)">
        {(id) => (
          <input
            id={id}
            className="input"
            type="datetime-local"
            step={1}
            value={startInput}
            onChange={(event) => setStartInput(event.target.value)}
          />
        )}
      </Field>
      <Field label="To (UTC)">
        {(id) => (
          <input
            id={id}
            className="input"
            type="datetime-local"
            step={1}
            value={endInput}
            onChange={(event) => setEndInput(event.target.value)}
          />
        )}
      </Field>
      <Field label="Group by">
        {(id) => (
          <Select
            id={id}
            value={draft.groupBy}
            options={GROUP_FIELDS.map((field) => ({ value: field, label: field.replace('_', ' ') }))}
            onChange={(event) => set('groupBy', event.target.value as GroupField)}
          />
        )}
      </Field>
      <div className="filters__actions">
        <Button type="submit" variant="primary" icon="filter">
          Apply
        </Button>
        <Button
          variant="ghost"
          onClick={() => {
            const reset = { ...EMPTY_FILTERS, scope: value.scope };
            setDraft(reset);
            setStartInput('');
            setEndInput('');
            onApply(reset);
          }}
        >
          Reset
        </Button>
      </div>
    </form>
  );
}
