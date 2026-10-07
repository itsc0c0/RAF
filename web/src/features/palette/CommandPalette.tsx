import { useId, useMemo, useState, type KeyboardEvent } from 'react';
import { usePalette } from '../../app/shellState';
import { Button } from '../../components/Button';
import { Kbd } from '../../components/Data';
import { Icon } from '../../components/Icon';
import { Modal } from '../../components/Modal';
import { Spinner } from '../../components/Spinner';
import { cx } from '../../lib/cx';
import { useDebouncedValue, useDocumentKeydown } from '../../lib/hooks';
import { fuzzyFilter } from './fuzzy';
import { usePaletteCommands, type PaletteCommand, type PromptSpec } from './usePaletteCommands';

const MAX_RESULTS = 40;

/** Global Ctrl/⌘+K handler plus the palette dialog. Mounted once by the shell. */
export function CommandPaletteHost() {
  const { isOpen, toggle, close } = usePalette();
  useDocumentKeydown((event) => {
    if ((event.ctrlKey || event.metaKey) && !event.altKey && event.key.toLowerCase() === 'k') {
      event.preventDefault();
      toggle();
    }
  });
  return isOpen ? <CommandPalette onClose={close} /> : null;
}

function PromptForm({
  spec,
  onDone,
  onCancel,
}: {
  spec: PromptSpec;
  onDone: () => void;
  onCancel: () => void;
}) {
  const [value, setValue] = useState(spec.initial);
  const [busy, setBusy] = useState(false);
  const inputId = useId();
  const submit = () => {
    const text = value.trim();
    if (!text || busy) return;
    setBusy(true);
    spec.submit(text).then(onDone, () => setBusy(false));
  };
  return (
    <form
      className="palette__prompt"
      onSubmit={(event) => {
        event.preventDefault();
        submit();
      }}
    >
      <label className="field__label" htmlFor={inputId}>
        {spec.label}
      </label>
      <input
        id={inputId}
        className="input"
        value={value}
        data-autofocus
        autoComplete="off"
        spellCheck={false}
        onChange={(event) => setValue(event.target.value)}
      />
      <div className="row row--between">
        <Button variant="ghost" onClick={onCancel}>
          Back
        </Button>
        <Button type="submit" variant="primary" loading={busy} disabled={!value.trim()}>
          {spec.submitLabel}
        </Button>
      </div>
    </form>
  );
}

export function CommandPalette({ onClose }: { onClose: () => void }) {
  const [query, setQuery] = useState('');
  const [active, setActive] = useState(0);
  const [prompt, setPrompt] = useState<PromptSpec | null>(null);
  const liveQuery = useDebouncedValue(query, 200);
  const { commands, live, liveLoading } = usePaletteCommands(liveQuery);
  const listId = useId();

  const results = useMemo(() => {
    const ranked = fuzzyFilter(commands, query, (command) => `${command.label} ${command.keywords ?? ''}`);
    const seen = new Set(ranked.map((command) => command.id));
    return [...ranked, ...live.filter((command) => !seen.has(command.id))].slice(0, MAX_RESULTS);
  }, [commands, live, query]);

  const activeIndex = results.length === 0 ? -1 : Math.min(active, results.length - 1);

  const execute = (command: PaletteCommand | undefined) => {
    if (!command) return;
    if (command.prompt) {
      setPrompt(command.prompt());
      return;
    }
    onClose();
    command.run?.();
  };

  const onKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault();
      if (results.length === 0) return;
      const delta = event.key === 'ArrowDown' ? 1 : -1;
      setActive((activeIndex + delta + results.length) % results.length);
    } else if (event.key === 'Enter') {
      event.preventDefault();
      execute(results[activeIndex]);
    }
  };

  if (prompt) {
    return (
      <Modal title={prompt.title} onClose={onClose} size="sm" className="palette">
        <PromptForm spec={prompt} onDone={onClose} onCancel={() => setPrompt(null)} />
      </Modal>
    );
  }

  return (
    <Modal ariaLabel="Command palette" onClose={onClose} hideHeader size="md" className="palette">
      <div className="palette__search">
        <Icon name="command" />
        <input
          className="palette__input"
          role="combobox"
          aria-expanded="true"
          aria-controls={listId}
          aria-autocomplete="list"
          aria-activedescendant={activeIndex >= 0 ? `${listId}-${activeIndex}` : undefined}
          aria-label="Type a command or search objects"
          placeholder="Type a command or search objects…"
          value={query}
          data-autofocus
          autoComplete="off"
          spellCheck={false}
          onChange={(event) => {
            setQuery(event.target.value);
            setActive(0);
          }}
          onKeyDown={onKeyDown}
        />
        {liveLoading ? <Spinner size={14} /> : null}
      </div>
      <ul className="palette__list" role="listbox" id={listId} aria-label="Commands">
        {results.length === 0 ? (
          <li className="palette__empty" role="presentation">
            No matching commands{query.trim() ? ' or objects' : ''}.
          </li>
        ) : (
          results.map((command, index) => (
            <li
              key={command.id}
              id={`${listId}-${index}`}
              role="option"
              aria-selected={index === activeIndex}
              className={cx('palette__item', index === activeIndex && 'is-active')}
              onMouseMove={() => {
                if (index !== activeIndex) setActive(index);
              }}
              onClick={() => execute(command)}
            >
              <Icon name={command.icon} className="palette__icon" />
              <span className="palette__label truncate">{command.label}</span>
              {command.detail ? <span className="palette__detail truncate">{command.detail}</span> : null}
              <span className="palette__group">{command.group}</span>
            </li>
          ))
        )}
      </ul>
      <footer className="palette__footer">
        <span>
          <Kbd>↑</Kbd>
          <Kbd>↓</Kbd> navigate
        </span>
        <span>
          <Kbd>Enter</Kbd> run
        </span>
        <span>
          <Kbd>Esc</Kbd> close
        </span>
      </footer>
    </Modal>
  );
}
