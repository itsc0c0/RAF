import { useId, useMemo, useRef, useState, type KeyboardEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { useSearch } from '../../api/hooks';
import { useInspector } from '../../app/shellState';
import { SeverityBadge } from '../../components/Badge';
import { Kbd } from '../../components/Data';
import { Icon } from '../../components/Icon';
import { TypeTag } from '../../components/ObjectChip';
import { Spinner } from '../../components/Spinner';
import { describeError } from '../../components/States';
import { cx } from '../../lib/cx';
import { isEditableTarget, useDebouncedValue, useDocumentKeydown } from '../../lib/hooks';
import { routeTo } from '../../lib/routes';

interface SearchOption {
  key: string;
  group: 'Incidents' | 'Objects' | 'Findings';
  label: string;
  secondary: string;
  type?: string;
  severity?: string;
  select: () => void;
}

/** Top-bar search (`GET /search`): ↑/↓ to move, Enter to open in the inspector, Esc to close. */
export function GlobalSearch() {
  const [text, setText] = useState('');
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listId = useId();
  const debounced = useDebouncedValue(text, 250);
  const search = useSearch(open ? debounced : '');
  const inspector = useInspector();
  const navigate = useNavigate();

  useDocumentKeydown((event) => {
    if (event.key === '/' && !event.ctrlKey && !event.metaKey && !isEditableTarget(event.target)) {
      event.preventDefault();
      inputRef.current?.focus();
    }
  });

  const options = useMemo<SearchOption[]>(() => {
    const data = search.data;
    if (!data || !debounced.trim()) return [];
    return [
      ...data.incidents.map<SearchOption>((object) => ({
        key: `i:${object.id}`,
        group: 'Incidents',
        label: object.name,
        secondary: typeof object.metadata.title === 'string' ? object.metadata.title : object.id,
        type: object.type,
        select: () => inspector.open(object.id),
      })),
      ...data.objects.map<SearchOption>((object) => ({
        key: `o:${object.id}`,
        group: 'Objects',
        label: object.name,
        secondary: object.id,
        type: object.type,
        select: () => inspector.open(object.id),
      })),
      ...data.findings.map<SearchOption>((finding) => ({
        key: `f:${finding.id}`,
        group: 'Findings',
        label: finding.title,
        secondary: `${finding.product} · ${finding.status}`,
        severity: finding.severity,
        select: () => void navigate(routeTo.finding(finding.id)),
      })),
    ];
  }, [search.data, debounced, inspector, navigate]);

  const activeIndex = options.length === 0 ? -1 : Math.min(active, options.length - 1);
  const showList = open && text.trim().length > 0;

  const choose = (option: SearchOption | undefined) => {
    if (!option) return;
    option.select();
    setOpen(false);
    inputRef.current?.blur();
  };

  const onKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault();
      setOpen(true);
      if (options.length === 0) return;
      const delta = event.key === 'ArrowDown' ? 1 : -1;
      setActive((activeIndex + delta + options.length) % options.length);
    } else if (event.key === 'Enter') {
      event.preventDefault();
      const reference = text.trim();
      if (options.length > 0 && debounced === text && !search.isPlaceholderData) {
        choose(options[activeIndex]);
      } else if (reference) {
        // Results not in yet (or none): the API resolves IDs, names and aliases directly.
        inspector.open(reference);
        setOpen(false);
        inputRef.current?.blur();
      }
    } else if (event.key === 'Escape') {
      if (showList) {
        event.preventDefault();
        setOpen(false);
      } else {
        setText('');
        inputRef.current?.blur();
      }
    }
  };

  return (
    <div
      className="search"
      onBlur={(event) => {
        if (!event.currentTarget.contains(event.relatedTarget)) setOpen(false);
      }}
    >
      <Icon name="search" className="search__icon" />
      <input
        ref={inputRef}
        className="search__input"
        type="search"
        placeholder="Search R$F..."
        role="combobox"
        aria-label="Search R$F"
        aria-expanded={showList}
        aria-controls={listId}
        aria-autocomplete="list"
        aria-activedescendant={showList && activeIndex >= 0 ? `${listId}-${activeIndex}` : undefined}
        autoComplete="off"
        spellCheck={false}
        maxLength={200}
        value={text}
        onChange={(event) => {
          setText(event.target.value);
          setActive(0);
          setOpen(true);
        }}
        onFocus={() => setOpen(true)}
        onKeyDown={onKeyDown}
      />
      {search.isFetching && open ? <Spinner size={14} className="search__spinner" /> : <Kbd>/</Kbd>}
      {showList ? (
        <div className="search__popover">
          <ul className="search__list" role="listbox" id={listId} aria-label="Search results">
            {options.map((option, index) => {
              const header = index === 0 || options[index - 1]?.group !== option.group ? option.group : null;
              return (
                <li key={option.key} role="presentation">
                  {header ? (
                    <div className="search__group" role="presentation">
                      {header}
                    </div>
                  ) : null}
                  <div
                    id={`${listId}-${index}`}
                    role="option"
                    aria-selected={index === activeIndex}
                    className={cx('search__option', index === activeIndex && 'is-active')}
                    onMouseDown={(event) => event.preventDefault()}
                    onMouseMove={() => {
                      if (index !== activeIndex) setActive(index);
                    }}
                    onClick={() => choose(option)}
                  >
                    {option.type ? <TypeTag type={option.type} /> : null}
                    {option.severity ? <SeverityBadge severity={option.severity} /> : null}
                    <span className="search__label truncate">{option.label}</span>
                    <span className="search__secondary truncate mono">{option.secondary}</span>
                  </div>
                </li>
              );
            })}
          </ul>
          {search.isError ? (
            <p className="search__status" role="alert">
              {describeError(search.error).message}
            </p>
          ) : options.length === 0 && !search.isFetching && debounced === text ? (
            <p className="search__status">No objects, incidents or findings match “{text.trim()}”.</p>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
