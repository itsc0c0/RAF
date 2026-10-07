import { useRef, type KeyboardEvent, type ReactNode } from 'react';
import { cx } from '../lib/cx';

export interface TabItem<K extends string> {
  key: K;
  label: ReactNode;
  badge?: ReactNode;
  disabled?: boolean;
}

/** Accessible tab strip (arrow keys move between tabs). Panels are rendered by the caller. */
export function Tabs<K extends string>({
  items,
  value,
  onChange,
  label,
  idPrefix,
}: {
  items: readonly TabItem<K>[];
  value: K;
  onChange: (key: K) => void;
  label: string;
  idPrefix: string;
}) {
  const listRef = useRef<HTMLDivElement>(null);
  const enabled = items.filter((item) => !item.disabled);

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (!['ArrowRight', 'ArrowLeft', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault();
    const index = enabled.findIndex((item) => item.key === value);
    let next = index;
    if (event.key === 'ArrowRight') next = (index + 1) % enabled.length;
    if (event.key === 'ArrowLeft') next = (index - 1 + enabled.length) % enabled.length;
    if (event.key === 'Home') next = 0;
    if (event.key === 'End') next = enabled.length - 1;
    const target = enabled[next];
    if (!target) return;
    onChange(target.key);
    listRef.current
      ?.querySelector<HTMLButtonElement>(`#${CSS.escape(`${idPrefix}-tab-${target.key}`)}`)
      ?.focus();
  };

  return (
    <div className="tabs" role="tablist" aria-label={label} ref={listRef} onKeyDown={onKeyDown}>
      {items.map((item) => {
        const selected = item.key === value;
        return (
          <button
            key={item.key}
            type="button"
            role="tab"
            id={`${idPrefix}-tab-${item.key}`}
            aria-selected={selected}
            aria-controls={`${idPrefix}-panel`}
            tabIndex={selected ? 0 : -1}
            disabled={item.disabled}
            className={cx('tab', selected && 'is-selected')}
            onClick={() => onChange(item.key)}
          >
            {item.label}
            {item.badge !== undefined ? <span className="tab__badge">{item.badge}</span> : null}
          </button>
        );
      })}
    </div>
  );
}

export function TabPanel({
  idPrefix,
  activeKey,
  children,
}: {
  idPrefix: string;
  activeKey: string;
  children: ReactNode;
}) {
  return (
    <div
      role="tabpanel"
      id={`${idPrefix}-panel`}
      aria-labelledby={`${idPrefix}-tab-${activeKey}`}
      className="tabpanel"
    >
      {children}
    </div>
  );
}
