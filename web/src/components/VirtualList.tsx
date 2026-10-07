import { useVirtualizer } from '@tanstack/react-virtual';
import { useEffect, useRef, type KeyboardEvent, type ReactNode } from 'react';
import { cx } from '../lib/cx';
import { useLatest } from '../lib/hooks';

/**
 * Windowed list: only the visible rows (plus overscan) are in the DOM, so tens of thousands of rows
 * scroll smoothly. Fixed row height keeps scrolling math exact. ↑/↓ move focus between rows.
 */
export function VirtualList<T>({
  items,
  rowHeight,
  renderRow,
  getKey,
  height,
  onEndReached,
  endThreshold = 25,
  overscan = 10,
  label,
  className,
  activeIndex,
}: {
  items: readonly T[];
  rowHeight: number;
  renderRow: (item: T, index: number) => ReactNode;
  getKey: (item: T, index: number) => string;
  height: number | string;
  /** Called when the visible window approaches the end (load the next page). */
  onEndReached?: () => void;
  endThreshold?: number;
  overscan?: number;
  label: string;
  className?: string;
  /** Row to highlight/scroll into view (e.g. the selected event). */
  activeIndex?: number | null;
}) {
  const parentRef = useRef<HTMLDivElement>(null);
  // TanStack Virtual returns non-memoizable functions; this app does not use the React Compiler.
  // eslint-disable-next-line react-hooks/incompatible-library
  const virtualizer = useVirtualizer({
    count: items.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => rowHeight,
    overscan,
    getItemKey: (index) => getKey(items[index]!, index),
  });
  const virtualItems = virtualizer.getVirtualItems();
  const lastIndex = virtualItems.length > 0 ? virtualItems[virtualItems.length - 1]!.index : -1;
  const onEnd = useLatest(onEndReached);

  useEffect(() => {
    if (lastIndex >= 0 && lastIndex >= items.length - 1 - endThreshold) onEnd.current?.();
  }, [lastIndex, items.length, endThreshold, onEnd]);

  useEffect(() => {
    if (activeIndex !== null && activeIndex !== undefined && activeIndex >= 0) {
      virtualizer.scrollToIndex(activeIndex, { align: 'auto' });
    }
  }, [activeIndex, virtualizer]);

  const focusRow = (index: number) => {
    virtualizer.scrollToIndex(index, { align: 'auto' });
    window.requestAnimationFrame(() => {
      parentRef.current
        ?.querySelector<HTMLElement>(`[data-index="${index}"] button, [data-index="${index}"] [tabindex="0"]`)
        ?.focus({ preventScroll: true });
    });
  };

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return;
    const row = (event.target as HTMLElement).closest<HTMLElement>('[data-index]');
    if (!row) return;
    event.preventDefault();
    const index = Number(row.dataset.index);
    const next = event.key === 'ArrowDown' ? Math.min(items.length - 1, index + 1) : Math.max(0, index - 1);
    if (next !== index) focusRow(next);
  };

  return (
    <div
      ref={parentRef}
      className={cx('vlist', className)}
      style={{ height }}
      role="list"
      aria-label={label}
      onKeyDown={onKeyDown}
    >
      <div className="vlist__inner" style={{ height: virtualizer.getTotalSize() }}>
        {virtualItems.map((virtualItem) => {
          const item = items[virtualItem.index];
          if (item === undefined) return null;
          return (
            <div
              key={virtualItem.key}
              role="listitem"
              data-index={virtualItem.index}
              className="vlist__row"
              style={{ height: virtualItem.size, transform: `translateY(${virtualItem.start}px)` }}
            >
              {renderRow(item, virtualItem.index)}
            </div>
          );
        })}
      </div>
    </div>
  );
}
