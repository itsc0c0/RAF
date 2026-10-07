import type { KeyboardEvent, ReactNode } from 'react';
import { cx } from '../lib/cx';

export interface Column<T> {
  key: string;
  header: ReactNode;
  render: (row: T) => ReactNode;
  width?: string;
  align?: 'left' | 'right' | 'center';
  className?: string;
}

/**
 * Data table. Rows are clickable when `onRowClick` is set; they are focusable and activate with
 * Enter/Space so the table stays keyboard operable.
 */
export function Table<T>({
  columns,
  rows,
  rowKey,
  onRowClick,
  selectedKey,
  caption,
  empty,
  dense = false,
  rowLabel,
}: {
  columns: readonly Column<T>[];
  rows: readonly T[];
  rowKey: (row: T) => string;
  onRowClick?: (row: T) => void;
  selectedKey?: string | null;
  caption?: string;
  empty?: ReactNode;
  dense?: boolean;
  /** Tooltip for clickable rows (e.g. "Open finding <title>"). */
  rowLabel?: (row: T) => string;
}) {
  const onKeyDown = (event: KeyboardEvent<HTMLTableRowElement>, row: T) => {
    if (!onRowClick) return;
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      onRowClick(row);
    }
  };
  return (
    <div className="table-wrap">
      <table className={cx('table', dense && 'table--dense', onRowClick && 'table--interactive')}>
        {caption ? <caption className="sr-only">{caption}</caption> : null}
        <thead>
          <tr>
            {columns.map((column) => (
              <th
                key={column.key}
                scope="col"
                style={{ width: column.width, textAlign: column.align }}
                className={column.className}
              >
                {column.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 ? (
            <tr className="table__empty">
              <td colSpan={columns.length}>{empty ?? <span className="muted">No rows.</span>}</td>
            </tr>
          ) : (
            rows.map((row) => {
              const key = rowKey(row);
              const selected = selectedKey === key;
              return (
                <tr
                  key={key}
                  className={cx(selected && 'is-selected')}
                  onClick={onRowClick ? () => onRowClick(row) : undefined}
                  onKeyDown={onRowClick ? (event) => onKeyDown(event, row) : undefined}
                  tabIndex={onRowClick ? 0 : undefined}
                  aria-selected={onRowClick ? selected : undefined}
                  title={onRowClick && rowLabel ? rowLabel(row) : undefined}
                >
                  {columns.map((column) => (
                    <td key={column.key} style={{ textAlign: column.align }} className={column.className}>
                      {column.render(row)}
                    </td>
                  ))}
                </tr>
              );
            })
          )}
        </tbody>
      </table>
    </div>
  );
}
