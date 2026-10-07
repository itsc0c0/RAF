import { useEffect, useState, type ReactNode } from 'react';
import type { ScoreFactor } from '../api/types';
import { cx } from '../lib/cx';
import { displayValue, formatTimestamp, parseTime } from '../lib/format';
import { IconButton } from './Button';

/** UTC timestamp with the raw ISO value as tooltip. */
export function Time({ value, className }: { value: string | null | undefined; className?: string }) {
  if (!value || parseTime(value) === null) return <span className={cx('time', 'muted', className)}>—</span>;
  return (
    <time className={cx('time', 'tabular', className)} dateTime={value} title={value}>
      {formatTimestamp(value)}
    </time>
  );
}

/** Monospace identifier (IDs, hashes, paths), wraps anywhere so long values never overflow. */
export function Mono({
  children,
  className,
  title,
}: {
  children: ReactNode;
  className?: string;
  title?: string;
}) {
  return (
    <span className={cx('mono', 'break', className)} title={title}>
      {children}
    </span>
  );
}

export type KeyValueEntry = readonly [label: ReactNode, value: ReactNode, key?: string];

export function KeyValueList({
  entries,
  className,
}: {
  entries: readonly KeyValueEntry[];
  className?: string;
}) {
  return (
    <dl className={cx('kv', className)}>
      {entries.map(([label, value, key], index) => (
        <div className="kv__row" key={key ?? (typeof label === 'string' ? label : index)}>
          <dt className="kv__key">{label}</dt>
          <dd className="kv__value">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

/** Arbitrary (untrusted) metadata as a key/value list; values are always rendered as text. */
export function MetadataList({
  metadata,
  empty = 'No metadata.',
}: {
  metadata: Record<string, unknown>;
  empty?: string;
}) {
  const keys = Object.keys(metadata).sort();
  if (keys.length === 0) return <p className="muted small">{empty}</p>;
  return (
    <KeyValueList
      entries={keys.map((key) => [
        <span className="mono">{key}</span>,
        <span className="break">{displayValue(metadata[key])}</span>,
        key,
      ])}
    />
  );
}

export function CopyButton({ value, label = 'Copy to clipboard' }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) return undefined;
    const timer = window.setTimeout(() => setCopied(false), 1500);
    return () => window.clearTimeout(timer);
  }, [copied]);
  return (
    <IconButton
      size="sm"
      icon={copied ? 'check' : 'copy'}
      label={copied ? 'Copied' : label}
      onClick={() => {
        void navigator.clipboard?.writeText(value).then(
          () => setCopied(true),
          () => setCopied(false),
        );
      }}
    />
  );
}

export function Kbd({ children }: { children: ReactNode }) {
  return <kbd className="kbd">{children}</kbd>;
}

export function StatTile({ label, value, detail }: { label: string; value: ReactNode; detail?: ReactNode }) {
  return (
    <div className="stat">
      <p className="stat__label">{label}</p>
      <p className="stat__value">{value}</p>
      {detail ? <p className="stat__detail">{detail}</p> : null}
    </div>
  );
}

/** Horizontal meter (0..1) with a same-hue track. */
export function Meter({
  value,
  label,
  tone = 'accent',
}: {
  value: number;
  label: string;
  tone?: 'accent' | 'warn' | 'bad';
}) {
  const clamped = Math.max(0, Math.min(1, value));
  return (
    <span
      className={cx('meter', `meter--${tone}`)}
      role="meter"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={Math.round(clamped * 100)}
    >
      <span className="meter__fill" style={{ width: `${clamped * 100}%` }} />
    </span>
  );
}

export function TagList({ tags }: { tags: readonly string[] }) {
  if (tags.length === 0) return <span className="muted">—</span>;
  return (
    <span className="tags">
      {tags.map((tag) => (
        <span key={tag} className="tag">
          {tag}
        </span>
      ))}
    </span>
  );
}

/**
 * Explainable score: each factor with its signed points, plus the total. Factors are the "why"
 * behind exposure, blast risk and finding scores.
 */
export function FactorList({ factors, total }: { factors: readonly ScoreFactor[]; total?: number | null }) {
  if (factors.length === 0) return <p className="muted small">No scoring factors were reported.</p>;
  const scored = factors.some(
    (factor) => typeof factor.points === 'number' && Number.isFinite(factor.points),
  );
  const sum = factors.reduce((acc, factor) => acc + signedPoints(factor), 0);
  return (
    <div className="factors">
      <ul className="factors__list">
        {factors.map((factor, index) => {
          const points = signedPoints(factor);
          const negative = isNegative(factor);
          const hasPoints = typeof factor.points === 'number' && Number.isFinite(factor.points);
          return (
            <li
              key={`${factor.label}-${index}`}
              className={cx('factor', negative ? 'factor--minus' : 'factor--plus')}
            >
              <span
                className="factor__points tabular"
                aria-label={
                  hasPoints
                    ? `${negative ? 'minus' : 'plus'} ${Math.abs(points)} points`
                    : negative
                      ? 'decreases'
                      : 'increases'
                }
              >
                {negative ? '−' : '+'}
                {hasPoints ? Math.abs(points) : ''}
              </span>
              <span className="factor__label">{factor.label}</span>
              {factor.evidence && factor.evidence.length > 0 ? (
                <span
                  className="factor__evidence mono small muted truncate"
                  title={factor.evidence.join(', ')}
                >
                  {factor.evidence.join(', ')}
                </span>
              ) : null}
            </li>
          );
        })}
      </ul>
      {scored || (total !== undefined && total !== null) ? (
        <p className="factors__total">
          <span className="muted">Total</span> <strong className="tabular">{total ?? sum}</strong>
          {scored && total !== undefined && total !== null && total !== sum ? (
            <span className="muted small"> (factors sum to {sum})</span>
          ) : null}
        </p>
      ) : null}
    </div>
  );
}

function isNegative(factor: ScoreFactor): boolean {
  return (
    factor.sign === '-' || factor.sign === '−' || (typeof factor.points === 'number' && factor.points < 0)
  );
}

export function signedPoints(factor: ScoreFactor): number {
  const points =
    typeof factor.points === 'number' && Number.isFinite(factor.points) ? Math.abs(factor.points) : 0;
  return isNegative(factor) ? -points : points;
}
