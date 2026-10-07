import { cx } from '../lib/cx';

export function Spinner({ size = 16, className }: { size?: number; className?: string }) {
  return (
    <span className={cx('spinner', className)} style={{ width: size, height: size }} aria-hidden="true" />
  );
}

export function LoadingState({ label = 'Loading…', compact = false }: { label?: string; compact?: boolean }) {
  return (
    <div
      className={cx('loading-state', compact && 'loading-state--compact')}
      role="status"
      aria-live="polite"
    >
      <Spinner />
      <span>{label}</span>
    </div>
  );
}

export function Skeleton({ lines = 3 }: { lines?: number }) {
  return (
    <div className="skeleton" aria-hidden="true">
      {Array.from({ length: lines }, (_, index) => (
        <span key={index} className="skeleton__line" style={{ width: `${92 - ((index * 17) % 40)}%` }} />
      ))}
    </div>
  );
}
