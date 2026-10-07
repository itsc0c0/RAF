import type { UseQueryResult } from '@tanstack/react-query';
import type { ReactNode } from 'react';
import { isApiError, type ApiError } from '../api/client';
import { cx } from '../lib/cx';
import { Button } from './Button';
import { Icon, type IconName } from './Icon';
import { LoadingState } from './Spinner';

export interface ErrorInfo {
  message: string;
  reason?: string;
  hint?: string;
  suggestions: string[];
  code?: string;
  status?: number;
}

export function describeError(error: unknown): ErrorInfo {
  if (isApiError(error)) {
    return {
      message: error.message,
      reason: error.reason,
      hint: error.hint,
      suggestions: error.suggestions,
      code: error.code,
      status: error.status,
    };
  }
  if (error instanceof Error) return { message: error.message || 'Unexpected error.', suggestions: [] };
  return { message: 'Unexpected error.', suggestions: [] };
}

/** Renders an API error: message, why (reason), what to do (hint), suggested commands. */
export function ErrorState({
  error,
  title,
  onRetry,
  compact = false,
}: {
  error: unknown;
  title?: string;
  onRetry?: () => void;
  compact?: boolean;
}) {
  const info = describeError(error);
  return (
    <div className={cx('state', 'state--error', compact && 'state--compact')} role="alert">
      <Icon name="warning" size={compact ? 16 : 20} className="state__icon" />
      <div className="state__body">
        {title ? <p className="state__title">{title}</p> : null}
        <p className="state__message">{info.message}</p>
        {info.reason ? (
          <p className="state__detail">
            <span className="state__label">Reason</span> {info.reason}
          </p>
        ) : null}
        {info.hint ? (
          <p className="state__detail">
            <span className="state__label">Hint</span> {info.hint}
          </p>
        ) : null}
        {info.suggestions.length > 0 ? (
          <div className="state__detail">
            <span className="state__label">Try</span>
            <ul className="state__suggestions">
              {info.suggestions.map((suggestion) => (
                <li key={suggestion}>
                  <code>{suggestion}</code>
                </li>
              ))}
            </ul>
          </div>
        ) : null}
        {info.code ? <p className="state__code mono">{info.code}</p> : null}
        {onRetry ? (
          <div className="state__actions">
            <Button size="sm" icon="refresh" onClick={onRetry}>
              Retry
            </Button>
          </div>
        ) : null}
      </div>
    </div>
  );
}

/** A capability that is not installed, not mounted or whose dependency is missing (404/503). */
export function UnavailableState({
  feature,
  error,
  compact = false,
}: {
  feature: string;
  error?: unknown;
  compact?: boolean;
}) {
  const info = error ? describeError(error) : null;
  const dependency = isApiError(error) && error.status === 503;
  return (
    <div className={cx('state', 'state--unavailable', compact && 'state--compact')} role="status">
      <Icon name="info" size={compact ? 16 : 20} className="state__icon" />
      <div className="state__body">
        <p className="state__title">{feature} is not available yet</p>
        <p className="state__message">
          {dependency
            ? 'A dependency this capability needs is not available on this R$F host.'
            : 'This R$F installation does not provide this capability yet, or the product is disabled.'}
        </p>
        {info && (info.reason || info.hint) ? (
          <p className="state__detail">{[info.reason, info.hint].filter(Boolean).join(' ')}</p>
        ) : null}
        {info?.code ? <p className="state__code mono">{info.code}</p> : null}
      </div>
    </div>
  );
}

export function EmptyState({
  icon = 'info',
  title,
  children,
  compact = false,
}: {
  icon?: IconName;
  title: string;
  children?: ReactNode;
  compact?: boolean;
}) {
  return (
    <div className={cx('state', 'state--empty', compact && 'state--compact')}>
      <Icon name={icon} size={compact ? 16 : 20} className="state__icon" />
      <div className="state__body">
        <p className="state__title">{title}</p>
        {children ? <div className="state__message">{children}</div> : null}
      </div>
    </div>
  );
}

/** Shown wherever a workspace has no data yet. */
export function NoDataHint({ title = 'This workspace has no data yet' }: { title?: string }) {
  return (
    <EmptyState icon="database" title={title}>
      <p>Load the synthetic demo organization or analyze your own evidence:</p>
      <ul className="state__suggestions">
        <li>
          <code>raf demo load</code> <span className="muted">— Raven Industries, incident INC-001</span>
        </li>
        <li>
          <code>raf analyze &lt;file&gt;</code> <span className="muted">— logs, exports, archives</span>
        </li>
      </ul>
      <p className="muted small">You can also use “Analyze Evidence” in the command palette (Ctrl/⌘ K).</p>
    </EmptyState>
  );
}

export function isUnavailableError(error: unknown): error is ApiError {
  return isApiError(error) && error.isUnavailable;
}

/**
 * Renders loading / unavailable / error states for a query and hands successful data to `children`.
 * 404s of missing endpoints and 503s degrade to an inline "not available yet" state.
 */
export function QueryView<T>({
  query,
  feature,
  children,
  loadingLabel,
  compact = false,
}: {
  query: UseQueryResult<T>;
  feature: string;
  children: (data: T) => ReactNode;
  loadingLabel?: string;
  compact?: boolean;
}) {
  if (query.isError && !query.data) {
    if (isUnavailableError(query.error))
      return <UnavailableState feature={feature} error={query.error} compact={compact} />;
    return <ErrorState error={query.error} onRetry={() => void query.refetch()} compact={compact} />;
  }
  if (query.data === undefined) {
    return query.fetchStatus === 'idle' ? null : <LoadingState label={loadingLabel} compact={compact} />;
  }
  return <>{children(query.data)}</>;
}
