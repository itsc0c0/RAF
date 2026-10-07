import type { ReactNode } from 'react';
import type { ConfidenceLevel, Severity } from '../api/types';
import { cx } from '../lib/cx';
import { formatConfidence } from '../lib/format';

export type Tone = 'neutral' | 'accent' | 'good' | 'warn' | 'bad' | 'violet';

export interface BadgeProps {
  tone?: Tone;
  outline?: boolean;
  title?: string;
  className?: string;
  children: ReactNode;
}

export function Badge({ tone = 'neutral', outline = false, title, className, children }: BadgeProps) {
  return (
    <span className={cx('badge', `badge--${tone}`, outline && 'badge--outline', className)} title={title}>
      {children}
    </span>
  );
}

const SEVERITY_ORDER: Record<Severity, number> = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

export function normalizeSeverity(value: unknown): Severity {
  const text = typeof value === 'string' ? value.toUpperCase() : '';
  return text in SEVERITY_ORDER ? (text as Severity) : 'INFO';
}

export function severityRank(value: unknown): number {
  return SEVERITY_ORDER[normalizeSeverity(value)];
}

/**
 * Severity: how bad it is if true. Rendered as a filled, square-cornered badge.
 * Deliberately distinct from {@link ConfidenceBadge} (how sure we are): "Severity: HIGH,
 * Confidence: LOW" is a valid, common combination.
 */
export function SeverityBadge({
  severity,
  showLabel = false,
  className,
}: {
  /** A {@link Severity}; unknown values render as INFO. */
  severity: string;
  showLabel?: boolean;
  className?: string;
}) {
  const value = normalizeSeverity(severity);
  return (
    <span className={cx('sev', `sev--${value.toLowerCase()}`, className)} title={`Severity: ${value}`}>
      {showLabel ? (
        <span className="sev__prefix">Severity</span>
      ) : (
        <span className="sr-only">Severity: </span>
      )}
      <span className="sev__value">{value}</span>
    </span>
  );
}

/** Mirrors the backend thresholds (raf.core.objects.types.confidence_level). */
export function confidenceLevel(confidence: number): ConfidenceLevel {
  if (confidence >= 0.8) return 'HIGH';
  if (confidence >= 0.5) return 'MEDIUM';
  return 'LOW';
}

const METER_FILL: Record<ConfidenceLevel, number> = { LOW: 1, MEDIUM: 2, HIGH: 3 };

/** Confidence: how sure the evidence makes us. Outlined pill with a 3-step meter. */
export function ConfidenceBadge({
  confidence,
  level,
  showLabel = false,
  showValue = true,
  className,
}: {
  confidence: number;
  /** API-provided level ({@link ConfidenceLevel}); computed from `confidence` when absent. */
  level?: string | null;
  showLabel?: boolean;
  showValue?: boolean;
  className?: string;
}) {
  const resolved: ConfidenceLevel =
    level === 'LOW' || level === 'MEDIUM' || level === 'HIGH' ? level : confidenceLevel(confidence);
  const filled = METER_FILL[resolved];
  return (
    <span
      className={cx('conf', `conf--${resolved.toLowerCase()}`, className)}
      title={`Confidence: ${resolved} (${formatConfidence(confidence)})`}
    >
      {showLabel ? (
        <span className="conf__prefix">Confidence</span>
      ) : (
        <span className="sr-only">Confidence: </span>
      )}
      <span className="conf__meter" aria-hidden="true">
        {[1, 2, 3].map((step) => (
          <span key={step} className={cx('conf__bar', step <= filled && 'is-filled')} />
        ))}
      </span>
      <span className="conf__value">{resolved}</span>
      {showValue ? <span className="conf__number">{formatConfidence(confidence)}</span> : null}
    </span>
  );
}

const PRODUCT_TONES: Record<string, Tone> = {
  STABLE: 'good',
  BETA: 'accent',
  ALPHA: 'warn',
  EXPERIMENTAL: 'violet',
  DISABLED: 'neutral',
  UNAVAILABLE: 'bad',
};

export function ProductStatusBadge({ status }: { status: string }) {
  const value = status.toUpperCase();
  return (
    <Badge tone={PRODUCT_TONES[value] ?? 'neutral'} outline={value === 'UNAVAILABLE' || value === 'DISABLED'}>
      {value}
    </Badge>
  );
}

const JOB_TONES: Record<string, Tone> = {
  QUEUED: 'neutral',
  RUNNING: 'accent',
  COMPLETED: 'good',
  FAILED: 'bad',
  CANCELLED: 'warn',
};

export function JobStatusBadge({ status }: { status: string }) {
  return <Badge tone={JOB_TONES[status.toUpperCase()] ?? 'neutral'}>{status.toUpperCase()}</Badge>;
}

const LEVEL_TONES: Record<string, Tone> = {
  LOW: 'accent',
  MEDIUM: 'warn',
  HIGH: 'bad',
  CRITICAL: 'bad',
  INFO: 'neutral',
  NONE: 'neutral',
};

/** Risk/exposure levels reuse the severity scale, so they render as severity badges. */
export function RiskLevelBadge({ level }: { level: string }) {
  const value = level.toUpperCase();
  if (value in SEVERITY_ORDER) return <SeverityBadge severity={value} />;
  return <Badge tone={LEVEL_TONES[value] ?? 'neutral'}>{value}</Badge>;
}

export function CriticalityTag({ value }: { value: string | null | undefined }) {
  if (!value) return null;
  const text = value.toLowerCase();
  return (
    <span className={cx('crit', `crit--${text}`)} title={`Business criticality: ${text}`}>
      <span className="crit__dot" aria-hidden="true" />
      {text}
    </span>
  );
}
