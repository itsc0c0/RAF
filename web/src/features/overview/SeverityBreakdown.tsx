import { SEVERITIES, type Severity } from '../../api/types';
import { SeverityBadge } from '../../components/Badge';
import { formatNumber } from '../../lib/format';

const ORDER: Severity[] = [...SEVERITIES].reverse();

/**
 * Part-to-whole of open findings by severity: one stacked bar (2px surface gaps between segments)
 * plus a labeled legend, so severity is never conveyed by color alone.
 */
export function SeverityBreakdown({ counts }: { counts: Partial<Record<Severity, number>> }) {
  const total = ORDER.reduce((sum, severity) => sum + (counts[severity] ?? 0), 0);
  if (total === 0) return <p className="muted small">No open findings.</p>;
  return (
    <div className="sev-breakdown">
      <div
        className="sev-breakdown__bar"
        role="img"
        aria-label={ORDER.map((s) => `${s} ${counts[s] ?? 0}`).join(', ')}
      >
        {ORDER.map((severity) => {
          const count = counts[severity] ?? 0;
          if (count === 0) return null;
          return (
            <span
              key={severity}
              className={`sev-breakdown__segment sev-breakdown__segment--${severity.toLowerCase()}`}
              style={{ flexGrow: count }}
              title={`${severity}: ${formatNumber(count)}`}
            />
          );
        })}
      </div>
      <ul className="sev-breakdown__legend">
        {ORDER.map((severity) => (
          <li key={severity}>
            <SeverityBadge severity={severity} />
            <span className="tabular">{formatNumber(counts[severity] ?? 0)}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
