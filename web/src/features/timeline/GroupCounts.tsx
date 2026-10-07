import type { CountGroup } from '../../api/types';
import { formatNumber } from '../../lib/format';

/**
 * Group-by counts as a single-series bar list (one hue, labeled values). Clicking a group narrows
 * the timeline to it.
 */
export function GroupCounts({
  groups,
  field,
  onPick,
}: {
  groups: readonly CountGroup[];
  field: string;
  onPick?: (key: string) => void;
}) {
  if (groups.length === 0) return <p className="muted small">No groups.</p>;
  const max = Math.max(1, ...groups.map((group) => group.count));
  return (
    <ul className="groups" aria-label={`Event counts by ${field}`}>
      {groups.map((group) => {
        const key = group.key ?? '';
        const label = group.key ?? '(none)';
        return (
          <li key={label}>
            <button
              type="button"
              className="groups__item"
              disabled={!onPick || !key}
              onClick={() => onPick?.(key)}
              title={onPick && key ? `Filter to ${field} ${label}` : label}
            >
              <span className="groups__label truncate mono">{label}</span>
              <span className="groups__value tabular">{formatNumber(group.count)}</span>
              <span className="groups__bar" aria-hidden="true">
                <span className="groups__fill" style={{ width: `${(group.count / max) * 100}%` }} />
              </span>
            </button>
          </li>
        );
      })}
    </ul>
  );
}
