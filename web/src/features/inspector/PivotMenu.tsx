import { useNavigate } from 'react-router-dom';
import type { Pivot } from '../../api/types';
import { Icon, type IconName } from '../../components/Icon';
import { toInternalRoute } from '../../lib/routes';

const PRODUCT_ICONS: Record<string, IconName> = {
  graph: 'graph',
  timeline: 'timeline',
  replay: 'replay',
  trace: 'route',
  blast: 'target',
  exposure: 'exposure',
  iam: 'layers',
  evidence: 'evidence',
  lens: 'investigate',
};

/**
 * Pivot buttons from `GET /objects/{id}/pivots`. Views are data: only internal routes are followed;
 * anything else is dropped. The CLI equivalent is shown as a tooltip.
 */
export function PivotMenu({ pivots, onNavigate }: { pivots: readonly Pivot[]; onNavigate?: () => void }) {
  const navigate = useNavigate();
  const safe = pivots
    .map((pivot) => ({ pivot, route: toInternalRoute(pivot.view) }))
    .filter((entry): entry is { pivot: Pivot; route: string } => entry.route !== null);
  if (safe.length === 0) return <p className="muted small">No pivots available for this object.</p>;
  return (
    <nav className="pivots" aria-label="Pivot to another view">
      {safe.map(({ pivot, route }) => (
        <button
          key={`${pivot.product}-${pivot.key}`}
          type="button"
          className="pivot"
          title={`${pivot.label} — CLI: ${pivot.command}`}
          onClick={() => {
            void navigate(route);
            onNavigate?.();
          }}
        >
          <Icon name={PRODUCT_ICONS[pivot.product] ?? 'pivot'} size={14} />
          <span>{pivot.label}</span>
          <kbd className="pivot__key" aria-hidden="true">
            {pivot.key}
          </kbd>
        </button>
      ))}
    </nav>
  );
}
