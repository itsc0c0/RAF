import { useNavigate } from 'react-router-dom';
import { useProducts } from '../../api/hooks';
import { Button } from '../../components/Button';
import type { IconName } from '../../components/Icon';
import { routeTo } from '../../lib/routes';

const ASSETS = new Set(['host', 'service', 'cloud_resource', 'container', 'network', 'project']);

interface QuickPivot {
  product: string;
  label: string;
  icon: IconName;
  route: string;
}

/** The per-object pivots of the Investigate results (same rules as the backend pivot API). */
export function quickPivots(id: string, type: string): QuickPivot[] {
  const pivots: QuickPivot[] = [
    { product: 'graph', label: 'Graph', icon: 'graph', route: routeTo.graph(id) },
    { product: 'timeline', label: 'Timeline', icon: 'timeline', route: routeTo.timeline(id) },
  ];
  if (type !== 'incident')
    pivots.push({ product: 'trace', label: 'Trace', icon: 'route', route: routeTo.trace(id) });
  else pivots.push({ product: 'replay', label: 'Replay', icon: 'replay', route: routeTo.replay(id) });
  pivots.push({ product: 'evidence', label: 'Evidence', icon: 'evidence', route: routeTo.evidence(id) });
  if (ASSETS.has(type))
    pivots.push({ product: 'exposure', label: 'Exposure', icon: 'exposure', route: routeTo.exposure(id) });
  return pivots;
}

export function QuickPivots({ id, type }: { id: string; type: string }) {
  const navigate = useNavigate();
  const products = useProducts();
  const available = products.data
    ? new Set(products.data.items.filter((p) => p.available && p.enabled).map((p) => p.name))
    : null;
  return (
    <span className="row row--wrap quick-pivots">
      {quickPivots(id, type).map((pivot) => {
        const missing = available !== null && !available.has(pivot.product);
        return (
          <Button
            key={pivot.product}
            size="sm"
            variant="ghost"
            icon={pivot.icon}
            disabled={missing}
            title={
              missing ? `${pivot.label} is not available in this installation yet` : `Open ${pivot.label}`
            }
            onClick={(event) => {
              event.stopPropagation();
              void navigate(pivot.route);
            }}
          >
            {pivot.label}
          </Button>
        );
      })}
    </span>
  );
}
