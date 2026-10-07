import type { ReactNode } from 'react';
import { cx } from '../lib/cx';

export interface ChainItem {
  key: string;
  node: ReactNode;
  /** Connector to the next node (why it is traversable, relation, confidence...). */
  link?: ReactNode;
  /** Dashed connectors mark weaker evidence (correlation rather than observation). */
  linkStyle?: 'solid' | 'dashed';
  emphasis?: boolean;
}

/** Vertical chain: node, connector, node... (causal chains, attack paths, custody). */
export function Chain({
  items,
  label,
  className,
}: {
  items: readonly ChainItem[];
  label: string;
  className?: string;
}) {
  return (
    <ol className={cx('chain', className)} aria-label={label}>
      {items.map((item, index) => (
        <li key={item.key} className={cx('chain__item', item.emphasis && 'chain__item--emphasis')}>
          <div className="chain__node">
            <span className="chain__dot" aria-hidden="true" />
            <div className="chain__content">{item.node}</div>
          </div>
          {item.link !== undefined && index < items.length - 1 ? (
            <div className={cx('chain__link', item.linkStyle === 'dashed' && 'chain__link--dashed')}>
              {item.link}
            </div>
          ) : null}
        </li>
      ))}
    </ol>
  );
}

export interface HopLike {
  source: string;
  target: string;
}

/**
 * Turns a list of hops (a → b, b → c) into chain items: nodes a, b, c with each hop rendered as the
 * connector between consecutive nodes.
 */
export function hopsToChain<H extends HopLike>(
  hops: readonly H[],
  renderNode: (id: string, position: number) => ReactNode,
  renderLink: (hop: H, index: number) => ReactNode,
  linkStyle?: (hop: H) => 'solid' | 'dashed',
): ChainItem[] {
  if (hops.length === 0) return [];
  const items: ChainItem[] = [];
  hops.forEach((hop, index) => {
    items.push({
      key: `${index}:${hop.source}`,
      node: renderNode(hop.source, index),
      link: renderLink(hop, index),
      linkStyle: linkStyle?.(hop) ?? 'solid',
    });
  });
  const last = hops[hops.length - 1]!;
  items.push({ key: `${hops.length}:${last.target}`, node: renderNode(last.target, hops.length) });
  return items;
}
