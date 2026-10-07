import type { TraceLink } from '../../api/types';

export interface TraceTreeNode {
  link: TraceLink;
  children: TraceTreeNode[];
}

/**
 * Builds the trace tree from `step`/`parent_step`: top-level links explain the subject directly;
 * children explain their parent's next node (the cause when tracing backward, the effect forward).
 * Links whose parent is missing become top-level; cycles are cut.
 */
export function buildTraceTree(links: readonly TraceLink[]): TraceTreeNode[] {
  const steps = new Set(links.map((link) => link.step));
  const byParent = new Map<number | null, TraceLink[]>();
  for (const link of links) {
    const parent = link.parent_step !== null && steps.has(link.parent_step) ? link.parent_step : null;
    const bucket = byParent.get(parent) ?? [];
    bucket.push(link);
    byParent.set(parent, bucket);
  }
  const seen = new Set<number>();
  const build = (parent: number | null): TraceTreeNode[] =>
    (byParent.get(parent) ?? [])
      .filter((link) => {
        if (seen.has(link.step)) return false;
        seen.add(link.step);
        return true;
      })
      .map((link) => ({ link, children: build(link.step) }));
  return build(null);
}

export function countTree(nodes: readonly TraceTreeNode[]): number {
  return nodes.reduce((total, node) => total + 1 + countTree(node.children), 0);
}

export function isCorrelated(link: Pick<TraceLink, 'kind'>): boolean {
  return link.kind === 'correlated';
}
