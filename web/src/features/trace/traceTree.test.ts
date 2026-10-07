import { describe, expect, it } from 'vitest';
import type { TraceLink } from '../../api/types';
import { buildTraceTree, countTree, isCorrelated } from './traceTree';

function link(
  step: number,
  parent: number | null,
  cause: string,
  effect: string,
  kind = 'observed',
): TraceLink {
  return {
    cause,
    effect,
    relation: 'AUTHENTICATED_FROM',
    kind,
    confidence: 0.8,
    timestamp: '2026-10-06T22:58:03Z',
    event_id: `event:${step}`,
    explanation: `${cause} -> ${effect}`,
    provenance: { source: 'auth.log', record: `line ${step}` },
    direction: 'backward',
    step,
    parent_step: parent,
    corroborated_by: [],
  };
}

describe('trace tree', () => {
  it('nests links under the link that reached their frontier node', () => {
    // Shaped after `GET /trace/svc-deploy`: steps 0-2 explain the subject, 6 explains step 0's cause...
    const links = [
      link(0, null, 'host:ci-01', 'identity:svc-deploy'),
      link(1, null, 'host:dev-01', 'identity:svc-deploy'),
      link(2, null, 'process:cat', 'identity:svc-deploy', 'correlated'),
      link(6, 0, 'identity:svc-deploy', 'host:ci-01'),
      link(10, 1, 'user:bob', 'host:dev-01'),
      link(22, 10, 'host:ws-02', 'user:bob'),
    ];
    const tree = buildTraceTree(links);
    expect(tree.map((node) => node.link.step)).toEqual([0, 1, 2]);
    expect(tree[0]!.children.map((node) => node.link.step)).toEqual([6]);
    expect(tree[1]!.children[0]!.children[0]!.link.cause).toBe('host:ws-02');
    expect(countTree(tree)).toBe(6);
    expect(isCorrelated(tree[2]!.link)).toBe(true);
    expect(isCorrelated(tree[0]!.link)).toBe(false);
  });

  it('treats links with unknown parents as top-level and cuts cycles', () => {
    const tree = buildTraceTree([link(3, 99, 'a', 'b'), link(4, 5, 'c', 'd'), link(5, 4, 'e', 'f')]);
    expect(tree.map((node) => node.link.step)).toEqual([3]);
    expect(countTree(tree)).toBe(1);
  });
});
