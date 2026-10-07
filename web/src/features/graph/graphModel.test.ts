import { describe, expect, it } from 'vitest';
import type { GraphEdge, GraphNode, PathResult, Subgraph } from '../../api/types';
import {
  branchOf,
  collapseBranch,
  hiddenElements,
  mergePath,
  mergeSubgraph,
  modelFromSubgraph,
  nodeTypeCounts,
  relationshipTypeCounts,
  toElements,
} from './graphModel';

function node(id: string, extra: Partial<GraphNode> = {}): GraphNode {
  return {
    id,
    type: id.split(':')[0]!,
    name: id.split(':')[1]!,
    depth: 0,
    criticality: null,
    tags: [],
    synthetic: false,
    first_seen: null,
    last_seen: null,
    metadata: {},
    missing: false,
    ...extra,
  };
}

function edge(source: string, type: string, target: string, extra: Partial<GraphEdge> = {}): GraphEdge {
  return {
    id: `rel:${source}-${type}-${target}`,
    type,
    source,
    target,
    confidence: 0.8,
    first_seen: null,
    last_seen: null,
    valid_to: null,
    observations: 1,
    metadata: {},
    ...extra,
  };
}

function subgraph(nodes: GraphNode[], edges: GraphEdge[], roots: string[] = [], truncated = false): Subgraph {
  return { roots, nodes, edges, truncated, at: null, depth: 2 };
}

// alice -> ws-01 -> net:corp <- dev-01 ; ws-01 -> proc ; alice -> grp
const FOCUS = subgraph(
  [
    node('user:alice'),
    node('host:ws-01', { criticality: 'high' }),
    node('network:corp'),
    node('host:dev-01'),
    node('group:eng'),
  ],
  [
    edge('user:alice', 'LOGGED_INTO', 'host:ws-01'),
    edge('host:ws-01', 'MEMBER_OF', 'network:corp'),
    edge('host:dev-01', 'MEMBER_OF', 'network:corp'),
    edge('user:alice', 'MEMBER_OF', 'group:eng'),
    edge('user:alice', 'OWNS', 'host:not-in-view'),
  ],
  ['user:alice'],
);

describe('graph model', () => {
  it('only keeps edges whose endpoints were returned by the API', () => {
    const model = modelFromSubgraph(FOCUS);
    expect(model.nodes.size).toBe(5);
    expect(model.edges.size).toBe(4);
    expect(model.roots).toEqual(['user:alice']);
  });

  it('merges neighbor expansions without duplicates and records the anchor', () => {
    const model = modelFromSubgraph(FOCUS);
    const expansion = subgraph(
      [node('host:dev-01'), node('process:build'), node('user:bob')],
      [
        edge('host:dev-01', 'RUNS', 'process:build'),
        edge('user:bob', 'LOGGED_INTO', 'host:dev-01'),
        edge('host:dev-01', 'MEMBER_OF', 'network:corp'),
      ],
      ['host:dev-01'],
      true,
    );
    const merged = mergeSubgraph(model, expansion, 'host:dev-01');
    expect(merged.addedNodes.sort()).toEqual(['process:build', 'user:bob']);
    expect(merged.addedEdges).toHaveLength(2);
    expect(merged.model.anchors.get('user:bob')).toBe('host:dev-01');
    expect(merged.model.truncated).toBe(true);
    expect(model.nodes.size).toBe(5);
  });

  it('collapses a branch: removes only nodes reachable exclusively through it', () => {
    const model = mergeSubgraph(
      modelFromSubgraph(FOCUS),
      subgraph(
        [node('process:build'), node('user:bob')],
        [edge('host:dev-01', 'RUNS', 'process:build'), edge('user:bob', 'LOGGED_INTO', 'host:dev-01')],
      ),
      'host:dev-01',
    ).model;
    expect(branchOf(model, 'host:dev-01')).toEqual(['process:build', 'user:bob']);
    // Everything behind ws-01 (corp, dev-01 and dev-01's expansion) is only reachable through it.
    expect(branchOf(model, 'host:ws-01')).toEqual([
      'host:dev-01',
      'network:corp',
      'process:build',
      'user:bob',
    ]);
    const { model: collapsed, removed } = collapseBranch(model, 'host:dev-01');
    expect(removed).toEqual(['process:build', 'user:bob']);
    expect(collapsed.nodes.has('host:dev-01')).toBe(true);
    expect(
      [...collapsed.edges.values()].some((e) => e.source === 'user:bob' || e.target === 'process:build'),
    ).toBe(false);
  });

  it('collapses relative to the loaded nodes when the view has no roots (overview)', () => {
    const overview = modelFromSubgraph({ ...FOCUS, roots: [] });
    const expanded = mergeSubgraph(
      overview,
      subgraph([node('process:x')], [edge('group:eng', 'RUNS', 'process:x')]),
      'group:eng',
    ).model;
    expect(branchOf(expanded, 'group:eng')).toEqual(['process:x']);
    expect(collapseBranch(overview, 'group:eng').removed).toEqual([]);
  });

  it('collapsing the only root keeps just the root', () => {
    const { model, removed } = collapseBranch(modelFromSubgraph(FOCUS), 'user:alice');
    expect(removed).toHaveLength(4);
    expect([...model.nodes.keys()]).toEqual(['user:alice']);
  });

  it('counts types and hides filtered types together with their edges', () => {
    const model = modelFromSubgraph(FOCUS);
    expect(nodeTypeCounts(model)[0]).toEqual({ type: 'host', count: 2 });
    expect(relationshipTypeCounts(model)[0]).toEqual({ type: 'MEMBER_OF', count: 3 });
    const hidden = hiddenElements(model, new Set(['group']), new Set(['LOGGED_INTO']));
    expect(hidden.has('group:eng')).toBe(true);
    expect(hidden.has('rel:user:alice-MEMBER_OF-group:eng')).toBe(true);
    expect(hidden.has('rel:user:alice-LOGGED_INTO-host:ws-01')).toBe(true);
    expect(hidden.has('host:ws-01')).toBe(false);
  });

  it('adds missing path hops to the view', () => {
    const path: PathResult = {
      source: 'user:alice',
      target: 'host:db-01',
      found: true,
      directed: false,
      at: null,
      length: 2,
      hops: [
        {
          source: 'user:alice',
          source_name: 'alice',
          target: 'host:ws-01',
          target_name: 'WS-01',
          relationship: edge('user:alice', 'LOGGED_INTO', 'host:ws-01'),
          forward: true,
        },
        {
          source: 'host:ws-01',
          source_name: 'WS-01',
          target: 'host:db-01',
          target_name: 'DB-01',
          relationship: edge('host:ws-01', 'CAN_REACH', 'host:db-01'),
          forward: true,
        },
      ],
    };
    const merged = mergePath(modelFromSubgraph(FOCUS), path);
    expect(merged.addedNodes).toEqual(['host:db-01']);
    expect(merged.model.nodes.get('host:db-01')?.name).toBe('DB-01');
    expect(merged.addedEdges).toEqual(['rel:host:ws-01-CAN_REACH-host:db-01']);
  });

  it('produces Cytoscape elements with type, criticality and virtual-edge classes', () => {
    const model = modelFromSubgraph(
      subgraph(
        [node('incident:inc-001'), node('host:db-01', { criticality: 'critical' })],
        [edge('incident:inc-001', 'INVOLVES', 'host:db-01', { metadata: { virtual: true } })],
        ['incident:inc-001'],
      ),
    );
    const elements = toElements(model);
    const db = elements.find((element) => element.data.id === 'host:db-01');
    expect(db?.classes).toBe('fam-asset crit-critical');
    expect(db?.data.label).toBe('db-01');
    expect(elements.find((element) => element.data.id === 'incident:inc-001')?.classes).toBe(
      'fam-incident root',
    );
    expect(elements.find((element) => element.group === 'edges')?.classes).toBe('virtual');
  });
});
