/**
 * Client-side graph model for the Graph view (pure functions, no Cytoscape dependency).
 *
 * The model only ever contains nodes/edges returned by the API (view, neighbors, path), so the UI
 * never renders more than the server allowed (the server caps node counts and flags truncation).
 */

import type cytoscape from 'cytoscape';
import type { GraphEdge, GraphNode, PathResult, Subgraph } from '../../api/types';
import { objectKeyOf, objectTypeOf } from '../../lib/format';
import { familyOf, shapeOf } from '../../lib/objectTypes';

export interface GraphModel {
  readonly nodes: ReadonlyMap<string, GraphNode>;
  readonly edges: ReadonlyMap<string, GraphEdge>;
  readonly roots: readonly string[];
  /** Nodes of the initially loaded view. */
  readonly base: ReadonlySet<string>;
  /** Node -> node it was expanded from (positions new nodes, documents provenance of the view). */
  readonly anchors: ReadonlyMap<string, string>;
  readonly truncated: boolean;
}

export function modelFromSubgraph(subgraph: Subgraph): GraphModel {
  const nodes = new Map(subgraph.nodes.map((node) => [node.id, node] as const));
  const edges = new Map<string, GraphEdge>();
  for (const edge of subgraph.edges) {
    if (nodes.has(edge.source) && nodes.has(edge.target)) edges.set(edge.id, edge);
  }
  return {
    nodes,
    edges,
    roots: subgraph.roots.filter((id) => nodes.has(id)),
    base: new Set(nodes.keys()),
    anchors: new Map(),
    truncated: subgraph.truncated,
  };
}

export interface MergeResult {
  model: GraphModel;
  addedNodes: string[];
  addedEdges: string[];
}

/** Merges a neighbors/expansion subgraph into the model (existing items are kept as they are). */
export function mergeSubgraph(model: GraphModel, subgraph: Subgraph, anchor?: string): MergeResult {
  const nodes = new Map(model.nodes);
  const edges = new Map(model.edges);
  const anchors = new Map(model.anchors);
  const addedNodes: string[] = [];
  const addedEdges: string[] = [];
  for (const node of subgraph.nodes) {
    if (nodes.has(node.id)) continue;
    nodes.set(node.id, node);
    addedNodes.push(node.id);
    if (anchor && node.id !== anchor) anchors.set(node.id, anchor);
  }
  for (const edge of subgraph.edges) {
    if (edges.has(edge.id) || !nodes.has(edge.source) || !nodes.has(edge.target)) continue;
    edges.set(edge.id, edge);
    addedEdges.push(edge.id);
  }
  return {
    model: { ...model, nodes, edges, anchors, truncated: model.truncated || subgraph.truncated },
    addedNodes,
    addedEdges,
  };
}

function adjacency(model: GraphModel): Map<string, string[]> {
  const adjacent = new Map<string, string[]>();
  for (const id of model.nodes.keys()) adjacent.set(id, []);
  for (const edge of model.edges.values()) {
    adjacent.get(edge.source)?.push(edge.target);
    adjacent.get(edge.target)?.push(edge.source);
  }
  return adjacent;
}

/**
 * Nodes that are only reachable through `nodeId`: remove `nodeId` temporarily and keep everything
 * still connected to an anchor (the view's roots, or the initially loaded nodes for root-less
 * overviews). `nodeId` itself stays.
 */
export function branchOf(model: GraphModel, nodeId: string): string[] {
  if (!model.nodes.has(nodeId)) return [];
  const anchorPool = model.roots.length > 0 ? model.roots : [...model.base];
  const anchors = anchorPool.filter((id) => id !== nodeId && model.nodes.has(id));
  const adjacent = adjacency(model);
  const reached = new Set<string>(anchors);
  const queue = [...anchors];
  while (queue.length > 0) {
    const current = queue.shift()!;
    for (const next of adjacent.get(current) ?? []) {
      if (next === nodeId || reached.has(next)) continue;
      reached.add(next);
      queue.push(next);
    }
  }
  return [...model.nodes.keys()].filter((id) => id !== nodeId && !reached.has(id)).sort();
}

export function collapseBranch(model: GraphModel, nodeId: string): { model: GraphModel; removed: string[] } {
  const removed = branchOf(model, nodeId);
  if (removed.length === 0) return { model, removed };
  const gone = new Set(removed);
  const nodes = new Map([...model.nodes].filter(([id]) => !gone.has(id)));
  const edges = new Map(
    [...model.edges].filter(([, edge]) => !gone.has(edge.source) && !gone.has(edge.target)),
  );
  const anchors = new Map([...model.anchors].filter(([id]) => !gone.has(id)));
  return { model: { ...model, nodes, edges, anchors }, removed };
}

export interface TypeCount {
  type: string;
  count: number;
}

function countBy<T>(items: Iterable<T>, key: (item: T) => string): TypeCount[] {
  const counts = new Map<string, number>();
  for (const item of items) counts.set(key(item), (counts.get(key(item)) ?? 0) + 1);
  return [...counts]
    .map(([type, count]) => ({ type, count }))
    .sort((a, b) => b.count - a.count || a.type.localeCompare(b.type));
}

export function nodeTypeCounts(model: GraphModel): TypeCount[] {
  return countBy(model.nodes.values(), (node) => node.type);
}

export function relationshipTypeCounts(model: GraphModel): TypeCount[] {
  return countBy(model.edges.values(), (edge) => edge.type);
}

/** Element IDs hidden by the type filters (edges of hidden nodes are hidden too). */
export function hiddenElements(
  model: GraphModel,
  hiddenNodeTypes: ReadonlySet<string>,
  hiddenRelationshipTypes: ReadonlySet<string>,
): Set<string> {
  const hidden = new Set<string>();
  for (const node of model.nodes.values()) if (hiddenNodeTypes.has(node.type)) hidden.add(node.id);
  for (const edge of model.edges.values()) {
    if (hiddenRelationshipTypes.has(edge.type) || hidden.has(edge.source) || hidden.has(edge.target))
      hidden.add(edge.id);
  }
  return hidden;
}

/** Adds the nodes/edges of a path that are not in the view yet (so the whole path can be shown). */
export function mergePath(model: GraphModel, path: PathResult): MergeResult {
  const nodes: GraphNode[] = [];
  const seen = new Set<string>();
  const addNode = (id: string, name: string) => {
    if (seen.has(id) || model.nodes.has(id)) return;
    seen.add(id);
    nodes.push({
      id,
      name: name || objectKeyOf(id),
      type: objectTypeOf(id),
      depth: 0,
      criticality: null,
      tags: [],
      synthetic: false,
      first_seen: null,
      last_seen: null,
      metadata: {},
      missing: false,
    });
  };
  for (const hop of path.hops) {
    addNode(hop.source, hop.source_name);
    addNode(hop.target, hop.target_name);
  }
  return mergeSubgraph(model, {
    roots: [],
    nodes,
    edges: path.hops.map((hop) => hop.relationship),
    truncated: false,
    at: path.at,
    depth: 0,
  });
}

export function pathHighlight(path: PathResult): { nodes: Set<string>; edges: Set<string> } {
  const nodes = new Set<string>();
  const edges = new Set<string>();
  for (const hop of path.hops) {
    nodes.add(hop.source);
    nodes.add(hop.target);
    edges.add(hop.relationship.id);
  }
  return { nodes, edges };
}

export function nodeClasses(
  node: Pick<GraphNode, 'type' | 'criticality' | 'missing'>,
  isRoot: boolean,
): string {
  const classes = [`fam-${familyOf(node.type)}`];
  const criticality = node.criticality?.toLowerCase();
  if (criticality && ['low', 'medium', 'high', 'critical'].includes(criticality))
    classes.push(`crit-${criticality}`);
  if (isRoot) classes.push('root');
  if (node.missing) classes.push('missing');
  return classes.join(' ');
}

export function edgeClasses(edge: Pick<GraphEdge, 'metadata' | 'valid_to'>): string {
  const classes: string[] = [];
  if (edge.metadata?.virtual === true) classes.push('virtual');
  if (edge.valid_to) classes.push('ended');
  return classes.join(' ');
}

/** Cytoscape element definitions for the model. Labels are plain strings (canvas text). */
export function toElements(model: GraphModel): cytoscape.ElementDefinition[] {
  const roots = new Set(model.roots);
  const elements: cytoscape.ElementDefinition[] = [];
  for (const node of model.nodes.values()) {
    elements.push({
      group: 'nodes',
      data: {
        id: node.id,
        label: node.name,
        type: node.type,
        shape: shapeOf(node.type),
        anchor: model.anchors.get(node.id),
      },
      classes: nodeClasses(node, roots.has(node.id)),
    });
  }
  for (const edge of model.edges.values()) {
    elements.push({
      group: 'edges',
      data: { id: edge.id, source: edge.source, target: edge.target, label: edge.type, type: edge.type },
      classes: edgeClasses(edge),
    });
  }
  return elements;
}
