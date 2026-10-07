import type cytoscape from 'cytoscape';

/** Colors resolved from the CSS design tokens (Cytoscape draws on canvas and cannot read CSS vars). */
export interface GraphPalette {
  asset: string;
  principal: string;
  activity: string;
  neutral: string;
  incident: string;
  label: string;
  labelMuted: string;
  surface: string;
  edge: string;
  accent: string;
  critical: string;
  high: string;
  medium: string;
  low: string;
  added: string;
  removed: string;
}

const FALLBACK: GraphPalette = {
  asset: '#3987e5',
  principal: '#d95926',
  activity: '#199e70',
  neutral: '#6b7682',
  incident: '#e4e8ed',
  label: '#c9d0d8',
  labelMuted: '#8a94a0',
  surface: '#151a20',
  edge: '#4b5562',
  accent: '#4c8fd9',
  critical: '#ff5c5c',
  high: '#d94a47',
  medium: '#e0a43a',
  low: '#67717c',
  added: '#4fb37f',
  removed: '#e5706d',
};

export function readGraphPalette(): GraphPalette {
  if (typeof window === 'undefined' || typeof getComputedStyle === 'undefined') return FALLBACK;
  const css = getComputedStyle(document.documentElement);
  const read = (name: string, fallback: string) => css.getPropertyValue(name).trim() || fallback;
  return {
    asset: read('--node-asset', FALLBACK.asset),
    principal: read('--node-principal', FALLBACK.principal),
    activity: read('--node-activity', FALLBACK.activity),
    neutral: read('--node-neutral', FALLBACK.neutral),
    incident: read('--node-incident', FALLBACK.incident),
    label: read('--node-label', FALLBACK.label),
    labelMuted: read('--ink-muted', FALLBACK.labelMuted),
    surface: read('--bg-panel', FALLBACK.surface),
    edge: read('--graph-edge', FALLBACK.edge),
    accent: read('--accent', FALLBACK.accent),
    critical: read('--sev-critical-mark', FALLBACK.critical),
    high: read('--sev-high-mark', FALLBACK.high),
    medium: read('--sev-medium-mark', FALLBACK.medium),
    low: read('--ink-faint', FALLBACK.low),
    added: read('--graph-added', FALLBACK.added),
    removed: read('--graph-removed', FALLBACK.removed),
  };
}

/**
 * Node fill = type family (3 validated hues + neutral), node shape = exact type, border = business
 * criticality. Edge labels are drawn only on hover/selection (performance and legibility).
 */
export function buildGraphStyle(p: GraphPalette): cytoscape.StylesheetJson {
  return [
    {
      selector: 'node',
      style: {
        'background-color': p.neutral,
        shape: 'data(shape)' as unknown as cytoscape.Css.NodeShape,
        width: 20,
        height: 20,
        label: 'data(label)',
        color: p.label,
        'font-size': 10,
        'font-family': 'system-ui, -apple-system, "Segoe UI", sans-serif',
        'text-valign': 'bottom',
        'text-halign': 'center',
        'text-margin-y': 4,
        'text-max-width': '120px',
        'text-wrap': 'ellipsis',
        'min-zoomed-font-size': 6,
        'border-width': 1.5,
        'border-color': p.surface,
      },
    },
    { selector: 'node.fam-asset', style: { 'background-color': p.asset } },
    { selector: 'node.fam-principal', style: { 'background-color': p.principal } },
    { selector: 'node.fam-activity', style: { 'background-color': p.activity } },
    {
      selector: 'node.fam-incident',
      style: { 'background-color': p.incident, width: 30, height: 30, 'font-weight': 'bold' },
    },
    { selector: 'node.crit-low', style: { 'border-width': 2, 'border-color': p.low } },
    { selector: 'node.crit-medium', style: { 'border-width': 2.5, 'border-color': p.medium } },
    { selector: 'node.crit-high', style: { 'border-width': 3, 'border-color': p.high } },
    { selector: 'node.crit-critical', style: { 'border-width': 4, 'border-color': p.critical } },
    { selector: 'node.root', style: { width: 28, height: 28, 'font-weight': 'bold' } },
    {
      selector: 'node.missing',
      style: { 'background-opacity': 0.35, 'border-style': 'dashed', 'border-color': p.neutral },
    },
    {
      selector: 'edge',
      style: {
        width: 1.2,
        'line-color': p.edge,
        'target-arrow-shape': 'triangle',
        'target-arrow-color': p.edge,
        'arrow-scale': 0.7,
        'curve-style': 'bezier',
        label: '',
        'font-size': 9,
        color: p.labelMuted,
        'text-rotation': 'autorotate',
        'text-background-color': p.surface,
        'text-background-opacity': 0.9,
        'text-background-padding': '2px',
      },
    },
    {
      selector: 'edge.virtual',
      style: {
        'line-style': 'dashed',
        'line-dash-pattern': [4, 4],
        'target-arrow-shape': 'none',
        opacity: 0.6,
      },
    },
    { selector: 'edge.ended', style: { 'line-style': 'dotted' } },
    {
      selector: 'node.hover',
      style: { 'underlay-color': p.accent, 'underlay-opacity': 0.2, 'underlay-padding': 5 },
    },
    {
      selector: 'edge.hover, edge:selected',
      style: {
        label: 'data(label)',
        width: 2,
        'line-color': p.accent,
        'target-arrow-color': p.accent,
        opacity: 1,
      },
    },
    {
      selector: 'node:selected',
      style: { 'underlay-color': p.accent, 'underlay-opacity': 0.35, 'underlay-padding': 7 },
    },
    { selector: '.filtered', style: { display: 'none' } },
    { selector: '.faded', style: { opacity: 0.14 } },
    {
      selector: 'node.path',
      style: { 'underlay-color': p.accent, 'underlay-opacity': 0.3, 'underlay-padding': 6, opacity: 1 },
    },
    {
      selector: 'edge.path',
      style: {
        label: 'data(label)',
        width: 3,
        'line-color': p.accent,
        'target-arrow-color': p.accent,
        opacity: 1,
      },
    },
    // Replay statuses
    { selector: '.absent', style: { display: 'none' } },
    {
      selector: 'node.added',
      style: { 'underlay-color': p.added, 'underlay-opacity': 0.4, 'underlay-padding': 8 },
    },
    {
      selector: 'edge.added',
      style: { label: 'data(label)', width: 2.5, 'line-color': p.added, 'target-arrow-color': p.added },
    },
    {
      selector: 'edge.removed',
      style: {
        label: 'data(label)',
        'line-style': 'dashed',
        'line-color': p.removed,
        'target-arrow-color': p.removed,
        opacity: 0.45,
      },
    },
  ];
}
