import cytoscape from 'cytoscape';
import { useEffect, useImperativeHandle, useRef, type KeyboardEvent, type Ref } from 'react';
import { useTheme } from '../../app/theme';
import { useLatest } from '../../lib/hooks';
import { buildGraphStyle, readGraphPalette } from './graphStyle';

export type LayoutName = 'cose' | 'breadthfirst' | 'concentric';

export const LAYOUTS: ReadonlyArray<{ value: LayoutName; label: string }> = [
  { value: 'cose', label: 'Force (cose)' },
  { value: 'breadthfirst', label: 'Hierarchy (breadthfirst)' },
  { value: 'concentric', label: 'Concentric' },
];

export interface GraphCanvasHandle {
  fit: () => void;
  zoom: (factor: number) => void;
  center: (id: string) => void;
}

export interface Highlight {
  nodes: ReadonlySet<string>;
  edges: ReadonlySet<string>;
}

export interface GraphCanvasProps {
  elements: readonly cytoscape.ElementDefinition[];
  layout: LayoutName;
  /** Changing this re-runs the layout (new data, expansion, layout switch). */
  layoutKey: string | number;
  roots?: readonly string[];
  /** Per-element status class (replay: present/added/removed/absent). */
  statusClasses?: ReadonlyMap<string, string> | null;
  /** Elements hidden by filters. */
  hidden?: ReadonlySet<string> | null;
  highlight?: Highlight | null;
  selectedId?: string | null;
  onSelect?: (id: string | null, group: 'nodes' | 'edges' | null) => void;
  onExpand?: (id: string) => void;
  ariaLabel: string;
  /** Tighter force layout (small graphs that should stay readable when fitted). */
  compact?: boolean;
  ref?: Ref<GraphCanvasHandle>;
}

const STATUS_CLASSES = 'present added removed absent';
const FIT_PADDING = 44;
const MAX_FIT_ZOOM = 1.6;

/**
 * Fits the viewport to node geometry only. Cytoscape's own fit includes label boxes measured at the
 * current zoom; long labels then shrink the graph, and labels hide once zoomed out, leaving empty
 * margins. Small graphs are not blown up beyond MAX_FIT_ZOOM.
 */
export function fitToNodes(cy: cytoscape.Core, padding = FIT_PADDING): void {
  const elements = cy.elements().not('.filtered');
  if (elements.empty()) return;
  const box = elements.boundingBox({ includeLabels: false, includeOverlays: false });
  const width = cy.width();
  const height = cy.height();
  if (width <= 0 || height <= 0) return;
  const zoomX = box.w > 0 ? (width - 2 * padding) / box.w : MAX_FIT_ZOOM;
  const zoomY = box.h > 0 ? (height - 2 * padding) / box.h : MAX_FIT_ZOOM;
  const zoom = Math.max(cy.minZoom(), Math.min(MAX_FIT_ZOOM, cy.maxZoom(), zoomX, zoomY));
  cy.viewport({
    zoom,
    pan: { x: (width - zoom * (box.x1 + box.x2)) / 2, y: (height - zoom * (box.y1 + box.y2)) / 2 },
  });
}
const GOLDEN_ANGLE = 2.399963229728653;

function layoutOptions(
  name: LayoutName,
  roots: readonly string[],
  seeded: boolean,
  compact: boolean,
  bounds: { w: number; h: number },
): cytoscape.LayoutOptions {
  const common = { fit: false, animate: false } as const;
  if (name === 'breadthfirst') {
    return {
      name,
      ...common,
      directed: false,
      spacingFactor: 1.15,
      roots: roots.length ? [...roots] : undefined,
    };
  }
  if (name === 'concentric') {
    return {
      name,
      ...common,
      minNodeSpacing: 18,
      concentric: (node: cytoscape.NodeSingular) => (node.hasClass('root') ? 1000 : node.degree(false)),
      levelWidth: () => 3,
    };
  }
  return {
    name: 'cose',
    ...common,
    randomize: !seeded,
    // Spread nodes over the container's aspect ratio (wide panels get wide layouts).
    boundingBox: bounds.w > 0 && bounds.h > 0 ? { x1: 0, y1: 0, w: bounds.w, h: bounds.h } : undefined,
    nodeRepulsion: () => (compact ? 7000 : 18000),
    idealEdgeLength: () => (compact ? 56 : 84),
    nodeOverlap: 24,
    gravity: compact ? 1.2 : 0.4,
    numIter: 1500,
    componentSpacing: 80,
  };
}

/**
 * Cytoscape.js wrapper. The Cytoscape instance lives for the component's lifetime; prop changes are
 * applied as diffs (add/remove elements, toggle classes) so unrelated React state never re-creates or
 * re-lays out the graph. Labels are canvas text, so untrusted names can never become markup.
 */
export function GraphCanvas({
  elements,
  layout,
  layoutKey,
  roots = [],
  statusClasses,
  hidden,
  highlight,
  selectedId,
  onSelect,
  onExpand,
  ariaLabel,
  compact = false,
  ref,
}: GraphCanvasProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);
  const laidOut = useRef(false);
  const onSelectRef = useLatest(onSelect);
  const onExpandRef = useLatest(onExpand);
  const rootsRef = useLatest(roots);
  const { theme } = useTheme();

  // Create the instance once.
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return undefined;
    const cy = cytoscape({
      container,
      elements: [],
      style: buildGraphStyle(readGraphPalette()),
      minZoom: 0.05,
      maxZoom: 4,
      boxSelectionEnabled: false,
      selectionType: 'single',
    });
    cy.on('tap', 'node', (event) =>
      onSelectRef.current?.((event.target as cytoscape.NodeSingular).id(), 'nodes'),
    );
    cy.on('tap', 'edge', (event) =>
      onSelectRef.current?.((event.target as cytoscape.EdgeSingular).id(), 'edges'),
    );
    cy.on('tap', (event) => {
      if (event.target === cy) onSelectRef.current?.(null, null);
    });
    cy.on('dbltap', 'node', (event) => onExpandRef.current?.((event.target as cytoscape.NodeSingular).id()));
    cy.on('mouseover', 'node', (event) => {
      const node = event.target as cytoscape.NodeSingular;
      node.addClass('hover');
      node.connectedEdges().addClass('hover');
    });
    cy.on('mouseout', 'node', (event) => {
      const node = event.target as cytoscape.NodeSingular;
      node.removeClass('hover');
      node.connectedEdges().removeClass('hover');
    });
    cy.on('mouseover', 'edge', (event) => (event.target as cytoscape.EdgeSingular).addClass('hover'));
    cy.on('mouseout', 'edge', (event) => (event.target as cytoscape.EdgeSingular).removeClass('hover'));
    cyRef.current = cy;
    laidOut.current = false;
    // Keep Cytoscape's cached viewport size in sync with the container (panels, drawers, window).
    const observer = typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(() => cy.resize());
    observer?.observe(container);
    return () => {
      observer?.disconnect();
      cy.destroy();
      cyRef.current = null;
    };
  }, [onSelectRef, onExpandRef]);

  // Apply element diffs.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    const wanted = new Set(elements.map((element) => String(element.data.id)));
    cy.batch(() => {
      cy.elements().forEach((element) => {
        if (!wanted.has(element.id())) element.remove();
      });
      let placed = 0;
      for (const definition of elements) {
        if (definition.group !== 'nodes') continue;
        const id = String(definition.data.id);
        const existing = cy.getElementById(id);
        if (existing.nonempty()) {
          existing.data(definition.data);
          continue;
        }
        const anchorId = (definition.data as { anchor?: string }).anchor;
        const anchor = anchorId ? cy.getElementById(anchorId) : null;
        let position: cytoscape.Position | undefined;
        if (anchor && anchor.nonempty()) {
          const base = anchor.position();
          const angle = placed * GOLDEN_ANGLE;
          const radius = 70 + 14 * Math.sqrt(placed);
          position = { x: base.x + radius * Math.cos(angle), y: base.y + radius * Math.sin(angle) };
          placed += 1;
        }
        cy.add({ ...definition, position });
      }
      for (const definition of elements) {
        if (definition.group !== 'edges') continue;
        const data = definition.data as cytoscape.EdgeDataDefinition;
        const id = String(data.id);
        if (cy.getElementById(id).nonempty()) continue;
        if (cy.getElementById(String(data.source)).empty() || cy.getElementById(String(data.target)).empty())
          continue;
        cy.add(definition);
      }
    });
  }, [elements]);

  // Layout (after element diffs in the same commit).
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || cy.nodes().length === 0) return;
    if (layout === 'cose' && !laidOut.current) {
      // Deterministic seed positions: the same graph always produces the same picture.
      cy.layout({
        name: 'concentric',
        animate: false,
        fit: false,
        concentric: (node: cytoscape.NodeSingular) => node.degree(false),
      }).run();
    }
    cy.layout(
      layoutOptions(layout, rootsRef.current, true, compact, { w: cy.width(), h: cy.height() }),
    ).run();
    fitToNodes(cy);
    laidOut.current = true;
  }, [layout, layoutKey, rootsRef, compact]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.batch(() => {
      cy.elements().removeClass(STATUS_CLASSES);
      if (!statusClasses) return;
      for (const [id, status] of statusClasses) cy.getElementById(id).addClass(status);
    });
  }, [statusClasses, elements]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.batch(() => {
      cy.elements().removeClass('filtered');
      if (!hidden) return;
      for (const id of hidden) cy.getElementById(id).addClass('filtered');
    });
  }, [hidden, elements]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.batch(() => {
      cy.elements().removeClass('path faded');
      if (!highlight) return;
      cy.elements().forEach((element) => {
        const id = element.id();
        const on = element.isNode() ? highlight.nodes.has(id) : highlight.edges.has(id);
        element.addClass(on ? 'path' : 'faded');
      });
    });
  }, [highlight, elements]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.elements(':selected').unselect();
    if (selectedId) cy.getElementById(selectedId).select();
  }, [selectedId, elements]);

  // Canvas colors follow the theme tokens.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.style(buildGraphStyle(readGraphPalette()));
  }, [theme]);

  useImperativeHandle(
    ref,
    () => ({
      fit: () => {
        if (cyRef.current) fitToNodes(cyRef.current);
      },
      zoom: (factor: number) => {
        const cy = cyRef.current;
        if (!cy) return;
        cy.zoom({ level: cy.zoom() * factor, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
      },
      center: (id: string) => {
        const cy = cyRef.current;
        const node = cy?.getElementById(id);
        if (cy && node && node.nonempty()) cy.animate({ center: { eles: node } }, { duration: 200 });
      },
    }),
    [],
  );

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const cy = cyRef.current;
    if (!cy) return;
    if (event.key === '+' || event.key === '=')
      cy.zoom({ level: cy.zoom() * 1.2, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
    else if (event.key === '-')
      cy.zoom({ level: cy.zoom() / 1.2, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
    else if (event.key === '0') fitToNodes(cy);
    else return;
    event.preventDefault();
  };

  return (
    <div
      ref={containerRef}
      className="graph-canvas"
      role="application"
      aria-label={`${ariaLabel}. Keys: plus/minus zoom, 0 fits. Use the object list for keyboard selection.`}
      tabIndex={0}
      onKeyDown={onKeyDown}
    />
  );
}
