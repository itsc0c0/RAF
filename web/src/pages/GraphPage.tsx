import { useMemo, useRef, useState, type ReactNode } from 'react';
import { useSearchParams } from 'react-router-dom';
import { downloadUrl } from '../api/client';
import { useInspector } from '../app/shellState';
import { useWorkspaceName } from '../app/workspace';
import { Badge } from '../components/Badge';
import { Button, IconButton } from '../components/Button';
import { Select, TextInput } from '../components/Form';
import { Callout, PageHeader, Toolbar } from '../components/Panel';
import { LoadingState } from '../components/Spinner';
import {
  EmptyState,
  ErrorState,
  isUnavailableError,
  NoDataHint,
  UnavailableState,
} from '../components/States';
import { TabPanel, Tabs } from '../components/Tabs';
import { GraphCanvas, LAYOUTS, type GraphCanvasHandle, type LayoutName } from '../features/graph/GraphCanvas';
import {
  hiddenElements,
  nodeTypeCounts,
  relationshipTypeCounts,
  toElements,
} from '../features/graph/graphModel';
import {
  EdgeSelection,
  GraphLegend,
  NodeList,
  NodeSelection,
  PathFinder,
  TypeFilters,
} from '../features/graph/GraphPanels';
import { useGraphExplorer } from '../features/graph/useGraphExplorer';
import { formatNumber, formatTimestamp, inputFromIso, isoFromInput } from '../lib/format';
import '../styles/graph.css';

type SideTab = 'filters' | 'objects' | 'path';

const DEPTHS = [1, 2, 3, 4].map((d) => ({ value: String(d), label: `Depth ${d}` }));
const EXPORT_FORMATS = ['graphml', 'json', 'cytoscape', 'csv', 'dot'] as const;

function clampDepth(value: string | null): number {
  const depth = Number(value ?? 2);
  return Number.isFinite(depth) ? Math.max(1, Math.min(4, Math.trunc(depth))) : 2;
}

/** Remounts per focus/time so inputs and local expansions always match the URL (pivots included). */
export default function GraphPage() {
  const [params] = useSearchParams();
  return <GraphView key={`${params.get('focus') ?? ''}|${params.get('at') ?? ''}`} />;
}

function GraphView() {
  const [params, setParams] = useSearchParams();
  const focus = params.get('focus');
  const depth = clampDepth(params.get('depth'));
  const at = params.get('at');
  const workspace = useWorkspaceName();
  const inspector = useInspector();
  const explorer = useGraphExplorer({ focus, depth, at });
  const { model } = explorer;

  const [layout, setLayout] = useState<LayoutName>('cose');
  const [hiddenNodeTypes, setHiddenNodeTypes] = useState<Set<string>>(() => new Set());
  const [hiddenRelationshipTypes, setHiddenRelationshipTypes] = useState<Set<string>>(() => new Set());
  const [selected, setSelected] = useState<{ id: string; group: 'nodes' | 'edges' } | null>(null);
  const [tab, setTab] = useState<SideTab>('filters');
  const [focusInput, setFocusInput] = useState(focus ?? '');
  const [atInput, setAtInput] = useState(inputFromIso(at));
  const [pathSource, setPathSource] = useState(focus ?? '');
  const [pathTarget, setPathTarget] = useState('');
  const [exportFormat, setExportFormat] = useState<(typeof EXPORT_FORMATS)[number]>('graphml');
  const canvas = useRef<GraphCanvasHandle>(null);

  const elements = useMemo(() => (model ? toElements(model) : []), [model]);
  const hidden = useMemo(
    () => (model ? hiddenElements(model, hiddenNodeTypes, hiddenRelationshipTypes) : null),
    [model, hiddenNodeTypes, hiddenRelationshipTypes],
  );
  const nodeTypes = useMemo(() => (model ? nodeTypeCounts(model) : []), [model]);
  const relationshipTypes = useMemo(() => (model ? relationshipTypeCounts(model) : []), [model]);

  const selectedNode = selected?.group === 'nodes' ? model?.nodes.get(selected.id) : undefined;
  const selectedEdge = selected?.group === 'edges' ? model?.edges.get(selected.id) : undefined;

  const updateParams = (changes: Record<string, string | null>) => {
    const next = new URLSearchParams(params);
    for (const [key, value] of Object.entries(changes)) {
      if (value) next.set(key, value);
      else next.delete(key);
    }
    setParams(next);
    setSelected(null);
  };

  const visibleNodes = model ? [...model.nodes.keys()].filter((id) => !hidden?.has(id)).length : 0;
  const visibleEdges = model ? [...model.edges.keys()].filter((id) => !hidden?.has(id)).length : 0;
  const scopeLabel = explorer.view.data?.scope?.label ?? (focus ? focus : 'workspace overview');

  let stageOverlay: ReactNode = null;
  if (explorer.view.isError && !explorer.view.data) {
    stageOverlay = isUnavailableError(explorer.view.error) ? (
      <UnavailableState feature="Graph" error={explorer.view.error} />
    ) : (
      <ErrorState error={explorer.view.error} onRetry={() => void explorer.view.refetch()} />
    );
  } else if (!explorer.view.data) {
    stageOverlay = <LoadingState label="Loading graph…" />;
  } else if (model && model.nodes.size === 0) {
    stageOverlay = focus ? (
      <EmptyState title="Nothing to show">
        <p>
          No relationships were found around “{focus}”{at ? ` as of ${formatTimestamp(at)}` : ''}.
        </p>
      </EmptyState>
    ) : (
      <NoDataHint />
    );
  }

  return (
    <div className="page page--full graph-page">
      <PageHeader
        title="Graph"
        subtitle={
          <>
            <span className="break">{scopeLabel}</span>
            {at ? (
              <Badge tone="warn" title="Relationships active at this instant">
                as of {formatTimestamp(at)}
              </Badge>
            ) : null}
          </>
        }
      >
        <Toolbar label="Graph controls" className="graph-toolbar">
          <form
            className="row"
            onSubmit={(event) => {
              event.preventDefault();
              updateParams({ focus: focusInput.trim() || null });
            }}
          >
            <label className="sr-only" htmlFor="graph-focus">
              Focus object
            </label>
            <TextInput
              id="graph-focus"
              value={focusInput}
              placeholder="Focus: ID, name or incident"
              onChange={(event) => setFocusInput(event.target.value)}
            />
            <Button type="submit" variant="primary" size="sm">
              Load
            </Button>
            {focus ? (
              <Button
                size="sm"
                variant="ghost"
                onClick={() => {
                  setFocusInput('');
                  updateParams({ focus: null, depth: null });
                }}
              >
                Overview
              </Button>
            ) : null}
          </form>
          <Select
            aria-label="Neighborhood depth"
            options={DEPTHS}
            value={String(depth)}
            disabled={!focus}
            onChange={(event) => updateParams({ depth: event.target.value })}
          />
          <form
            className="row"
            onSubmit={(event) => {
              event.preventDefault();
              updateParams({ at: isoFromInput(atInput) });
            }}
          >
            <label className="small muted" htmlFor="graph-at">
              As of (UTC)
            </label>
            <input
              id="graph-at"
              className="input input--compact"
              type="datetime-local"
              step={1}
              value={atInput}
              onChange={(event) => setAtInput(event.target.value)}
            />
            <Button type="submit" size="sm">
              Apply
            </Button>
            {at ? (
              <Button
                size="sm"
                variant="ghost"
                onClick={() => {
                  setAtInput('');
                  updateParams({ at: null });
                }}
              >
                Now
              </Button>
            ) : null}
          </form>
          <Select
            aria-label="Layout"
            options={LAYOUTS}
            value={layout}
            onChange={(event) => setLayout(event.target.value as LayoutName)}
          />
          <span className="toolbar__group">
            <IconButton icon="plus" label="Zoom in" onClick={() => canvas.current?.zoom(1.25)} />
            <IconButton icon="minus" label="Zoom out" onClick={() => canvas.current?.zoom(0.8)} />
            <IconButton icon="fit" label="Fit to view" onClick={() => canvas.current?.fit()} />
          </span>
          {explorer.modified ? (
            <Button size="sm" variant="ghost" icon="reset" onClick={explorer.reset}>
              Reset expansions
            </Button>
          ) : null}
          <span className="toolbar__group">
            <Select
              aria-label="Export format"
              options={EXPORT_FORMATS.map((format) => ({ value: format, label: format.toUpperCase() }))}
              value={exportFormat}
              onChange={(event) => setExportFormat(event.target.value as (typeof EXPORT_FORMATS)[number])}
            />
            <a
              className="btn btn--secondary btn--sm"
              href={downloadUrl(
                '/graph/export',
                { ref: focus ?? undefined, depth: focus ? depth : undefined, format: exportFormat },
                workspace,
              )}
              download={`raf-graph.${exportFormat === 'cytoscape' ? 'json' : exportFormat}`}
            >
              Export
            </a>
          </span>
        </Toolbar>
      </PageHeader>

      <div className="graph-layout">
        <aside className="graph-side" aria-label="Graph filters and tools">
          <Tabs<SideTab>
            label="Graph tools"
            idPrefix="graph-side"
            value={tab}
            onChange={setTab}
            items={[
              { key: 'filters', label: 'Filters' },
              { key: 'objects', label: 'Objects', badge: model ? formatNumber(model.nodes.size) : undefined },
              { key: 'path', label: 'Path' },
            ]}
          />
          <TabPanel idPrefix="graph-side" activeKey={tab}>
            {tab === 'filters' ? (
              <TypeFilters
                nodeTypes={nodeTypes}
                relationshipTypes={relationshipTypes}
                hiddenNodeTypes={hiddenNodeTypes}
                hiddenRelationshipTypes={hiddenRelationshipTypes}
                onNodeTypes={setHiddenNodeTypes}
                onRelationshipTypes={setHiddenRelationshipTypes}
              />
            ) : null}
            {tab === 'objects' && model ? (
              <NodeList
                model={model}
                hidden={hidden}
                selectedId={selected?.id ?? null}
                onSelect={(id) => {
                  setSelected({ id, group: 'nodes' });
                  canvas.current?.center(id);
                  inspector.open(id);
                }}
              />
            ) : null}
            {tab === 'path' ? (
              <PathFinder
                source={pathSource}
                target={pathTarget}
                onSource={setPathSource}
                onTarget={setPathTarget}
                busy={explorer.pathBusy}
                path={explorer.path}
                selectedNode={selectedNode?.id ?? null}
                onFind={() => void explorer.findPath(pathSource.trim(), pathTarget.trim())}
                onClear={explorer.clearPath}
              />
            ) : null}
          </TabPanel>
        </aside>

        <section className="graph-stage" aria-label="Graph canvas">
          <GraphCanvas
            ref={canvas}
            ariaLabel={`Graph of ${scopeLabel}: ${visibleNodes} nodes, ${visibleEdges} edges`}
            elements={elements}
            layout={layout}
            layoutKey={`${explorer.viewKey}:${explorer.layoutNonce}`}
            roots={model?.roots}
            hidden={hidden}
            highlight={explorer.highlight}
            selectedId={selected?.id ?? null}
            onSelect={(id, group) => {
              if (!id || !group) {
                setSelected(null);
                return;
              }
              setSelected({ id, group });
              if (group === 'nodes') inspector.open(id);
            }}
            onExpand={(id) => void explorer.expand(id)}
          />
          {stageOverlay ? <div className="graph-stage__overlay">{stageOverlay}</div> : null}
          {selectedNode ? (
            <NodeSelection
              node={selectedNode}
              expanding={explorer.expanding === selectedNode.id}
              onExpand={() => void explorer.expand(selectedNode.id)}
              onCollapse={() => explorer.collapse(selectedNode.id)}
              onInspect={() => inspector.open(selectedNode.id)}
            />
          ) : null}
          {selectedEdge ? (
            <EdgeSelection
              edge={selectedEdge}
              source={model?.nodes.get(selectedEdge.source)}
              target={model?.nodes.get(selectedEdge.target)}
            />
          ) : null}
          <GraphLegend />
        </section>
      </div>

      <footer className="graph-status" aria-live="polite">
        <span className="tabular">
          {formatNumber(visibleNodes)} nodes · {formatNumber(visibleEdges)} edges
          {hidden && hidden.size > 0 ? ` · ${formatNumber(hidden.size)} hidden by filters` : ''}
        </span>
        {explorer.view.isFetching && explorer.view.data ? <span className="muted">Refreshing…</span> : null}
        <span className="muted">Double-click a node to expand its neighbors.</span>
      </footer>
      {model?.truncated ? (
        <Callout tone="warn" title="Truncated view">
          The server capped this view (setting <code>graph.max_nodes</code>); some objects are not shown.
          Focus on an object, reduce the depth or use filters to see a complete neighborhood.
        </Callout>
      ) : null}
    </div>
  );
}
