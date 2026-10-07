import { useMemo, useState } from 'react';
import type { GraphEdge, GraphNode, PathResult } from '../../api/types';
import { ConfidenceBadge, CriticalityTag } from '../../components/Badge';
import { Button } from '../../components/Button';
import { Chain, hopsToChain } from '../../components/Chain';
import { KeyValueList, MetadataList, Mono, Time } from '../../components/Data';
import { Checkbox, Field, TextInput } from '../../components/Form';
import { ObjectChip, TypeTag } from '../../components/ObjectChip';
import { cx } from '../../lib/cx';
import { formatNumber } from '../../lib/format';
import { FAMILY_LABELS, familyOf, typeLabel, type NodeFamily } from '../../lib/objectTypes';
import type { GraphModel, TypeCount } from './graphModel';

function toggleIn(set: ReadonlySet<string>, value: string, on: boolean): Set<string> {
  const next = new Set(set);
  if (on) next.delete(value);
  else next.add(value);
  return next;
}

/** Type filters built from the loaded data (checked = visible). Doubles as the color legend. */
export function TypeFilters({
  nodeTypes,
  relationshipTypes,
  hiddenNodeTypes,
  hiddenRelationshipTypes,
  onNodeTypes,
  onRelationshipTypes,
}: {
  nodeTypes: readonly TypeCount[];
  relationshipTypes: readonly TypeCount[];
  hiddenNodeTypes: ReadonlySet<string>;
  hiddenRelationshipTypes: ReadonlySet<string>;
  onNodeTypes: (hidden: Set<string>) => void;
  onRelationshipTypes: (hidden: Set<string>) => void;
}) {
  return (
    <div className="stack">
      <fieldset className="filter-group">
        <legend className="filter-group__legend">
          Object types
          <span className="filter-group__actions">
            <button type="button" className="link-btn" onClick={() => onNodeTypes(new Set())}>
              all
            </button>
            <button
              type="button"
              className="link-btn"
              onClick={() => onNodeTypes(new Set(nodeTypes.map((t) => t.type)))}
            >
              none
            </button>
          </span>
        </legend>
        {nodeTypes.length === 0 ? <p className="muted small">No objects.</p> : null}
        {nodeTypes.map(({ type, count }) => (
          <Checkbox
            key={type}
            label={typeLabel(type)}
            count={count}
            checked={!hiddenNodeTypes.has(type)}
            swatch={<span className={cx('swatch', `swatch--${familyOf(type)}`)} aria-hidden="true" />}
            onChange={(checked) => onNodeTypes(toggleIn(hiddenNodeTypes, type, checked))}
          />
        ))}
      </fieldset>
      <fieldset className="filter-group">
        <legend className="filter-group__legend">
          Relationship types
          <span className="filter-group__actions">
            <button type="button" className="link-btn" onClick={() => onRelationshipTypes(new Set())}>
              all
            </button>
            <button
              type="button"
              className="link-btn"
              onClick={() => onRelationshipTypes(new Set(relationshipTypes.map((t) => t.type)))}
            >
              none
            </button>
          </span>
        </legend>
        {relationshipTypes.length === 0 ? <p className="muted small">No relationships.</p> : null}
        {relationshipTypes.map(({ type, count }) => (
          <Checkbox
            key={type}
            label={<span className="mono">{type}</span>}
            count={count}
            checked={!hiddenRelationshipTypes.has(type)}
            onChange={(checked) => onRelationshipTypes(toggleIn(hiddenRelationshipTypes, type, checked))}
          />
        ))}
      </fieldset>
    </div>
  );
}

const LEGEND_FAMILIES: NodeFamily[] = ['asset', 'principal', 'activity', 'neutral'];

export function GraphLegend() {
  return (
    <div className="graph-legend" aria-label="Legend">
      {LEGEND_FAMILIES.map((family) => (
        <span key={family} className="graph-legend__item">
          <span className={cx('swatch', `swatch--${family}`)} aria-hidden="true" />
          {FAMILY_LABELS[family]}
        </span>
      ))}
      <span className="graph-legend__item">
        <span className="swatch swatch--ring" aria-hidden="true" />
        border = criticality
      </span>
      <span className="graph-legend__item">
        <span className="legend-dash" aria-hidden="true" />
        virtual (incident involvement)
      </span>
      <span className="graph-legend__item muted">shape = object type</span>
    </div>
  );
}

/** Keyboard/screen-reader access to every node in the view (the canvas itself is pointer-first). */
export function NodeList({
  model,
  hidden,
  selectedId,
  onSelect,
}: {
  model: GraphModel;
  hidden: ReadonlySet<string> | null;
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  const [filter, setFilter] = useState('');
  const nodes = useMemo(() => {
    const text = filter.trim().toLowerCase();
    return [...model.nodes.values()]
      .filter(
        (node) => !text || node.name.toLowerCase().includes(text) || node.id.toLowerCase().includes(text),
      )
      .sort((a, b) => a.type.localeCompare(b.type) || a.name.localeCompare(b.name));
  }, [model, filter]);
  return (
    <div className="stack">
      <Field label="Filter objects in view">
        {(id) => (
          <TextInput
            id={id}
            value={filter}
            placeholder="name or ID"
            onChange={(e) => setFilter(e.target.value)}
          />
        )}
      </Field>
      <ul className="node-list" aria-label="Objects in view">
        {nodes.slice(0, 400).map((node) => (
          <li key={node.id}>
            <button
              type="button"
              className={cx(
                'node-list__item',
                node.id === selectedId && 'is-selected',
                hidden?.has(node.id) && 'is-hidden',
              )}
              onClick={() => onSelect(node.id)}
              title={node.id}
            >
              <TypeTag type={node.type} />
              <span className="truncate">{node.name}</span>
            </button>
          </li>
        ))}
      </ul>
      {nodes.length > 400 ? (
        <p className="muted small">Showing 400 of {formatNumber(nodes.length)}; refine the filter.</p>
      ) : null}
    </div>
  );
}

export function PathFinder({
  source,
  target,
  onSource,
  onTarget,
  onFind,
  onClear,
  busy,
  path,
  selectedNode,
}: {
  source: string;
  target: string;
  onSource: (value: string) => void;
  onTarget: (value: string) => void;
  onFind: () => void;
  onClear: () => void;
  busy: boolean;
  path: PathResult | null;
  selectedNode: string | null;
}) {
  return (
    <div className="stack">
      <form
        className="stack"
        onSubmit={(event) => {
          event.preventDefault();
          if (source.trim() && target.trim()) onFind();
        }}
      >
        <Field label="From">
          {(id) => (
            <div className="row">
              <TextInput
                id={id}
                className="grow"
                value={source}
                placeholder="e.g. bob"
                onChange={(e) => onSource(e.target.value)}
              />
              <Button
                size="sm"
                variant="ghost"
                disabled={!selectedNode}
                onClick={() => selectedNode && onSource(selectedNode)}
              >
                Use selected
              </Button>
            </div>
          )}
        </Field>
        <Field label="To">
          {(id) => (
            <div className="row">
              <TextInput
                id={id}
                className="grow"
                value={target}
                placeholder="e.g. DB-01"
                onChange={(e) => onTarget(e.target.value)}
              />
              <Button
                size="sm"
                variant="ghost"
                disabled={!selectedNode}
                onClick={() => selectedNode && onTarget(selectedNode)}
              >
                Use selected
              </Button>
            </div>
          )}
        </Field>
        <div className="row">
          <Button
            type="submit"
            variant="primary"
            icon="route"
            loading={busy}
            disabled={!source.trim() || !target.trim()}
          >
            Find path
          </Button>
          {path ? (
            <Button variant="ghost" onClick={onClear}>
              Clear
            </Button>
          ) : null}
        </div>
      </form>
      {path ? (
        <div className="stack stack--tight">
          <p className="small muted">
            Shortest {path.directed ? 'directed' : 'undirected'} path · {path.length} hop
            {path.length === 1 ? '' : 's'}
          </p>
          <Chain
            label="Path"
            items={hopsToChain(
              path.hops,
              (id) => (
                <ObjectChip
                  id={id}
                  name={
                    path.hops.find((h) => h.source === id)?.source_name ??
                    path.hops.find((h) => h.target === id)?.target_name
                  }
                />
              ),
              (hop) => (
                <span className="row row--wrap small">
                  <span className="mono">
                    {hop.forward ? '' : '← '}
                    {hop.relationship.type}
                    {hop.forward ? ' →' : ''}
                  </span>
                  <ConfidenceBadge confidence={hop.relationship.confidence} showValue={false} />
                </span>
              ),
            )}
          />
        </div>
      ) : null}
    </div>
  );
}

export function NodeSelection({
  node,
  onExpand,
  onCollapse,
  onInspect,
  expanding,
}: {
  node: GraphNode;
  onExpand: () => void;
  onCollapse: () => void;
  onInspect: () => void;
  expanding: boolean;
}) {
  return (
    <div className="selection-card" aria-label="Selected object">
      <div className="row row--wrap">
        <TypeTag type={node.type} />
        <strong className="truncate" title={node.name}>
          {node.name}
        </strong>
        <CriticalityTag value={node.criticality} />
      </div>
      <Mono className="small muted">{node.id}</Mono>
      <div className="row row--wrap">
        <Button
          size="sm"
          icon="expand"
          loading={expanding}
          onClick={onExpand}
          title="Double-click a node to expand it"
        >
          Expand
        </Button>
        <Button size="sm" icon="collapse" onClick={onCollapse}>
          Collapse branch
        </Button>
        <Button size="sm" icon="eye" onClick={onInspect}>
          Inspect
        </Button>
      </div>
    </div>
  );
}

export function EdgeSelection({
  edge,
  source,
  target,
}: {
  edge: GraphEdge;
  source?: GraphNode;
  target?: GraphNode;
}) {
  return (
    <div className="selection-card" aria-label="Selected relationship">
      <div className="row row--wrap">
        <span className="mono">{edge.type}</span>
        {edge.metadata?.virtual === true ? <span className="tag">virtual</span> : null}
        <ConfidenceBadge confidence={edge.confidence} />
      </div>
      <div className="row row--wrap">
        <ObjectChip id={edge.source} name={source?.name} />
        <span aria-hidden="true">→</span>
        <ObjectChip id={edge.target} name={target?.name} />
      </div>
      <KeyValueList
        entries={[
          ['First seen', <Time value={edge.first_seen} />],
          ['Last seen', <Time value={edge.last_seen} />],
          ...(edge.valid_to ? ([['Ended', <Time value={edge.valid_to} />]] as const) : []),
          ['Observations', formatNumber(edge.observations)],
        ]}
      />
      {Object.keys(edge.metadata ?? {}).length > 0 ? <MetadataList metadata={edge.metadata} /> : null}
    </div>
  );
}
