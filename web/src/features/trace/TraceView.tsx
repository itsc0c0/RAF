import { useMemo, useState } from 'react';
import { useTrace } from '../../api/hooks';
import type { TraceLink, TraceNode, TraceResult } from '../../api/types';
import { useInspector } from '../../app/shellState';
import { ConfidenceBadge } from '../../components/Badge';
import { Button } from '../../components/Button';
import { Chain, hopsToChain } from '../../components/Chain';
import { Select } from '../../components/Form';
import { Icon } from '../../components/Icon';
import { ObjectChip } from '../../components/ObjectChip';
import { Callout, Panel, Toolbar } from '../../components/Panel';
import { EmptyState, QueryView } from '../../components/States';
import { cx } from '../../lib/cx';
import { formatTimestamp } from '../../lib/format';
import { buildTraceTree, countTree, isCorrelated, type TraceTreeNode } from './traceTree';

export const CORRELATION_NOTE =
  'Observed links come directly from a single event. Correlated links (dashed) are consistent in time and structure, but correlation is not causation: verify them before drawing conclusions.';

function KindPill({ link }: { link: TraceLink }) {
  const correlated = isCorrelated(link);
  return (
    <span
      className={cx('kind', correlated ? 'kind--correlated' : 'kind--observed')}
      title={
        correlated
          ? 'Correlated: consistent in time and structure, not proven causation'
          : 'Observed directly in an event'
      }
    >
      {correlated ? 'correlated' : 'observed'}
    </span>
  );
}

function LinkMeta({ link }: { link: TraceLink }) {
  const { openEvent } = useInspector();
  const provenance = [link.provenance.source, link.provenance.record].filter(Boolean).join(' #');
  return (
    <div className="trace-link__meta small muted row row--wrap">
      <span className="tabular">{formatTimestamp(link.timestamp)}</span>
      {provenance ? <span className="mono">{provenance}</span> : null}
      {link.corroborated_by.length > 0 ? (
        <span
          title={link.corroborated_by
            .map((item) => [item.source, item.record].filter(Boolean).join('#'))
            .join(', ')}
        >
          +{link.corroborated_by.length} corroborating source{link.corroborated_by.length === 1 ? '' : 's'}
        </span>
      ) : null}
      {link.event_id ? (
        <button type="button" className="link-btn" onClick={() => openEvent(link.event_id!)}>
          event
        </button>
      ) : null}
    </div>
  );
}

function TreeItem({
  node,
  names,
  backward,
  level,
}: {
  node: TraceTreeNode;
  names: Map<string, TraceNode>;
  backward: boolean;
  level: number;
}) {
  const [open, setOpen] = useState(level < 2);
  const link = node.link;
  const subject = backward ? link.cause : link.effect;
  const other = backward ? link.effect : link.cause;
  const hasChildren = node.children.length > 0;
  return (
    <li className={cx('trace-item', isCorrelated(link) && 'trace-item--correlated')}>
      <div className="trace-link">
        {hasChildren ? (
          <button
            type="button"
            className="trace-link__toggle"
            aria-expanded={open}
            aria-label={`${open ? 'Collapse' : 'Expand'} ${node.children.length} further link${node.children.length === 1 ? '' : 's'}`}
            onClick={() => setOpen((value) => !value)}
          >
            <Icon name={open ? 'chevronDown' : 'chevronRight'} size={14} />
          </button>
        ) : (
          <span className="trace-link__toggle" aria-hidden="true" />
        )}
        <div className="trace-link__body">
          <div className="row row--wrap">
            <ObjectChip id={subject} name={names.get(subject)?.name} type={names.get(subject)?.type} />
            <span className="trace-link__relation mono">
              {backward ? `${link.relation} →` : `← ${link.relation}`}
            </span>
            <span className="small muted">{names.get(other)?.name ?? other}</span>
            <KindPill link={link} />
            <ConfidenceBadge confidence={link.confidence} />
          </div>
          <p className="trace-link__explanation">{link.explanation}</p>
          <LinkMeta link={link} />
        </div>
      </div>
      {hasChildren && open ? (
        <ul className="trace-tree__children">
          {node.children.map((child) => (
            <TreeItem
              key={child.link.step}
              node={child}
              names={names}
              backward={backward}
              level={level + 1}
            />
          ))}
        </ul>
      ) : null}
    </li>
  );
}

function TraceTree({
  links,
  names,
  backward,
  label,
}: {
  links: readonly TraceLink[];
  names: Map<string, TraceNode>;
  backward: boolean;
  label: string;
}) {
  const tree = useMemo(() => buildTraceTree(links), [links]);
  if (tree.length === 0) return <p className="muted small">No {backward ? 'causes' : 'effects'} found.</p>;
  return (
    <>
      <p className="small muted">{countTree(tree)} links</p>
      <ul className="trace-tree" aria-label={label}>
        {tree.map((node) => (
          <TreeItem key={node.link.step} node={node} names={names} backward={backward} level={0} />
        ))}
      </ul>
    </>
  );
}

/** The "most supported causal chain", earliest cause first, ending at the subject. */
export function CausalChain({
  chain,
  names,
}: {
  chain: readonly TraceLink[];
  names: Map<string, TraceNode>;
}) {
  if (chain.length === 0)
    return <p className="muted small">No causal chain could be supported by the data.</p>;
  const hops = chain.map((link) => ({ ...link, source: link.cause, target: link.effect }));
  return (
    <Chain
      label="Most supported causal chain"
      items={hopsToChain(
        hops,
        (id) => (
          <ObjectChip id={id} name={names.get(id)?.name} type={names.get(id)?.type} />
        ),
        (hop) => (
          <div className="stack stack--tight">
            <div className="row row--wrap">
              <span className="mono small">{hop.relation}</span>
              <KindPill link={hop} />
              <ConfidenceBadge confidence={hop.confidence} />
            </div>
            <span className="small">{hop.explanation}</span>
            <LinkMeta link={hop} />
          </div>
        ),
        (hop) => (isCorrelated(hop) ? 'dashed' : 'solid'),
      )}
    />
  );
}

function TraceResultView({ result }: { result: TraceResult }) {
  const names = useMemo(() => new Map(result.nodes.map((node) => [node.id, node] as const)), [result]);
  return (
    <div className="stack">
      <Callout tone="info" title="Correlation is not causation">
        <p>{CORRELATION_NOTE}</p>
        {result.notes
          .filter((note) => !/causation/i.test(note))
          .map((note) => (
            <p key={note}>{note}</p>
          ))}
      </Callout>
      <div className="trace-grid">
        <Panel title="Most supported causal chain" className="trace-chain">
          <CausalChain chain={result.chain} names={names} />
        </Panel>
        <div className="stack">
          <Panel title={`How ${result.subject.name} became involved (backward)`}>
            <TraceTree links={result.backward} names={names} backward label="Backward trace" />
          </Panel>
          <Panel title={`What ${result.subject.name} did next (forward)`}>
            <TraceTree links={result.forward} names={names} backward={false} label="Forward trace" />
          </Panel>
        </div>
      </div>
    </div>
  );
}

const DIRECTIONS = [
  { value: 'both', label: 'Both directions' },
  { value: 'back', label: 'Backward (causes)' },
  { value: 'forward', label: 'Forward (effects)' },
];

export function TraceView({ subject, onClose }: { subject: string; onClose?: () => void }) {
  const [direction, setDirection] = useState('both');
  const [depth, setDepth] = useState(3);
  const query = useTrace(subject, direction, depth);
  return (
    <div className="stack">
      <Toolbar label="Trace options">
        <span className="row">
          <Icon name="route" />
          <strong>Trace</strong>
          <ObjectChip id={query.data?.subject.id ?? subject} name={query.data?.subject.name} />
        </span>
        <Select
          aria-label="Direction"
          value={direction}
          options={DIRECTIONS}
          onChange={(event) => setDirection(event.target.value)}
        />
        <Select
          aria-label="Depth"
          value={String(depth)}
          options={[1, 2, 3, 4, 5, 6].map((d) => ({ value: String(d), label: `Depth ${d}` }))}
          onChange={(event) => setDepth(Number(event.target.value))}
        />
        {onClose ? (
          <Button size="sm" variant="ghost" icon="close" onClick={onClose}>
            Close trace
          </Button>
        ) : null}
      </Toolbar>
      <QueryView query={query} feature="Trace" loadingLabel="Tracing…">
        {(result) =>
          result.backward.length === 0 && result.forward.length === 0 ? (
            <EmptyState title="No causal links found">
              <p>No events link {result.subject.name} to other objects.</p>
            </EmptyState>
          ) : (
            <TraceResultView result={result} />
          )
        }
      </QueryView>
    </div>
  );
}
