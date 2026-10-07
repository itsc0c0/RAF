import { useMemo } from 'react';
import type cytoscape from 'cytoscape';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useIncidents, useReplay } from '../api/hooks';
import type { ReplayTimeline } from '../api/types';
import { useInspector } from '../app/shellState';
import { SeverityBadge } from '../components/Badge';
import { Button } from '../components/Button';
import { Time } from '../components/Data';
import { Select } from '../components/Form';
import { Callout, PageHeader, Panel } from '../components/Panel';
import { EmptyState, QueryView } from '../components/States';
import { Table } from '../components/Table';
import { GraphCanvas } from '../features/graph/GraphCanvas';
import { nodeClasses } from '../features/graph/graphModel';
import { elementStatuses, everVisible, indexAtTime, severityMarkers } from '../features/replay/engine';
import { ReplayControls } from '../features/replay/ReplayControls';
import { EventLog, ReplayPanels } from '../features/replay/ReplayPanels';
import { Scrubber } from '../features/replay/Scrubber';
import { usePlayback } from '../features/replay/usePlayback';
import { formatNumber, formatTimestamp, objectKeyOf, objectTypeOf } from '../lib/format';
import { useDocumentKeydown } from '../lib/hooks';
import { shapeOf } from '../lib/objectTypes';
import { routeTo } from '../lib/routes';
import '../styles/graph.css';
import '../styles/replay.css';

/**
 * Every object/relationship that is visible at some step. Positions are computed once for this
 * union so nodes never jump while scrubbing; per-step visibility is a class toggle.
 */
function replayElements(timeline: ReplayTimeline): cytoscape.ElementDefinition[] {
  const visible = everVisible(timeline);
  const elements: cytoscape.ElementDefinition[] = [];
  for (const id of [...visible.objects].sort()) {
    const info = timeline.objects[id] ?? { name: objectKeyOf(id), type: objectTypeOf(id), criticality: null };
    elements.push({
      group: 'nodes',
      data: { id, label: info.name, type: info.type, shape: shapeOf(info.type) },
      classes: nodeClasses({ type: info.type, criticality: info.criticality, missing: false }, false),
    });
  }
  for (const id of [...visible.relationships].sort()) {
    const rel = timeline.relationships[id];
    if (!rel || !visible.objects.has(rel.source) || !visible.objects.has(rel.target)) continue;
    elements.push({
      group: 'edges',
      data: { id, source: rel.source, target: rel.target, label: rel.type, type: rel.type },
    });
  }
  return elements;
}

function isInteractive(target: EventTarget | null): boolean {
  return (
    target instanceof HTMLElement &&
    target.closest('button, a, input, select, textarea, [contenteditable="true"], [role="dialog"]') !== null
  );
}

function ReplayPlayer({ timeline }: { timeline: ReplayTimeline }) {
  const playback = usePlayback(timeline);
  const inspector = useInspector();
  const markers = useMemo(() => severityMarkers(timeline.steps), [timeline]);
  const elements = useMemo(() => replayElements(timeline), [timeline]);
  const statuses = useMemo(() => {
    if (!playback.state) return null;
    const map = new Map<string, string>();
    for (const [id, status] of elementStatuses(timeline, playback.state)) map.set(id, status);
    return map;
  }, [timeline, playback.state]);
  const start = Date.parse(timeline.start);
  const end = Date.parse(timeline.end);
  const current = playback.index >= 0 ? timeline.steps[playback.index] : undefined;

  useDocumentKeydown((event) => {
    if (
      event.defaultPrevented ||
      event.ctrlKey ||
      event.metaKey ||
      event.altKey ||
      isInteractive(event.target)
    )
      return;
    if (event.key === ' ') {
      event.preventDefault();
      if (playback.playing) playback.pause();
      else playback.play();
    } else if (event.key === 'ArrowRight') {
      event.preventDefault();
      playback.stepForward();
    } else if (event.key === 'ArrowLeft') {
      event.preventDefault();
      playback.stepBack();
    }
  });

  if (timeline.steps.length === 0) {
    return (
      <EmptyState title="Nothing to replay">
        <p>No events fall inside the replay window.</p>
      </EmptyState>
    );
  }

  return (
    <div className="replay">
      <div className="replay-transport">
        <ReplayControls playback={playback} length={timeline.steps.length} />
        <Scrubber
          start={start}
          end={end}
          time={playback.time}
          index={playback.index}
          markers={markers}
          steps={timeline.steps}
          onSeekTime={(time) => playback.seek(indexAtTime(timeline.steps, time))}
          onSeekIndex={playback.seek}
        />
      </div>
      <div className="replay-now" aria-live="polite">
        {current ? (
          <>
            <span className="tabular mono">{formatTimestamp(current.timestamp)}</span>
            <SeverityBadge severity={current.severity} />
            <span className="replay-now__summary break">{current.summary}</span>
            <Button
              size="sm"
              variant="ghost"
              icon="eye"
              onClick={() => inspector.openEvent(current.event_id)}
            >
              Event
            </Button>
          </>
        ) : (
          <span className="muted">
            Initial state at {formatTimestamp(timeline.start)} —{' '}
            {formatNumber(timeline.initial_objects.length)} objects,{' '}
            {formatNumber(timeline.initial_relationships.length)} relationships. Press play or step forward.
          </span>
        )}
      </div>
      {timeline.notes.length > 0 ? (
        <Callout tone="info">
          {timeline.notes.map((note) => (
            <p key={note}>{note}</p>
          ))}
        </Callout>
      ) : null}
      <div className="replay-grid">
        <section className="replay-graph" aria-label="State graph">
          <GraphCanvas
            ariaLabel={`Replay graph at ${formatTimestamp(playback.time)}`}
            elements={elements}
            layout="cose"
            compact
            layoutKey={timeline.scope.id}
            statusClasses={statuses}
            onSelect={(id, group) => {
              if (id && group === 'nodes') inspector.open(id);
            }}
          />
          <div className="graph-legend">
            <span className="graph-legend__item">
              <span className="swatch swatch--added" aria-hidden="true" /> added at this step
            </span>
            <span className="graph-legend__item">
              <span className="legend-dash legend-dash--removed" aria-hidden="true" /> removed at this step
            </span>
          </div>
        </section>
        {playback.state ? (
          <aside className="replay-side" aria-label="State at cursor">
            <ReplayPanels timeline={timeline} state={playback.state} time={playback.time} />
          </aside>
        ) : null}
        <section className="replay-log" aria-label="Event log">
          <EventLog steps={timeline.steps} index={playback.index} onSeek={playback.seek} />
        </section>
      </div>
    </div>
  );
}

function IncidentChooser({ onChoose }: { onChoose: (id: string) => void }) {
  const incidents = useIncidents();
  return (
    <Panel title="Choose an incident to replay" flush>
      <QueryView query={incidents} feature="Incidents">
        {(data) =>
          data.items.length === 0 ? (
            <div className="panel__pad">
              <EmptyState title="No incidents in this workspace">
                <p>
                  Incidents come from imported data (<code>raf demo load</code> creates INC-001). Any object
                  or analysis can also be replayed from the CLI: <code>raf replay &lt;ref&gt;</code>.
                </p>
              </EmptyState>
            </div>
          ) : (
            <Table
              caption="Incidents"
              rows={data.items}
              rowKey={(incident) => incident.id}
              onRowClick={(incident) => onChoose(incident.id)}
              columns={[
                { key: 'name', header: 'Incident', render: (i) => <strong>{i.name}</strong> },
                { key: 'title', header: 'Title', render: (i) => <span className="break">{i.title}</span> },
                {
                  key: 'severity',
                  header: 'Severity',
                  render: (i) => <SeverityBadge severity={i.severity} />,
                },
                {
                  key: 'start',
                  header: 'Window',
                  render: (i) => (
                    <span className="small">
                      <Time value={i.start} /> → <Time value={i.end} />
                    </span>
                  ),
                },
                {
                  key: 'events',
                  header: 'Events',
                  align: 'right',
                  render: (i) => formatNumber(i.event_count),
                },
              ]}
            />
          )
        }
      </QueryView>
    </Panel>
  );
}

export default function ReplayPage() {
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const reference = params.get('incident');
  const incidents = useIncidents();
  const replay = useReplay(reference);
  const options = (incidents.data?.items ?? []).map((incident) => ({
    value: incident.id,
    label: `${incident.name} — ${incident.title}`,
  }));
  if (reference && !options.some((option) => option.value === reference))
    options.unshift({ value: reference, label: reference });

  return (
    <div className="page page--full">
      <PageHeader
        title="Replay"
        subtitle={
          replay.data ? (
            <span className="break">{replay.data.title}</span>
          ) : (
            'Reconstruct the security state step by step'
          )
        }
        actions={
          reference ? (
            <>
              <Select
                aria-label="Incident"
                value={reference}
                options={options}
                onChange={(event) => setParams({ incident: event.target.value })}
              />
              <Button size="sm" icon="timeline" onClick={() => navigate(routeTo.timeline(reference))}>
                Timeline
              </Button>
              <Button size="sm" icon="graph" onClick={() => navigate(routeTo.graph(reference))}>
                Graph
              </Button>
            </>
          ) : null
        }
      />
      {reference ? (
        <QueryView key={reference} query={replay} feature="Replay" loadingLabel="Building replay…">
          {(timeline) => <ReplayPlayer key={timeline.scope.id} timeline={timeline} />}
        </QueryView>
      ) : (
        <IncidentChooser onChoose={(id) => setParams({ incident: id })} />
      )}
    </div>
  );
}
