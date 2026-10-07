import type { ReactNode } from 'react';
import type { ReplayObjectInfo, ReplayStep, ReplayTimeline } from '../../api/types';
import { SeverityBadge } from '../../components/Badge';
import { ObjectChip } from '../../components/ObjectChip';
import { VirtualList } from '../../components/VirtualList';
import { cx } from '../../lib/cx';
import { displayValue, formatBytes, formatTime } from '../../lib/format';
import { recentFlows, type ReplayState } from './engine';

type Names = Record<string, ReplayObjectInfo>;

function Ref({ id, objects }: { id: string | null | undefined; objects: Names }) {
  if (!id) return <span className="muted">—</span>;
  const info = objects[id];
  return <ObjectChip id={id} name={info?.name} type={info?.type} showType={false} />;
}

function Section({ title, count, children }: { title: string; count: number; children: ReactNode }) {
  return (
    <section className="replay-panel" aria-label={title}>
      <h3 className="replay-panel__title">
        {title} <span className="muted tabular">{count}</span>
      </h3>
      {count === 0 ? <p className="muted small">None at this point.</p> : children}
    </section>
  );
}

const RECENT_LIMIT = 12;

function latest<T>(items: readonly T[], limit = RECENT_LIMIT): T[] {
  return items.slice(-limit).reverse();
}

/** Side panels describing the reconstructed state at the cursor. */
export function ReplayPanels({
  timeline,
  state,
  time,
}: {
  timeline: ReplayTimeline;
  state: ReplayState;
  time: number;
}) {
  const objects = timeline.objects;
  const sessions = [...state.sessions.values()];
  const processes = [...state.processes.values()];
  const flows = recentFlows(state, time);
  return (
    <div className="replay-panels">
      <Section title="Active sessions" count={sessions.length}>
        <ul className="replay-list">
          {sessions.map((session) => (
            <li key={`${session.user}@${session.host}`} className="replay-list__item">
              <div className="row row--wrap">
                <Ref id={session.user} objects={objects} />
                <span aria-hidden="true">→</span>
                <Ref id={session.host} objects={objects} />
              </div>
              <div className="small muted row row--wrap">
                <span>since {formatTime(session.since)}</span>
                {session.method ? <span className="mono">{session.method}</span> : null}
                {session.source ? (
                  <span>
                    from <Ref id={session.source} objects={objects} />
                  </span>
                ) : null}
              </div>
            </li>
          ))}
        </ul>
      </Section>
      <Section title="Running processes" count={processes.length}>
        <ul className="replay-list">
          {processes.map((process) => (
            <li key={process.process} className="replay-list__item">
              <div className="row row--wrap">
                <Ref id={process.process} objects={objects} />
                {process.host ? (
                  <span className="small muted">
                    on <Ref id={process.host} objects={objects} />
                  </span>
                ) : null}
              </div>
              {process.command_line ? (
                <code className="replay-list__cmd break">{process.command_line}</code>
              ) : null}
              <div className="small muted">
                {process.user ? <Ref id={process.user} objects={objects} /> : null} since{' '}
                {formatTime(process.since)}
              </div>
            </li>
          ))}
        </ul>
      </Section>
      <Section title="Recent flows (10 min)" count={flows.length}>
        <ul className="replay-list">
          {latest(flows).map((flow, index) => (
            <li key={`${flow.at}-${index}`} className="replay-list__item">
              <div className="row row--wrap">
                <Ref id={flow.source} objects={objects} />
                <span aria-hidden="true">→</span>
                <Ref id={flow.destination} objects={objects} />
                {flow.port !== null && flow.port !== undefined ? (
                  <span className="mono small">:{displayValue(flow.port)}</span>
                ) : null}
              </div>
              <div className="small muted row row--wrap">
                <span>{formatTime(flow.at)}</span>
                {flow.protocol ? <span className="mono">{flow.protocol}</span> : null}
                {flow.bytes_out !== null && flow.bytes_out !== undefined ? (
                  <span>{formatBytes(Number(flow.bytes_out))} out</span>
                ) : null}
              </div>
            </li>
          ))}
        </ul>
      </Section>
      <Section title="File activity" count={state.files.length}>
        <ul className="replay-list">
          {latest(state.files).map((file, index) => (
            <li key={`${file.at}-${index}`} className="replay-list__item">
              <div className="row row--wrap">
                <span className="tag">{file.operation}</span>
                <Ref id={file.file} objects={objects} />
              </div>
              <div className="small muted row row--wrap">
                <span>{formatTime(file.at)}</span>
                {file.actor ? (
                  <span>
                    by <Ref id={file.actor} objects={objects} />
                  </span>
                ) : null}
              </div>
            </li>
          ))}
        </ul>
      </Section>
      <Section title="Identity changes" count={state.identityChanges.length}>
        <ul className="replay-list">
          {latest(state.identityChanges).map((change, index) => (
            <li key={`${change.at}-${index}`} className="replay-list__item">
              <div className="row row--wrap">
                <span className="mono small">{change.change}</span>
                <Ref id={change.target} objects={objects} />
              </div>
              <div className="small muted row row--wrap">
                <span>{formatTime(change.at)}</span>
                {change.actor ? (
                  <span>
                    by <Ref id={change.actor} objects={objects} />
                  </span>
                ) : null}
                {Object.entries(change.detail ?? {}).map(([key, value]) => (
                  <span key={key} className="mono">
                    {key}={displayValue(value)}
                  </span>
                ))}
              </div>
            </li>
          ))}
        </ul>
      </Section>
      <Section title="Alerts" count={state.alerts.length}>
        <ul className="replay-list">
          {latest(state.alerts).map((alert, index) => (
            <li key={`${alert.at}-${index}`} className="replay-list__item">
              <div className="row row--wrap">
                <SeverityBadge severity={alert.severity} />
                <span className="break">{alert.message}</span>
              </div>
              <div className="small muted row row--wrap">
                <span>{formatTime(alert.at)}</span>
                {alert.target ? <Ref id={alert.target} objects={objects} /> : null}
              </div>
            </li>
          ))}
        </ul>
      </Section>
    </div>
  );
}

/** Ordered step log; the current step is highlighted, future steps are dimmed. */
export function EventLog({
  steps,
  index,
  onSeek,
  height = '100%',
}: {
  steps: readonly ReplayStep[];
  index: number;
  onSeek: (index: number) => void;
  height?: number | string;
}) {
  return (
    <VirtualList
      label="Replay event log"
      items={steps}
      rowHeight={30}
      height={height}
      activeIndex={index >= 0 ? index : null}
      getKey={(step, position) => `${position}:${step.event_id}`}
      renderRow={(step, position) => (
        <button
          type="button"
          className={cx('log-row', position === index && 'is-current', position > index && 'is-future')}
          aria-current={position === index ? 'step' : undefined}
          onClick={() => onSeek(position)}
        >
          <time className="log-row__time tabular" dateTime={step.timestamp} title={step.timestamp}>
            {formatTime(step.timestamp)}
          </time>
          <SeverityBadge severity={step.severity} />
          <span className="log-row__type mono">{step.event_type}</span>
          <span className="log-row__summary truncate">{step.summary}</span>
        </button>
      )}
    />
  );
}
