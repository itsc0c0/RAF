import type { RafEvent } from '../../api/types';
import { SeverityBadge } from '../../components/Badge';
import { VirtualList } from '../../components/VirtualList';
import { cx } from '../../lib/cx';
import { formatTimestamp, objectKeyOf } from '../../lib/format';

export const EVENT_ROW_HEIGHT = 34;

function name(id: string | null, names: Record<string, string>): string {
  if (!id) return '—';
  return names[id] ?? objectKeyOf(id);
}

/** Summary line for an event row (all values are text). */
export function eventSummary(event: RafEvent, names: Record<string, string>): string {
  if (event.message) return event.message;
  const actor = name(event.actor, names);
  const target = name(event.target, names);
  return `${actor} → ${target}${event.outcome ? ` (${event.outcome})` : ''}`;
}

/** Virtualized event table: only visible rows are rendered (tens of thousands stay smooth). */
export function EventList({
  events,
  names,
  selectedId,
  onSelect,
  onEndReached,
  height,
}: {
  events: readonly RafEvent[];
  names: Record<string, string>;
  selectedId: string | null;
  onSelect: (event: RafEvent) => void;
  onEndReached?: () => void;
  height: number | string;
}) {
  return (
    <div className="event-table" role="region" aria-label="Events">
      <div className="event-row event-row--head" aria-hidden="true">
        <span>Time (UTC)</span>
        <span>Severity</span>
        <span>Type</span>
        <span>Summary</span>
      </div>
      <VirtualList
        label="Events"
        items={events}
        rowHeight={EVENT_ROW_HEIGHT}
        height={height}
        getKey={(event) => event.id}
        onEndReached={onEndReached}
        renderRow={(event) => (
          <button
            type="button"
            className={cx('event-row', event.id === selectedId && 'is-selected')}
            aria-pressed={event.id === selectedId}
            onClick={() => onSelect(event)}
          >
            <span className="event-row__time tabular">{formatTimestamp(event.timestamp)}</span>
            <span>
              <SeverityBadge severity={event.severity} />
            </span>
            <span className="event-row__type mono truncate">{event.event_type}</span>
            <span className="event-row__summary truncate">{eventSummary(event, names)}</span>
          </button>
        )}
      />
    </div>
  );
}
