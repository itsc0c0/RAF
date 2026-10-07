import { useId } from 'react';
import type { ReplayStep } from '../../api/types';
import { cx } from '../../lib/cx';
import { formatTime, formatTimestamp } from '../../lib/format';
import type { SeverityMarker } from './engine';

function label(ms: number, longSpan: boolean): string {
  return longSpan ? formatTimestamp(ms) : formatTime(ms);
}

/**
 * Time scrubber: `22:40:00 ───●─── 23:45:00`. The range input carries keyboard access
 * (←/→ move one second, PageUp/PageDown larger jumps); HIGH/CRITICAL steps are markers that jump to
 * that step.
 */
export function Scrubber({
  start,
  end,
  time,
  markers,
  steps,
  index,
  onSeekTime,
  onSeekIndex,
}: {
  start: number;
  end: number;
  time: number;
  markers: readonly SeverityMarker[];
  steps: readonly ReplayStep[];
  index: number;
  onSeekTime: (time: number) => void;
  onSeekIndex: (index: number) => void;
}) {
  const id = useId();
  const span = Math.max(1, end - start);
  const longSpan = span > 24 * 3600_000;
  const position = (t: number) => `${Math.max(0, Math.min(100, ((t - start) / span) * 100))}%`;
  const current = index >= 0 ? steps[index] : undefined;
  return (
    <div className="scrubber">
      <span className="scrubber__label tabular">{label(start, longSpan)}</span>
      <div className="scrubber__track-wrap">
        <div className="scrubber__track" aria-hidden="true">
          <div className="scrubber__progress" style={{ width: position(time) }} />
        </div>
        <label htmlFor={id} className="sr-only">
          Replay time
        </label>
        <input
          id={id}
          className="scrubber__input"
          type="range"
          min={start}
          max={end}
          step={1000}
          value={Math.max(start, Math.min(end, time))}
          aria-valuetext={`${formatTimestamp(time)}${current ? `, step ${index + 1} of ${steps.length}: ${current.summary}` : ', before the first event'}`}
          onChange={(event) => onSeekTime(Number(event.target.value))}
        />
        <div className="scrubber__thumb-label tabular" style={{ left: position(time) }} aria-hidden="true">
          {label(time, longSpan)}
        </div>
        {markers.map((marker) => (
          <button
            key={marker.index}
            type="button"
            className={cx(
              'scrubber__marker',
              `scrubber__marker--${marker.severity.toLowerCase()}`,
              marker.index === index && 'is-current',
            )}
            style={{ left: position(marker.time) }}
            aria-label={`${marker.severity} at ${formatTimestamp(marker.time)}: ${steps[marker.index]?.summary ?? ''}`}
            title={`${marker.severity} · ${formatTime(marker.time)} · ${steps[marker.index]?.summary ?? ''}`}
            onClick={() => onSeekIndex(marker.index)}
          />
        ))}
      </div>
      <span className="scrubber__label tabular">{label(end, longSpan)}</span>
    </div>
  );
}
