import { useMemo, useState, type KeyboardEvent, type PointerEvent } from 'react';
import { cx } from '../lib/cx';
import { formatNumber, formatTime, formatTimestamp } from '../lib/format';
import { useElementWidth } from '../lib/useElementWidth';
import { brushRange, domainOf, pixelAtTime, toBuckets, type Bucket, type TimeRange } from './histogramMath';

const AXIS_HEIGHT = 20;
const TOP_PAD = 16;

function roundedTopBar(x: number, y: number, width: number, height: number, radius: number): string {
  const r = Math.max(0, Math.min(radius, width / 2, height));
  const base = y + height;
  return [
    `M${x},${base}`,
    `V${y + r}`,
    `Q${x},${y} ${x + r},${y}`,
    `H${x + width - r}`,
    `Q${x + width},${y} ${x + width},${y + r}`,
    `V${base}`,
    'Z',
  ].join(' ');
}

function describeBucket(bucket: Bucket, unit: string): string {
  const sameDay = formatTimestamp(bucket.start).slice(0, 10) === formatTimestamp(bucket.end).slice(0, 10);
  const range = sameDay
    ? `${formatTimestamp(bucket.start)} – ${formatTime(bucket.end)}`
    : `${formatTimestamp(bucket.start)} – ${formatTimestamp(bucket.end)}`;
  return `${formatNumber(bucket.count)} ${unit} · ${range}`;
}

/**
 * Event-count histogram over time (single series, so no legend) with a brush: drag across bars to
 * select a time window, or focus the chart and use ←/→ and Enter. Escape clears the selection.
 */
export function Histogram({
  buckets: raw,
  selection,
  onBrush,
  height = 104,
  label,
  unit = 'events',
}: {
  buckets: ReadonlyArray<{ start: string; count: number }>;
  selection?: TimeRange | null;
  onBrush?: (range: TimeRange | null) => void;
  height?: number;
  label: string;
  unit?: string;
}) {
  const buckets = useMemo(() => toBuckets(raw), [raw]);
  const [setNode, width] = useElementWidth<HTMLDivElement>(640);
  const [drag, setDrag] = useState<{ x0: number; x1: number } | null>(null);
  const [active, setActive] = useState<number | null>(null);
  const domain = domainOf(buckets);

  if (!domain || buckets.length === 0) {
    return <p className="muted small">No events to chart.</p>;
  }

  const plotHeight = height - AXIS_HEIGHT;
  const max = Math.max(1, ...buckets.map((bucket) => bucket.count));
  const band = width / buckets.length;
  const barWidth = Math.max(1, Math.min(24, band - 2));
  const activeBucket = active !== null ? buckets[active] : undefined;

  const localX = (event: PointerEvent<SVGSVGElement>) =>
    event.clientX - event.currentTarget.getBoundingClientRect().left;

  const onPointerDown = (event: PointerEvent<SVGSVGElement>) => {
    if (!onBrush || event.button !== 0) return;
    const x = localX(event);
    event.currentTarget.setPointerCapture?.(event.pointerId);
    setDrag({ x0: x, x1: x });
  };
  const onPointerMove = (event: PointerEvent<SVGSVGElement>) => {
    const x = localX(event);
    if (drag) setDrag({ x0: drag.x0, x1: x });
    const index = Math.floor(x / band);
    setActive(index >= 0 && index < buckets.length ? index : null);
  };
  const onPointerUp = (event: PointerEvent<SVGSVGElement>) => {
    if (!drag || !onBrush) return;
    const range = brushRange(drag.x0, localX(event), width, buckets);
    setDrag(null);
    if (range) onBrush(range);
  };

  const onKeyDown = (event: KeyboardEvent<SVGSVGElement>) => {
    if (event.key === 'ArrowRight' || event.key === 'ArrowLeft') {
      event.preventDefault();
      const delta = event.key === 'ArrowRight' ? 1 : -1;
      const start = active ?? (delta > 0 ? -1 : buckets.length);
      setActive(Math.max(0, Math.min(buckets.length - 1, start + delta)));
    } else if (event.key === 'Enter' && activeBucket && onBrush) {
      event.preventDefault();
      onBrush({ start: activeBucket.start, end: activeBucket.end });
    } else if (event.key === 'Escape' && selection && onBrush) {
      event.preventDefault();
      onBrush(null);
    }
  };

  const selectionPx = selection
    ? { x0: pixelAtTime(selection.start, width, domain), x1: pixelAtTime(selection.end, width, domain) }
    : null;

  return (
    <figure className="hist" aria-label={label}>
      <div className="hist__plot" ref={setNode}>
        <svg
          width={width}
          height={height}
          className={cx('hist__svg', onBrush && 'is-brushable')}
          role="img"
          aria-label={`${label}. ${onBrush ? 'Drag across bars, or use arrow keys and Enter, to select a time window.' : ''}`}
          tabIndex={0}
          onPointerDown={onPointerDown}
          onPointerMove={onPointerMove}
          onPointerUp={onPointerUp}
          onPointerLeave={() => {
            if (!drag) setActive(null);
          }}
          onKeyDown={onKeyDown}
        >
          {selectionPx ? (
            <rect
              className="hist__selection"
              x={selectionPx.x0}
              y={0}
              width={Math.max(2, selectionPx.x1 - selectionPx.x0)}
              height={plotHeight}
            />
          ) : null}
          {buckets.map((bucket, index) => {
            if (bucket.count === 0) return null;
            const barHeight = Math.max(2, (bucket.count / max) * (plotHeight - TOP_PAD));
            const x = index * band + (band - barWidth) / 2;
            return (
              <path
                key={bucket.start}
                d={roundedTopBar(x, plotHeight - barHeight, barWidth, barHeight, 4)}
                className={cx('hist__bar', index === active && 'is-active')}
              />
            );
          })}
          {drag ? (
            <rect
              className="hist__drag"
              x={Math.min(drag.x0, drag.x1)}
              y={0}
              width={Math.abs(drag.x1 - drag.x0)}
              height={plotHeight}
            />
          ) : null}
          <line className="hist__baseline" x1={0} x2={width} y1={plotHeight + 0.5} y2={plotHeight + 0.5} />
          <text className="hist__tick" x={0} y={height - 5} textAnchor="start">
            {formatTimestamp(domain.start)}
          </text>
          <text className="hist__tick" x={width} y={height - 5} textAnchor="end">
            {formatTimestamp(domain.end)}
          </text>
          <text className="hist__tick" x={2} y={11} textAnchor="start">
            max {formatNumber(max)}
          </text>
        </svg>
        {activeBucket && active !== null ? (
          <div
            className="hist__tooltip"
            style={{ left: Math.min(Math.max(active * band + band / 2, 90), width - 90) }}
            aria-hidden="true"
          >
            <strong className="tabular">{formatNumber(activeBucket.count)}</strong> {unit}
            <span className="hist__tooltip-range">{describeBucket(activeBucket, unit).split(' · ')[1]}</span>
          </div>
        ) : null}
      </div>
      <p className="sr-only" aria-live="polite">
        {activeBucket ? describeBucket(activeBucket, unit) : ''}
      </p>
    </figure>
  );
}
