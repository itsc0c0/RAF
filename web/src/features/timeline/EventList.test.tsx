import { fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { RafEvent } from '../../api/types';
import { EVENT_ROW_HEIGHT, EventList } from './EventList';

function makeEvents(count: number): RafEvent[] {
  const base = Date.parse('2026-10-06T00:00:00Z');
  return Array.from({ length: count }, (_, index) => ({
    id: `event:${index}`,
    timestamp: new Date(base + index * 1000).toISOString(),
    event_type: 'auth.login',
    category: 'auth',
    action: 'login',
    outcome: 'success',
    actor: `user:u${index}`,
    target: 'host:ws-01',
    objects: [],
    source: 'test',
    parser: 'test/1.0',
    record: `line ${index}`,
    raw_reference: null,
    raw: null,
    severity: index % 5 === 0 ? 'HIGH' : 'INFO',
    confidence: 0.8,
    attributes: {},
    relationships: [],
    message: `message number ${index}`,
    synthetic: true,
    incidents: [],
  }));
}

const VIEWPORT = 400;
let restore: Array<() => void> = [];

function stubLayout(property: 'offsetHeight' | 'offsetWidth', value: number) {
  const original = Object.getOwnPropertyDescriptor(HTMLElement.prototype, property);
  Object.defineProperty(HTMLElement.prototype, property, { configurable: true, get: () => value });
  restore.push(() => {
    if (original) Object.defineProperty(HTMLElement.prototype, property, original);
  });
}

describe('timeline event list (virtualized)', () => {
  beforeEach(() => {
    restore = [];
    stubLayout('offsetHeight', VIEWPORT);
    stubLayout('offsetWidth', 900);
  });

  afterEach(() => {
    restore.forEach((undo) => undo());
  });

  it('renders only a window of rows for 5000 events', () => {
    const events = makeEvents(5000);
    render(
      <EventList events={events} names={{}} selectedId={null} onSelect={() => undefined} height={VIEWPORT} />,
    );
    const rows = screen.getAllByRole('listitem');
    const visible = Math.ceil(VIEWPORT / EVENT_ROW_HEIGHT);
    expect(rows.length).toBeGreaterThanOrEqual(visible);
    expect(rows.length).toBeLessThan(60);
    expect(screen.getByText('message number 0')).toBeInTheDocument();
    expect(screen.queryByText('message number 4999')).not.toBeInTheDocument();

    // The scroll height still represents every row.
    const list = screen.getByRole('list', { name: 'Events' });
    const inner = list.firstElementChild as HTMLElement;
    expect(inner.style.height).toBe(`${5000 * EVENT_ROW_HEIGHT}px`);
  });

  it('moves the window when scrolling and asks for the next page near the end', () => {
    const events = makeEvents(5000);
    const onEndReached = vi.fn();
    render(
      <EventList
        events={events}
        names={{}}
        selectedId={null}
        onSelect={() => undefined}
        onEndReached={onEndReached}
        height={VIEWPORT}
      />,
    );
    expect(onEndReached).not.toHaveBeenCalled();
    const list = screen.getByRole('list', { name: 'Events' });

    list.scrollTop = 2500 * EVENT_ROW_HEIGHT;
    fireEvent.scroll(list);
    expect(screen.getByText('message number 2500')).toBeInTheDocument();
    expect(screen.queryByText('message number 0')).not.toBeInTheDocument();
    expect(screen.getAllByRole('listitem').length).toBeLessThan(60);

    list.scrollTop = 4990 * EVENT_ROW_HEIGHT;
    fireEvent.scroll(list);
    expect(screen.getByText('message number 4999')).toBeInTheDocument();
    expect(onEndReached).toHaveBeenCalled();
  });

  it('reports the clicked event', () => {
    const events = makeEvents(50);
    const onSelect = vi.fn();
    render(
      <EventList
        events={events}
        names={{ 'user:u3': 'Alice <admin>' }}
        selectedId="event:2"
        onSelect={onSelect}
        height={VIEWPORT}
      />,
    );
    fireEvent.click(screen.getByText('message number 3'));
    expect(onSelect).toHaveBeenCalledWith(events[3]);
    expect(screen.getByText('message number 2').closest('button')).toHaveAttribute('aria-pressed', 'true');
  });
});
