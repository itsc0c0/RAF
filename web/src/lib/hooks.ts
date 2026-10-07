import { useEffect, useRef, useState } from 'react';

/** Returns `value` after it has been stable for `delay` ms (search boxes, live filters). */
export function useDebouncedValue<T>(value: T, delay: number): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = window.setTimeout(() => setDebounced(value), delay);
    return () => window.clearTimeout(timer);
  }, [value, delay]);
  return debounced;
}

/** Current time, refreshed every `intervalMs` (relative ages such as "3m ago"). */
export function useNow(intervalMs = 30_000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), intervalMs);
    return () => window.clearInterval(timer);
  }, [intervalMs]);
  return now;
}

/** Keeps a ref pointing at the latest value without re-subscribing listeners. */
export function useLatest<T>(value: T) {
  const ref = useRef(value);
  useEffect(() => {
    ref.current = value;
  });
  return ref;
}

export function isEditableTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  if (target.isContentEditable) return true;
  const tag = target.tagName;
  return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT';
}

/** Global keydown listener (document level) that always calls the latest handler. */
export function useDocumentKeydown(handler: (event: KeyboardEvent) => void, enabled = true): void {
  const latest = useLatest(handler);
  useEffect(() => {
    if (!enabled) return undefined;
    const listener = (event: KeyboardEvent) => latest.current(event);
    document.addEventListener('keydown', listener);
    return () => document.removeEventListener('keydown', listener);
  }, [enabled, latest]);
}
