import { useEffect, useState } from 'react';

/**
 * Measures an element's content width with ResizeObserver (callback-ref pattern). Falls back to
 * `fallback` where ResizeObserver or layout is unavailable (tests, very old browsers).
 */
export function useElementWidth<T extends Element>(fallback: number) {
  const [node, setNode] = useState<T | null>(null);
  const [width, setWidth] = useState(fallback);
  useEffect(() => {
    if (!node || typeof ResizeObserver === 'undefined') return undefined;
    const observer = new ResizeObserver((entries) => {
      const measured = entries[0]?.contentRect.width;
      if (measured && measured > 0) setWidth(Math.round(measured));
    });
    observer.observe(node);
    return () => observer.disconnect();
  }, [node]);
  return [setNode, width] as const;
}
