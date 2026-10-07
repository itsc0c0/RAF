import { useCallback, useEffect, useMemo, useState } from 'react';
import type { ReplayTimeline } from '../../api/types';
import { playbackDelayMs, ReplayEngine, timeAtIndex, type ReplayState, type Speed } from './engine';

export interface Playback {
  index: number;
  state: ReplayState | null;
  time: number;
  playing: boolean;
  speed: Speed;
  setSpeed: (speed: Speed) => void;
  play: () => void;
  pause: () => void;
  stepForward: () => void;
  stepBack: () => void;
  seek: (index: number) => void;
}

/**
 * Replay cursor + compressed-time playback. The engine is rebuilt per timeline; state at the cursor
 * comes from the pure delta engine (seeking backward recomputes from the nearest checkpoint).
 */
export function usePlayback(timeline: ReplayTimeline | undefined): Playback {
  const [index, setIndex] = useState(-1);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState<Speed>(1);
  const length = timeline?.steps.length ?? 0;

  const engine = useMemo(() => (timeline ? new ReplayEngine(timeline) : null), [timeline]);
  const cursor = Math.max(-1, Math.min(index, length - 1));
  const state = useMemo(() => (engine ? engine.seek(cursor) : null), [engine, cursor]);
  const time = timeline ? timeAtIndex(timeline, cursor) : 0;

  useEffect(() => {
    if (!playing || !timeline || cursor >= length - 1) return undefined;
    const delay = playbackDelayMs(timeAtIndex(timeline, cursor), timeAtIndex(timeline, cursor + 1), speed);
    const timer = window.setTimeout(() => {
      const next = cursor + 1;
      setIndex(next);
      if (next >= length - 1) setPlaying(false);
    }, delay);
    return () => window.clearTimeout(timer);
  }, [playing, timeline, cursor, length, speed]);

  const play = useCallback(() => {
    if (length === 0) return;
    if (cursor >= length - 1) setIndex(-1);
    setPlaying(true);
  }, [cursor, length]);

  const pause = useCallback(() => setPlaying(false), []);

  const stepForward = useCallback(() => {
    setPlaying(false);
    setIndex(Math.min(length - 1, cursor + 1));
  }, [cursor, length]);

  const stepBack = useCallback(() => {
    setPlaying(false);
    setIndex(Math.max(-1, cursor - 1));
  }, [cursor]);

  const seek = useCallback(
    (target: number) => {
      setIndex(Math.max(-1, Math.min(length - 1, Math.trunc(target))));
    },
    [length],
  );

  return { index: cursor, state, time, playing, speed, setSpeed, play, pause, stepForward, stepBack, seek };
}
