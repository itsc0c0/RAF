/**
 * R$F Replay delta engine (pure, deterministic).
 *
 * `GET /replay/{ref}` returns an initial state plus ordered steps with deltas. State at step index
 * `i` is the initial state with steps 0..i applied in order (index -1 = before the first step).
 * {@link applyStepInPlace} mirrors `raf.products.replay.service.apply_step` exactly, so the browser
 * reconstructs the same states as the server.
 *
 * Seeking forward continues from the last computed state; seeking backward restarts from the nearest
 * checkpoint at or before the target (or from the initial state). Checkpoints are full copies taken
 * every `interval` steps while moving forward. Correctness over cleverness: a seek never mutates a
 * state that was previously handed out.
 */

import type {
  ReplayAlert,
  ReplayFileActivity,
  ReplayFlow,
  ReplayIdentityChange,
  ReplayProcess,
  ReplaySession,
  ReplayStep,
  ReplayTimeline,
} from '../../api/types';

export interface ReplayState {
  /** Index of the last applied step; -1 is the initial state. */
  readonly index: number;
  readonly objects: ReadonlySet<string>;
  readonly relationships: ReadonlySet<string>;
  /** Open sessions keyed by `user@host`. */
  readonly sessions: ReadonlyMap<string, ReplaySession>;
  /** Running processes keyed by process object ID. */
  readonly processes: ReadonlyMap<string, ReplayProcess>;
  readonly flows: readonly ReplayFlow[];
  readonly files: readonly ReplayFileActivity[];
  readonly identityChanges: readonly ReplayIdentityChange[];
  readonly alerts: readonly ReplayAlert[];
}

interface MutableState {
  index: number;
  objects: Set<string>;
  relationships: Set<string>;
  sessions: Map<string, ReplaySession>;
  processes: Map<string, ReplayProcess>;
  flows: ReplayFlow[];
  files: ReplayFileActivity[];
  identityChanges: ReplayIdentityChange[];
  alerts: ReplayAlert[];
}

export type ReplaySource = Pick<ReplayTimeline, 'initial_objects' | 'initial_relationships' | 'steps'>;

export const sessionKey = (user: string, host: string): string => `${user}@${host}`;

export function initialState(source: ReplaySource): ReplayState {
  return {
    index: -1,
    objects: new Set(source.initial_objects),
    relationships: new Set(source.initial_relationships),
    sessions: new Map(),
    processes: new Map(),
    flows: [],
    files: [],
    identityChanges: [],
    alerts: [],
  };
}

function cloneState(state: ReplayState): MutableState {
  return {
    index: state.index,
    objects: new Set(state.objects),
    relationships: new Set(state.relationships),
    sessions: new Map(state.sessions),
    processes: new Map(state.processes),
    flows: [...state.flows],
    files: [...state.files],
    identityChanges: [...state.identityChanges],
    alerts: [...state.alerts],
  };
}

const list = <T>(value: readonly T[] | null | undefined): readonly T[] => value ?? [];

/** Applies `step` (at `position`) to `state` in place. Same order of operations as the server. */
function applyStepInPlace(state: MutableState, step: ReplayStep, position: number): void {
  for (const id of list(step.added_objects)) state.objects.add(id);
  for (const id of list(step.added_relationships)) state.relationships.add(id);
  for (const id of list(step.removed_relationships)) state.relationships.delete(id);
  for (const session of list(step.sessions_opened))
    state.sessions.set(sessionKey(session.user, session.host), session);
  for (const session of list(step.sessions_closed))
    state.sessions.delete(sessionKey(session.user, session.host));
  for (const process of list(step.processes_started)) state.processes.set(process.process, process);
  for (const id of list(step.processes_ended)) state.processes.delete(id);
  state.flows.push(...list(step.flows));
  state.files.push(...list(step.files));
  state.identityChanges.push(...list(step.identity_changes));
  state.alerts.push(...list(step.alerts));
  state.index = position;
}

/** Pure: a new state with `step` applied (the input state is untouched). */
export function applyStep(state: ReplayState, step: ReplayStep): ReplayState {
  const next = cloneState(state);
  applyStepInPlace(next, step, state.index + 1);
  return next;
}

export function clampIndex(source: ReplaySource, index: number): number {
  if (!Number.isFinite(index)) return -1;
  return Math.max(-1, Math.min(source.steps.length - 1, Math.trunc(index)));
}

/** Pure reference implementation: replays steps 0..index from the initial state. */
export function stateAt(source: ReplaySource, index: number): ReplayState {
  const target = clampIndex(source, index);
  const state = cloneState(initialState(source));
  for (let i = 0; i <= target; i += 1) applyStepInPlace(state, source.steps[i]!, i);
  return state;
}

/** Seekable engine with forward continuation and checkpointed backward seeks. */
export class ReplayEngine {
  private readonly checkpoints = new Map<number, ReplayState>();
  private last: ReplayState;

  constructor(
    private readonly source: ReplaySource,
    private readonly interval = 32,
  ) {
    this.last = initialState(source);
    this.checkpoints.set(-1, this.last);
  }

  get length(): number {
    return this.source.steps.length;
  }

  get checkpointCount(): number {
    return this.checkpoints.size;
  }

  private nearestCheckpoint(target: number): ReplayState {
    let best = this.checkpoints.get(-1)!;
    for (const [index, state] of this.checkpoints) {
      if (index <= target && index > best.index) best = state;
    }
    return best;
  }

  seek(index: number): ReplayState {
    const target = clampIndex(this.source, index);
    if (target === this.last.index) return this.last;
    let base = this.nearestCheckpoint(target);
    if (this.last.index <= target && this.last.index > base.index) base = this.last;
    const state = cloneState(base);
    for (let i = base.index + 1; i <= target; i += 1) {
      applyStepInPlace(state, this.source.steps[i]!, i);
      if ((i + 1) % this.interval === 0 && !this.checkpoints.has(i))
        this.checkpoints.set(i, cloneState(state));
    }
    this.last = state;
    return state;
  }
}

/** Order-independent, JSON-friendly form of a state (equality checks, debugging). */
export function canonicalState(state: ReplayState) {
  const sortedValues = <T>(map: ReadonlyMap<string, T>) =>
    [...map.keys()].sort().map((key) => [key, map.get(key)] as const);
  return {
    index: state.index,
    objects: [...state.objects].sort(),
    relationships: [...state.relationships].sort(),
    sessions: sortedValues(state.sessions),
    processes: sortedValues(state.processes),
    flows: [...state.flows],
    files: [...state.files],
    identityChanges: [...state.identityChanges],
    alerts: [...state.alerts],
  };
}

// ------------------------------------------------------------------ time helpers

export function stepTime(step: Pick<ReplayStep, 'timestamp'>): number {
  return Date.parse(step.timestamp);
}

/** Incident time at `index` (the replay start before the first step). */
export function timeAtIndex(timeline: Pick<ReplayTimeline, 'start' | 'steps'>, index: number): number {
  const step = index >= 0 ? timeline.steps[index] : undefined;
  return step ? stepTime(step) : Date.parse(timeline.start);
}

/** Last step index whose timestamp is <= `time` (binary search; steps are time ordered). */
export function indexAtTime(steps: ReadonlyArray<Pick<ReplayStep, 'timestamp'>>, time: number): number {
  let lo = 0;
  let hi = steps.length - 1;
  let found = -1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (stepTime(steps[mid]!) <= time) {
      found = mid;
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }
  return found;
}

export const FLOW_WINDOW_MS = 10 * 60_000;

/** Flows observed within the 10 minutes before `time` (same window as the server's state API). */
export function recentFlows(state: ReplayState, time: number, windowMs = FLOW_WINDOW_MS): ReplayFlow[] {
  return state.flows.filter((flow) => {
    const at = Date.parse(flow.at);
    return !Number.isNaN(at) && at >= time - windowMs && at <= time;
  });
}

export const SPEEDS = [0.25, 0.5, 1, 2, 5, 10] as const;
export type Speed = (typeof SPEEDS)[number];
export const MAX_STEP_DELAY_MS = 2000;
export const MIN_STEP_DELAY_MS = 40;

/**
 * Compressed playback: at 1x one minute of incident time plays in one second. Each step's delay is
 * capped at 2 s so quiet periods never stall the replay.
 */
export function playbackDelayMs(fromMs: number, toMs: number, speed: number): number {
  const gap = Math.max(0, toMs - fromMs);
  const scaled = gap / 60 / Math.max(speed, 0.01);
  return Math.round(Math.min(MAX_STEP_DELAY_MS, Math.max(MIN_STEP_DELAY_MS, scaled)));
}

export interface SeverityMarker {
  index: number;
  time: number;
  severity: string;
}

/** HIGH and CRITICAL steps, shown as markers on the scrubber. */
export function severityMarkers(steps: readonly ReplayStep[]): SeverityMarker[] {
  return steps
    .map((step, index) => ({ index, time: stepTime(step), severity: String(step.severity).toUpperCase() }))
    .filter((marker) => marker.severity === 'HIGH' || marker.severity === 'CRITICAL');
}

// ------------------------------------------------------------------ graph view of a state

/**
 * Objects and relationships that are visible at some point of the replay (initial state or added by
 * a step, plus relationship endpoints). The state graph lays out only these, so indexed objects that
 * never appear do not distort the layout.
 */
export function everVisible(
  timeline: Pick<ReplayTimeline, 'relationships' | 'initial_objects' | 'initial_relationships' | 'steps'>,
): {
  objects: Set<string>;
  relationships: Set<string>;
} {
  const objects = new Set(timeline.initial_objects);
  const relationships = new Set(timeline.initial_relationships);
  for (const step of timeline.steps) {
    for (const id of step.added_objects ?? []) objects.add(id);
    for (const id of step.added_relationships ?? []) relationships.add(id);
  }
  for (const id of relationships) {
    const rel = timeline.relationships[id];
    if (rel) {
      objects.add(rel.source);
      objects.add(rel.target);
    }
  }
  return { objects, relationships };
}

export type ElementStatus = 'present' | 'added' | 'removed' | 'absent';

/**
 * Status of every object/relationship of the timeline at `state`: present, newly added by the
 * current step, removed by the current step (still drawn, fading out) or absent.
 */
export function elementStatuses(
  timeline: Pick<ReplayTimeline, 'objects' | 'relationships' | 'steps'>,
  state: ReplayState,
): Map<string, ElementStatus> {
  const result = new Map<string, ElementStatus>();
  const step = state.index >= 0 ? timeline.steps[state.index] : undefined;
  const addedObjects = new Set(step?.added_objects ?? []);
  const addedRelationships = new Set(step?.added_relationships ?? []);
  const removedRelationships = new Set(step?.removed_relationships ?? []);
  const visibleNodes = new Set(state.objects);
  for (const id of state.relationships) {
    const rel = timeline.relationships[id];
    if (rel) {
      visibleNodes.add(rel.source);
      visibleNodes.add(rel.target);
    }
  }
  for (const id of removedRelationships) {
    const rel = timeline.relationships[id];
    if (rel) {
      visibleNodes.add(rel.source);
      visibleNodes.add(rel.target);
    }
  }
  for (const id of Object.keys(timeline.objects)) {
    if (!visibleNodes.has(id)) result.set(id, 'absent');
    else result.set(id, addedObjects.has(id) ? 'added' : 'present');
  }
  for (const id of Object.keys(timeline.relationships)) {
    if (removedRelationships.has(id) && !state.relationships.has(id)) result.set(id, 'removed');
    else if (!state.relationships.has(id)) result.set(id, 'absent');
    else result.set(id, addedRelationships.has(id) ? 'added' : 'present');
  }
  return result;
}
