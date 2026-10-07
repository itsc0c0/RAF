import { describe, expect, it } from 'vitest';
import type { ReplayStep, ReplayTimeline } from '../../api/types';
import {
  applyStep,
  canonicalState,
  elementStatuses,
  everVisible,
  indexAtTime,
  initialState,
  MAX_STEP_DELAY_MS,
  playbackDelayMs,
  recentFlows,
  ReplayEngine,
  sessionKey,
  severityMarkers,
  stateAt,
} from './engine';

function step(index: number, time: string, delta: Partial<ReplayStep> = {}): ReplayStep {
  return {
    index,
    timestamp: `2026-10-06T${time}Z`,
    event_id: `event:${index}`,
    event_type: 'log.message',
    severity: 'INFO',
    summary: `step ${index}`,
    actor: null,
    target: null,
    added_objects: [],
    added_relationships: [],
    removed_relationships: [],
    sessions_opened: [],
    sessions_closed: [],
    processes_started: [],
    processes_ended: [],
    flows: [],
    files: [],
    identity_changes: [],
    alerts: [],
    ...delta,
  };
}

const BOB_VPN = { user: 'user:bob', host: 'host:vpn-01' };

/** Shaped after INC-001: login, process, exfil flow, logout, group removal, alert. */
const TIMELINE: ReplayTimeline = {
  scope: { kind: 'incident', id: 'incident:inc-001', label: 'INC-001' },
  title: 'INC-001',
  start: '2026-10-06T22:40:00Z',
  end: '2026-10-06T23:45:00Z',
  objects: {
    'user:bob': { name: 'bob', type: 'user', criticality: null },
    'host:vpn-01': { name: 'VPN-01', type: 'host', criticality: 'high' },
    'group:deployers': { name: 'deployers', type: 'group', criticality: null },
    'ip:203.0.113.45': { name: '203.0.113.45', type: 'ip', criticality: null },
    'process:p1': { name: 'curl', type: 'process', criticality: null },
    'ip:198.51.100.23': { name: '198.51.100.23', type: 'ip', criticality: null },
  },
  relationships: {
    'rel:member': { type: 'MEMBER_OF', source: 'user:bob', target: 'group:deployers' },
    'rel:login': { type: 'LOGGED_INTO', source: 'user:bob', target: 'host:vpn-01' },
    'rel:runs': { type: 'RUNS', source: 'host:vpn-01', target: 'process:p1' },
    'rel:conn': { type: 'CONNECTED_TO', source: 'process:p1', target: 'ip:198.51.100.23' },
  },
  initial_objects: ['group:deployers', 'user:bob'],
  initial_relationships: ['rel:member'],
  steps: [
    step(0, '22:47:00', { event_type: 'auth.failure', severity: 'LOW', added_objects: ['ip:203.0.113.45'] }),
    step(1, '22:52:11', {
      event_type: 'auth.login',
      severity: 'MEDIUM',
      added_objects: ['host:vpn-01'],
      added_relationships: ['rel:login'],
      sessions_opened: [
        { ...BOB_VPN, since: '2026-10-06T22:52:11Z', source: 'ip:203.0.113.45', method: 'password' },
      ],
    }),
    step(2, '22:59:12', {
      event_type: 'process.start',
      added_objects: ['process:p1'],
      added_relationships: ['rel:runs'],
      processes_started: [
        { process: 'process:p1', host: 'host:vpn-01', user: 'user:bob', since: '2026-10-06T22:59:12Z' },
      ],
      files: [{ at: '2026-10-06T22:59:12Z', operation: 'read', file: 'file:.env', actor: 'process:p1' }],
    }),
    step(3, '23:16:30', {
      event_type: 'network.connection',
      severity: 'HIGH',
      added_objects: ['ip:198.51.100.23'],
      added_relationships: ['rel:conn'],
      flows: [
        {
          at: '2026-10-06T23:16:30Z',
          source: 'process:p1',
          destination: 'ip:198.51.100.23',
          port: 443,
          bytes_out: 48213000,
          protocol: 'tcp',
        },
      ],
    }),
    step(4, '23:20:00', {
      event_type: 'alert',
      severity: 'CRITICAL',
      alerts: [
        { at: '2026-10-06T23:20:00Z', severity: 'CRITICAL', message: 'Exfiltration', target: 'host:vpn-01' },
      ],
    }),
    step(5, '23:25:12', {
      event_type: 'auth.logout',
      sessions_closed: [BOB_VPN],
      processes_ended: ['process:p1'],
    }),
    step(6, '23:27:00', {
      event_type: 'iam.group.remove',
      removed_relationships: ['rel:member'],
      identity_changes: [
        {
          at: '2026-10-06T23:27:00Z',
          change: 'iam.group.remove',
          actor: 'identity:admin',
          target: 'user:bob',
          detail: { group: 'deployers' },
        },
      ],
    }),
    // Re-opening a session after it closed (same key) must work in both directions.
    step(7, '23:30:00', {
      event_type: 'auth.login',
      sessions_opened: [{ ...BOB_VPN, since: '2026-10-06T23:30:00Z' }],
    }),
  ],
  checkpoints: [],
  final_state_hash: 'n/a',
  notes: [],
};

const LAST = TIMELINE.steps.length - 1;

describe('replay engine', () => {
  it('starts from the initial objects and relationships', () => {
    const state = initialState(TIMELINE);
    expect(state.index).toBe(-1);
    expect([...state.objects].sort()).toEqual(['group:deployers', 'user:bob']);
    expect([...state.relationships]).toEqual(['rel:member']);
    expect(state.sessions.size).toBe(0);
  });

  it('seeking forward to N then backward to M equals applying steps 0..M directly', () => {
    for (const interval of [1, 2, 3, 32]) {
      for (let n = -1; n <= LAST; n += 1) {
        for (let m = -1; m <= n; m += 1) {
          const engine = new ReplayEngine(TIMELINE, interval);
          engine.seek(n);
          expect(canonicalState(engine.seek(m))).toEqual(canonicalState(stateAt(TIMELINE, m)));
        }
      }
    }
  });

  it('is deterministic over arbitrary seek sequences (checkpoints included)', () => {
    const engine = new ReplayEngine(TIMELINE, 2);
    const sequence = [5, 1, 7, 7, -1, 3, 6, 2, 0, 4, 7, 1, -5, 99];
    for (const target of sequence) {
      const expected = stateAt(TIMELINE, target);
      expect(canonicalState(engine.seek(target))).toEqual(canonicalState(expected));
    }
    expect(engine.checkpointCount).toBeGreaterThan(1);
  });

  it('never mutates a state it already handed out', () => {
    const engine = new ReplayEngine(TIMELINE, 2);
    const early = engine.seek(1);
    const snapshot = JSON.stringify(canonicalState(early));
    engine.seek(LAST);
    engine.seek(0);
    engine.seek(4);
    expect(JSON.stringify(canonicalState(early))).toBe(snapshot);
  });

  it('removes relationships at the step that removes them', () => {
    expect(stateAt(TIMELINE, 5).relationships.has('rel:member')).toBe(true);
    expect(stateAt(TIMELINE, 6).relationships.has('rel:member')).toBe(false);
    const engine = new ReplayEngine(TIMELINE);
    expect(engine.seek(LAST).relationships.has('rel:member')).toBe(false);
    expect(engine.seek(2).relationships.has('rel:member')).toBe(true);
  });

  it('opens and closes sessions and processes, forward and backward', () => {
    const key = sessionKey(BOB_VPN.user, BOB_VPN.host);
    const engine = new ReplayEngine(TIMELINE, 3);
    expect(engine.seek(0).sessions.has(key)).toBe(false);
    expect(engine.seek(1).sessions.get(key)?.method).toBe('password');
    expect(engine.seek(2).processes.has('process:p1')).toBe(true);
    const closed = engine.seek(5);
    expect(closed.sessions.has(key)).toBe(false);
    expect(closed.processes.has('process:p1')).toBe(false);
    expect(engine.seek(7).sessions.get(key)?.since).toBe('2026-10-06T23:30:00Z');
    expect(engine.seek(3).sessions.get(key)?.since).toBe('2026-10-06T22:52:11Z');
    expect(engine.seek(3).processes.get('process:p1')?.host).toBe('host:vpn-01');
  });

  it('accumulates flows, files, identity changes and alerts in order', () => {
    const final = stateAt(TIMELINE, LAST);
    expect(final.flows).toHaveLength(1);
    expect(final.files.map((file) => file.operation)).toEqual(['read']);
    expect(final.identityChanges[0]?.detail).toEqual({ group: 'deployers' });
    expect(final.alerts[0]?.message).toBe('Exfiltration');
    expect(stateAt(TIMELINE, 3).alerts).toHaveLength(0);
  });

  it('applyStep is pure', () => {
    const start = initialState(TIMELINE);
    const next = applyStep(start, TIMELINE.steps[0]!);
    expect(next.index).toBe(0);
    expect(next.objects.has('ip:203.0.113.45')).toBe(true);
    expect(start.objects.has('ip:203.0.113.45')).toBe(false);
  });

  it('clamps out-of-range seeks', () => {
    const engine = new ReplayEngine(TIMELINE);
    expect(engine.seek(1000).index).toBe(LAST);
    expect(engine.seek(-50).index).toBe(-1);
    expect(engine.seek(Number.NaN).index).toBe(-1);
  });

  it('maps times to step indices', () => {
    expect(indexAtTime(TIMELINE.steps, Date.parse('2026-10-06T22:40:00Z'))).toBe(-1);
    expect(indexAtTime(TIMELINE.steps, Date.parse('2026-10-06T22:47:00Z'))).toBe(0);
    expect(indexAtTime(TIMELINE.steps, Date.parse('2026-10-06T23:00:00Z'))).toBe(2);
    expect(indexAtTime(TIMELINE.steps, Date.parse('2026-10-07T00:00:00Z'))).toBe(LAST);
  });

  it('plays compressed time: one minute per second at 1x, capped at 2 s per step', () => {
    const t0 = Date.parse('2026-10-06T22:00:00Z');
    expect(playbackDelayMs(t0, t0 + 60_000, 1)).toBe(1000);
    expect(playbackDelayMs(t0, t0 + 60_000, 2)).toBe(500);
    expect(playbackDelayMs(t0, t0 + 60_000, 0.25)).toBe(MAX_STEP_DELAY_MS);
    expect(playbackDelayMs(t0, t0 + 3_600_000, 10)).toBe(MAX_STEP_DELAY_MS);
    expect(playbackDelayMs(t0, t0, 1)).toBeGreaterThan(0);
  });

  it('marks HIGH and CRITICAL steps for the scrubber', () => {
    expect(severityMarkers(TIMELINE.steps).map((marker) => [marker.index, marker.severity])).toEqual([
      [3, 'HIGH'],
      [4, 'CRITICAL'],
    ]);
  });

  it('keeps only flows from the last 10 minutes as recent', () => {
    const state = stateAt(TIMELINE, 3);
    expect(recentFlows(state, Date.parse('2026-10-06T23:20:00Z'))).toHaveLength(1);
    expect(recentFlows(state, Date.parse('2026-10-06T23:40:00Z'))).toHaveLength(0);
  });

  it('lays out only objects that are visible at some step', () => {
    const withGhost: ReplayTimeline = {
      ...TIMELINE,
      objects: { ...TIMELINE.objects, 'host:never-seen': { name: 'never', type: 'host', criticality: null } },
      relationships: {
        ...TIMELINE.relationships,
        'rel:ghost': { type: 'RUNS', source: 'host:never-seen', target: 'process:p1' },
      },
    };
    const visible = everVisible(withGhost);
    expect(visible.objects.has('host:never-seen')).toBe(false);
    expect(visible.relationships.has('rel:ghost')).toBe(false);
    expect(visible.objects.has('ip:198.51.100.23')).toBe(true);
    expect(visible.relationships.has('rel:member')).toBe(true);
  });

  it('labels graph elements as added, present, removed (fading) or absent', () => {
    const atLogin = elementStatuses(TIMELINE, stateAt(TIMELINE, 1));
    expect(atLogin.get('rel:login')).toBe('added');
    expect(atLogin.get('host:vpn-01')).toBe('added');
    expect(atLogin.get('rel:member')).toBe('present');
    expect(atLogin.get('process:p1')).toBe('absent');
    expect(atLogin.get('rel:conn')).toBe('absent');

    const atRemoval = elementStatuses(TIMELINE, stateAt(TIMELINE, 6));
    expect(atRemoval.get('rel:member')).toBe('removed');
    const after = elementStatuses(TIMELINE, stateAt(TIMELINE, 7));
    expect(after.get('rel:member')).toBe('absent');
  });
});
