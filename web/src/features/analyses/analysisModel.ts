/** Pure helpers for analysis records (`POST /analyze`, `GET /analyses`). */
import type { AnalysisRecord, AnalysisStep } from '../../api/types';

export interface StepCounts {
  ok: number;
  skipped: number;
  failed: number;
  other: number;
}

export function stepCounts(steps: readonly AnalysisStep[]): StepCounts {
  const counts: StepCounts = { ok: 0, skipped: 0, failed: 0, other: 0 };
  for (const step of steps) {
    if (step.status === 'ok' || step.status === 'skipped' || step.status === 'failed')
      counts[step.status] += 1;
    else counts.other += 1;
  }
  return counts;
}

/** `JSON Lines` for stored records too (the label lives in `stats.detected_label` there). */
export function detectedLabel(record: AnalysisRecord): string | null {
  if (record.detected_label) return record.detected_label;
  const label = record.stats.detected_label;
  return typeof label === 'string' && label ? label : null;
}

function stringList(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];
}

/** Incident IDs linked by the analysis (top level on uploads, `stats.incidents` on stored records). */
export function analysisIncidents(record: AnalysisRecord): string[] {
  return record.incidents && record.incidents.length > 0
    ? record.incidents
    : stringList(record.stats.incidents);
}

export function analysisJobs(record: AnalysisRecord): string[] {
  const jobs =
    record.job_ids && record.job_ids.length > 0 ? record.job_ids : stringList(record.stats.job_ids);
  if (jobs.length > 0) return jobs;
  return record.job_id ? [record.job_id] : [];
}

// An absolute path token with at least two components (`/srv/x/file.pcap`), outside quotes.
const SERVER_PATH = /(^|\s)(\/[^\s"']*\/[^\s"']+)/g;

/**
 * Suggested CLI commands. The API must never reveal server paths, yet some suggestions embed the
 * stored upload's path (`raf protocol inspect /…/uploads/analyze/<sha>.pcap`); such paths are
 * replaced by the uploaded file's name. Returns the commands and whether anything was replaced.
 */
export function displaySuggestions(record: AnalysisRecord): { commands: string[]; redacted: boolean } {
  let redacted = false;
  const name = record.input || 'FILE';
  const commands = record.suggestions.map((command) =>
    command.replace(SERVER_PATH, (_match, lead: string) => {
      redacted = true;
      return `${lead}${name}`;
    }),
  );
  return { commands, redacted };
}

/** `type:key` object IDs (`host:db-01`, `incident:inc-001`), as opposed to plain values. */
export function isObjectId(value: string): boolean {
  return /^[a-z][a-z_]*:\S/.test(value);
}

export const STATUS_TONES: Record<string, 'good' | 'warn' | 'bad' | 'neutral'> = {
  completed: 'good',
  partial: 'warn',
  failed: 'bad',
  ok: 'good',
  skipped: 'neutral',
};
