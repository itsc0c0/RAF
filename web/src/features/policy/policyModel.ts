/** Pure helpers for the policy views. */
import type { PolicyDiff, PolicyFormat } from '../../api/types';
import { displayValue } from '../../lib/format';

/** `POST /policy/check` refuses documents above 5 MB (`MAX_POLICY_FILE_BYTES`). */
export const MAX_POLICY_DOCUMENT_BYTES = 5 * 1024 * 1024;

export const POLICY_FORMATS: readonly PolicyFormat[] = ['json', 'yaml', 'csv', 'iptables'];

/** iptables-save file suffixes, as `raf policy check` recognizes them (`IPTABLES_SUFFIXES`). */
export const IPTABLES_SUFFIXES: readonly string[] = ['.rules', '.iptables', '.v4', '.v6'];

/**
 * The document format from a file name (`.yaml`, `.yml`, `.csv`, iptables-save suffixes; JSON
 * otherwise, as `raf policy check` reads it). The server also recognizes iptables-save by content.
 */
export function inferPolicyFormat(filename: string): PolicyFormat {
  const name = filename.toLowerCase();
  if (name.endsWith('.yaml') || name.endsWith('.yml')) return 'yaml';
  if (name.endsWith('.csv')) return 'csv';
  if (IPTABLES_SUFFIXES.some((suffix) => name.endsWith(suffix))) return 'iptables';
  return 'json';
}

/** The host an iptables-save file belongs to by default: its name without the suffix (`raf policy check` does the same). */
export function hostFromFileName(filename: string): string {
  const base = filename.split(/[\\/]/).pop() ?? '';
  const dot = base.lastIndexOf('.');
  return (dot > 0 ? base.slice(0, dot) : base).slice(0, 200);
}

/** True when the two revisions do not differ in any policy, default, rule or analysis finding. */
export function isEmptyPolicyDiff(diff: PolicyDiff): boolean {
  return (
    diff.policies_added.length === 0 &&
    diff.policies_removed.length === 0 &&
    diff.defaults_changed.length === 0 &&
    diff.changes.length === 0 &&
    diff.findings_introduced.length === 0 &&
    diff.findings_resolved.length === 0
  );
}

/** A changed rule field as text: selector lists are joined (`tcp/22, tcp/8443`), anything else stringified. */
export function ruleFieldText(value: unknown): string {
  if (Array.isArray(value))
    return value.length > 0 ? value.map((item) => displayValue(item)).join(', ') : '(none)';
  return displayValue(value);
}
