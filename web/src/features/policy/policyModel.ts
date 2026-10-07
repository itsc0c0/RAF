/** Pure helpers for the policy views. */
import type { PolicyDiff, PolicyFormat } from '../../api/types';
import { displayValue } from '../../lib/format';

/** `POST /policy/check` refuses documents above 5 MB (`MAX_POLICY_FILE_BYTES`). */
export const MAX_POLICY_DOCUMENT_BYTES = 5 * 1024 * 1024;

export const POLICY_FORMATS: readonly PolicyFormat[] = ['json', 'yaml', 'csv', 'iptables', 'nftables'];

/** iptables-save file suffixes, as `raf policy check` recognizes them (`IPTABLES_SUFFIXES`). */
export const IPTABLES_SUFFIXES: readonly string[] = ['.rules', '.iptables', '.v4', '.v6'];

/** nftables file suffixes (`NFT_SUFFIXES`); nftables.conf and `nft -j` JSON are recognized by content. */
export const NFT_SUFFIXES: readonly string[] = ['.nft', '.nftables'];

/** Formats whose rules belong to a host (`--host`). */
export const HOST_FORMATS: readonly PolicyFormat[] = ['iptables', 'nftables'];

/**
 * The document format from a file name (`.yaml`, `.yml`, `.csv`, iptables-save and nftables
 * suffixes, `nftables.conf`; JSON otherwise, as `raf policy check` reads it). The server also
 * recognizes iptables-save and nftables (text or `nft -j` JSON) by content.
 */
export function inferPolicyFormat(filename: string): PolicyFormat {
  const name = filename.toLowerCase();
  if (name.endsWith('.yaml') || name.endsWith('.yml')) return 'yaml';
  if (name.endsWith('.csv')) return 'csv';
  if (IPTABLES_SUFFIXES.some((suffix) => name.endsWith(suffix))) return 'iptables';
  if (NFT_SUFFIXES.some((suffix) => name.endsWith(suffix)) || /(^|[\\/])nftables\.conf$/.test(name)) {
    return 'nftables';
  }
  return 'json';
}

/** Suffixes a file name loses before it names the host (`raf policy check` does the same). */
const NAME_SUFFIXES = ['.json', '.txt', '.conf', ...NFT_SUFFIXES, ...IPTABLES_SUFFIXES];

/** The host a rule set file belongs to by default: its name without suffixes (`edge.nft.json` -> `edge`). */
export function hostFromFileName(filename: string): string {
  let name = filename.split(/[\\/]/).pop() ?? '';
  for (;;) {
    const lower = name.toLowerCase();
    const suffix = NAME_SUFFIXES.find((s) => lower.endsWith(s) && lower.length > s.length);
    if (!suffix) break;
    name = name.slice(0, -suffix.length);
  }
  return name.slice(0, 200);
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
