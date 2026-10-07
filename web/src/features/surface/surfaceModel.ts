/** Pure helpers for the Surface views (no network access anywhere: inventories are imported). */
import type { SurfaceFormat } from '../../api/hooks';

/** `POST /surface/import` refuses bodies above 20 MB (413). */
export const MAX_INVENTORY_BYTES = 20 * 1024 * 1024;

export const SURFACE_FORMATS: readonly SurfaceFormat[] = ['json', 'jsonl', 'yaml', 'csv'];

export const SURFACE_KINDS = ['domain', 'ip', 'service', 'certificate', 'cloud_asset'] as const;

export const SCOPE_KINDS = ['domain', 'cidr', 'ip', 'cloud_account'] as const;

/** Rules of `raf surface analyze` (docs/products/surface.md). */
export const SURFACE_RULES = [
  'out-of-scope-asset',
  'unowned-asset',
  'expired-certificate',
  'expiring-certificate',
  'certificate-name-mismatch',
  'dangling-dns',
  'exposed-sensitive-service',
  'public-cloud-storage',
  'shadow-asset',
  'internal-address-in-dns',
] as const;

/** The inventory format from the file name (`.jsonl`, `.ndjson`, `.yaml`, `.yml`, `.csv`; JSON otherwise). */
export function inferSurfaceFormat(filename: string): SurfaceFormat {
  const name = filename.toLowerCase();
  if (name.endsWith('.jsonl') || name.endsWith('.ndjson')) return 'jsonl';
  if (name.endsWith('.yaml') || name.endsWith('.yml')) return 'yaml';
  if (name.endsWith('.csv')) return 'csv';
  return 'json';
}

export type CertificateTone = 'good' | 'warn' | 'bad' | 'neutral';

/** Label and tone of a certificate state at the reference time; days make it readable without colour. */
export function certificateState(
  state: string,
  days: number | null,
): { label: string; detail: string; tone: CertificateTone } {
  switch (state) {
    case 'valid':
      return { label: 'VALID', detail: days !== null ? `${days} days left` : 'valid', tone: 'good' };
    case 'expiring':
      return {
        label: 'EXPIRING',
        detail: days !== null ? `expires in ${days} days` : 'expires soon',
        tone: 'warn',
      };
    case 'expired':
      return {
        label: 'EXPIRED',
        detail: days !== null ? `expired ${Math.abs(days)} days ago` : 'expired',
        tone: 'bad',
      };
    default:
      return { label: 'UNKNOWN', detail: 'no expiry date recorded', tone: 'neutral' };
  }
}

/** `in` / `out` / `unknown` scope status as a short label. */
export function scopeLabel(scope: string): string {
  if (scope === 'in') return 'IN SCOPE';
  if (scope === 'out') return 'OUT OF SCOPE';
  return 'NO SCOPE';
}
