/**
 * Internal routes and safe pivot handling.
 *
 * Pivot targets (`view`) come from the API, i.e. they are data. The UI only ever navigates to
 * routes of this application: anything that is not a known same-origin path is rejected.
 */

export const APP_ROUTES = [
  '/',
  '/investigate',
  '/graph',
  '/replay',
  '/timeline',
  '/exposure',
  '/ranges',
  '/labs',
  '/evidence',
  '/findings',
  '/products',
  '/settings',
] as const;

export type AppRoute = (typeof APP_ROUTES)[number];

const ROUTE_SET: ReadonlySet<string> = new Set(APP_ROUTES);

/**
 * Pivot parameters whose value is a raw reference. The backend builds views as
 * `/graph?focus=<object id>` without encoding, and object IDs may contain `&`, `+`, `#`, `|`, `/`,
 * so the parameter owns the whole remainder of the query string.
 */
const REFERENCE_PARAMS: ReadonlySet<string> = new Set([
  'focus',
  'object',
  'trace',
  'incident',
  'blast',
  'iam',
  'scope',
  'finding',
  'case',
]);

// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/;

/** Returns a safe, normalized in-app route for `view`, or null when it is not an internal route. */
export function toInternalRoute(view: unknown): string | null {
  if (typeof view !== 'string') return null;
  const value = view.trim();
  if (!value.startsWith('/') || value.startsWith('//') || value.includes('\\') || CONTROL_CHARS.test(value)) {
    return null;
  }
  const queryIndex = value.indexOf('?');
  const rawPath = queryIndex === -1 ? value : value.slice(0, queryIndex);
  const path = rawPath.length > 1 && rawPath.endsWith('/') ? rawPath.slice(0, -1) : rawPath;
  if (!ROUTE_SET.has(path)) return null;
  if (queryIndex === -1) return path;
  const query = value.slice(queryIndex + 1);
  if (!query) return path;
  const eq = query.indexOf('=');
  const key = eq === -1 ? '' : query.slice(0, eq);
  if (REFERENCE_PARAMS.has(key)) {
    const reference = query.slice(eq + 1);
    return reference ? `${path}?${key}=${encodeURIComponent(reference)}` : path;
  }
  const params = new URLSearchParams(query);
  const normalized = params.toString();
  return normalized ? `${path}?${normalized}` : path;
}

function withParam(path: AppRoute, key: string, value: string | null | undefined): string {
  return value ? `${path}?${key}=${encodeURIComponent(value)}` : path;
}

/** Builders for every pivot the UI creates itself (always encoded). */
export const routeTo = {
  overview: () => '/',
  graph: (focus?: string | null) => withParam('/graph', 'focus', focus),
  timeline: (object?: string | null) => withParam('/timeline', 'object', object),
  timelineScope: (scope: string) => withParam('/timeline', 'scope', scope),
  replay: (incident?: string | null) => withParam('/replay', 'incident', incident),
  trace: (ref: string) => withParam('/investigate', 'trace', ref),
  lens: (ref?: string | null) => withParam('/investigate', 'object', ref),
  blast: (ref: string) => withParam('/exposure', 'blast', ref),
  exposure: (ref?: string | null) => withParam('/exposure', 'object', ref),
  iam: (ref: string) => withParam('/exposure', 'iam', ref),
  evidence: (ref?: string | null) => withParam('/evidence', 'object', ref),
  evidenceCase: (name: string) => withParam('/evidence', 'case', name),
  finding: (id?: string | null) => withParam('/findings', 'finding', id),
} as const;
