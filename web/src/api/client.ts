/**
 * Typed fetch wrapper for the R$F API.
 *
 * - Every request is scoped to an explicit workspace (`X-RAF-Workspace`), passed by the caller so a
 *   response can never be attributed to the wrong workspace after a switch.
 * - Errors always surface as {@link ApiError}, built from the API's
 *   `{"error": {code, message, reason, hint, suggestions, details}}` envelope.
 * - When a bearer token is set for this tab (`api/auth.ts`) every request carries
 *   `Authorization: Bearer <token>`; a 401 `raf.unauthorized` answer notifies the token prompt.
 */

import { authorizationHeaders, getApiToken, hasApiToken, notifyUnauthorized } from './auth';
import type { ApiErrorBody } from './types';

export const API_BASE = '/api/v1';
export const WORKSPACE_HEADER = 'X-RAF-Workspace';

export type QueryScalar = string | number | boolean | null | undefined;
export type QueryValue = QueryScalar | readonly QueryScalar[];
export type QueryParams = Readonly<Record<string, QueryValue>>;

export interface RequestOptions {
  workspace?: string | null;
  query?: QueryParams;
  /** JSON body. */
  body?: unknown;
  /** Multipart body (file uploads). */
  form?: FormData;
  /** Raw body (a file sent as the request body) with its media type. */
  raw?: { body: Blob; contentType: string };
  signal?: AbortSignal;
}

/** Codes that mean "this capability is not installed / not mounted / not reachable yet". */
const UNAVAILABLE_CODES = new Set([
  'raf.http_404',
  'raf.http_405',
  'raf.http_501',
  'raf.product_disabled',
  'raf.dependency_unavailable',
]);

/** Returned by `TokenAuthMiddleware` when the bearer token is missing or wrong. */
export const UNAUTHORIZED_CODE = 'raf.unauthorized';

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly reason?: string;
  readonly hint?: string;
  readonly suggestions: string[];
  readonly details?: unknown;

  constructor(status: number, body: ApiErrorBody) {
    super(body.message);
    this.name = 'ApiError';
    this.status = status;
    this.code = body.code;
    this.reason = body.reason;
    this.hint = body.hint;
    this.suggestions = Array.isArray(body.suggestions) ? body.suggestions.map(String) : [];
    this.details = body.details;
  }

  /** The endpoint/product is not available (not built yet, disabled, or a dependency is missing). */
  get isUnavailable(): boolean {
    return this.status === 503 || this.status === 501 || UNAVAILABLE_CODES.has(this.code);
  }

  /** The API itself could not be reached (server stopped, proxy error). */
  get isNetwork(): boolean {
    return this.status === 0 || this.code === 'raf.network';
  }

  /** A referenced item does not exist (as opposed to a missing endpoint). */
  get isNotFound(): boolean {
    return this.status === 404 && !this.isUnavailable;
  }

  /** The server requires a bearer token (missing or rejected): `raf serve` on a non-loopback address. */
  get isUnauthorized(): boolean {
    return this.status === 401 && this.code === UNAUTHORIZED_CODE;
  }

  /** Field problems of a 422 `raf.invalid_request` (`details.problems: [{loc, msg}]`), as text. */
  get problems(): string[] {
    const details = this.details;
    if (typeof details !== 'object' || details === null || !('problems' in details)) return [];
    const problems = details.problems;
    if (!Array.isArray(problems)) return [];
    return problems.map((problem: unknown) => {
      if (typeof problem !== 'object' || problem === null) return String(problem);
      const loc = 'loc' in problem && Array.isArray(problem.loc) ? problem.loc.map(String) : [];
      const where = loc.filter((part) => part !== 'body' && part !== 'query').join('.');
      const msg = 'msg' in problem ? String(problem.msg) : 'invalid value';
      return where ? `${where}: ${msg}` : msg;
    });
  }
}

export function isApiError(error: unknown): error is ApiError {
  return error instanceof ApiError;
}

/** Encodes an object reference for use as a path segment (IDs may contain `/`, `|`, `:`, `#`). */
export function encodeRef(ref: string): string {
  return encodeURIComponent(ref);
}

export function buildQuery(query?: QueryParams): string {
  if (!query) return '';
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    const values: readonly QueryScalar[] = Array.isArray(value) ? value : [value];
    for (const item of values) {
      if (item === null || item === undefined || item === '') continue;
      params.append(key, String(item));
    }
  }
  const text = params.toString();
  return text ? `?${text}` : '';
}

export function buildUrl(path: string, query?: QueryParams): string {
  return `${API_BASE}${path}${buildQuery(query)}`;
}

function isErrorBody(value: unknown): value is { error: ApiErrorBody } {
  if (typeof value !== 'object' || value === null || !('error' in value)) return false;
  const error = value.error;
  return (
    typeof error === 'object' &&
    error !== null &&
    'message' in error &&
    typeof error.message === 'string' &&
    'code' in error &&
    typeof error.code === 'string'
  );
}

const UNAUTHORIZED_HINT =
  'This R$F server is exposed beyond loopback and requires the access token printed by `raf serve` (or set in RAF_API_TOKEN).';

async function errorFromResponse(response: Response): Promise<ApiError> {
  let payload: unknown;
  try {
    const text = await response.text();
    payload = text ? (JSON.parse(text) as unknown) : null;
  } catch {
    payload = null;
  }
  if (isErrorBody(payload)) {
    const body = payload.error;
    if (response.status === 401 && body.code === UNAUTHORIZED_CODE && !body.hint) {
      return new ApiError(response.status, { ...body, hint: UNAUTHORIZED_HINT });
    }
    return new ApiError(response.status, body);
  }
  if (response.status === 502 || response.status === 504) {
    return new ApiError(response.status, {
      code: 'raf.network',
      message: 'Cannot reach the R$F API.',
      hint: 'Start it with `raf serve` (default http://127.0.0.1:8765).',
    });
  }
  return new ApiError(response.status, {
    code: `raf.http_${response.status}`,
    message: response.statusText ? `${response.status} ${response.statusText}` : `HTTP ${response.status}`,
  });
}

/**
 * Error from a failed response; a 401 `raf.unauthorized` also notifies the token prompt (with the
 * token the request carried, so answers to requests sent before a new token was set are ignored).
 */
async function failure(response: Response, usedToken: string | null): Promise<ApiError> {
  const error = await errorFromResponse(response);
  if (error.isUnauthorized) notifyUnauthorized(usedToken);
  return error;
}

const NETWORK_ERROR: ApiErrorBody = {
  code: 'raf.network',
  message: 'Cannot reach the R$F API.',
  hint: 'Start it with `raf serve` (default http://127.0.0.1:8765).',
};

export async function request<T>(method: string, path: string, options: RequestOptions = {}): Promise<T> {
  const token = getApiToken();
  const headers: Record<string, string> = { Accept: 'application/json', ...authorizationHeaders(token) };
  if (options.workspace) headers[WORKSPACE_HEADER] = options.workspace;
  let body: BodyInit | undefined;
  if (options.form) {
    body = options.form;
  } else if (options.raw) {
    headers['Content-Type'] = options.raw.contentType;
    body = options.raw.body;
  } else if (options.body !== undefined) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(options.body);
  }
  let response: Response;
  try {
    response = await fetch(buildUrl(path, options.query), {
      method,
      headers,
      body,
      signal: options.signal,
      credentials: 'same-origin',
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') throw error;
    throw new ApiError(0, NETWORK_ERROR);
  }
  if (!response.ok) throw await failure(response, token);
  if (response.status === 204) return undefined as T;
  const contentType = response.headers.get('content-type') ?? '';
  if (contentType.includes('application/json')) return (await response.json()) as T;
  return (await response.text()) as T;
}

export const api = {
  get: <T>(path: string, options?: RequestOptions) => request<T>('GET', path, options),
  post: <T>(path: string, options?: RequestOptions) => request<T>('POST', path, options),
  patch: <T>(path: string, options?: RequestOptions) => request<T>('PATCH', path, options),
  delete: <T>(path: string, options?: RequestOptions) => request<T>('DELETE', path, options),
};

/**
 * Same-origin download URL (exports). Plain links cannot carry headers, so the workspace travels as
 * the `?workspace=` query parameter, which the API accepts on every route.
 */
export function downloadUrl(path: string, query: QueryParams, workspace: string | null): string {
  return buildUrl(path, { ...query, workspace: workspace ?? undefined });
}

// eslint-disable-next-line no-control-regex
const UNSAFE_FILENAME = /[\u0000-\u001f\u007f/\\:*?"<>|]+/g;

/** A file name safe to offer for saving (no path separators or control characters). */
export function safeFilename(name: string | null | undefined, fallback: string): string {
  const cleaned = (name ?? '')
    .replace(UNSAFE_FILENAME, '_')
    .replace(/^[.\s]+/, '')
    .trim()
    .slice(0, 120);
  return cleaned || fallback;
}

/** `attachment; filename="timeline-INC-001.csv"` -> `timeline-INC-001.csv` */
export function filenameFromDisposition(header: string | null): string | null {
  if (!header) return null;
  const star = /filename\*\s*=\s*(?:UTF-8'')?([^;]+)/i.exec(header);
  if (star?.[1]) {
    try {
      return decodeURIComponent(star[1].trim().replace(/^"|"$/g, ''));
    } catch {
      // Fall through to the plain parameter.
    }
  }
  const plain = /filename\s*=\s*"?([^";]+)"?/i.exec(header);
  return plain?.[1]?.trim() ?? null;
}

/** Whether downloads must go through `fetch` (a token header) instead of a plain link. */
export function downloadsNeedFetch(): boolean {
  return hasApiToken();
}

/**
 * Downloads an export with the `Authorization` header (plain links cannot carry it): fetch, Blob,
 * temporary object URL, programmatic click. The file name comes from `Content-Disposition` (sanitized)
 * or `fallbackName`.
 */
export async function downloadWithFetch(url: string, fallbackName: string): Promise<void> {
  const token = getApiToken();
  let response: Response;
  try {
    response = await fetch(url, { headers: authorizationHeaders(token), credentials: 'same-origin' });
  } catch {
    throw new ApiError(0, NETWORK_ERROR);
  }
  if (!response.ok) throw await failure(response, token);
  const blob = await response.blob();
  const name = safeFilename(
    filenameFromDisposition(response.headers.get('content-disposition')),
    fallbackName,
  );
  const objectUrl = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = objectUrl;
  anchor.download = name;
  anchor.rel = 'noopener';
  anchor.style.display = 'none';
  document.body.appendChild(anchor);
  try {
    anchor.click();
  } finally {
    anchor.remove();
    // Revoke after the browser has started the download.
    window.setTimeout(() => URL.revokeObjectURL(objectUrl), 10_000);
  }
}
