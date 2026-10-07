/**
 * Typed fetch wrapper for the R$F API.
 *
 * - Every request is scoped to an explicit workspace (`X-RAF-Workspace`), passed by the caller so a
 *   response can never be attributed to the wrong workspace after a switch.
 * - Errors always surface as {@link ApiError}, built from the API's
 *   `{"error": {code, message, reason, hint, suggestions, details}}` envelope.
 */

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

async function errorFromResponse(response: Response): Promise<ApiError> {
  let payload: unknown;
  try {
    const text = await response.text();
    payload = text ? (JSON.parse(text) as unknown) : null;
  } catch {
    payload = null;
  }
  if (isErrorBody(payload)) return new ApiError(response.status, payload.error);
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

export async function request<T>(method: string, path: string, options: RequestOptions = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (options.workspace) headers[WORKSPACE_HEADER] = options.workspace;
  let body: BodyInit | undefined;
  if (options.form) {
    body = options.form;
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
    throw new ApiError(0, {
      code: 'raf.network',
      message: 'Cannot reach the R$F API.',
      hint: 'Start it with `raf serve` (default http://127.0.0.1:8765).',
    });
  }
  if (!response.ok) throw await errorFromResponse(response);
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
