import { describe, expect, it, vi } from 'vitest';
import { mockFetch } from '../test/utils';
import { clearApiToken, getApiToken, onUnauthorized, setApiToken } from './auth';
import {
  api,
  ApiError,
  buildQuery,
  downloadUrl,
  encodeRef,
  filenameFromDisposition,
  safeFilename,
} from './client';

describe('api client', () => {
  it('sends the workspace header and encodes references', async () => {
    const { calls } = mockFetch([{ path: '/objects/file:app-01|/usr/bin/curl', body: { ok: true } }]);
    await api.get(`/objects/${encodeRef('file:app-01|/usr/bin/curl')}`, { workspace: 'case-7' });
    expect(calls[0]!.headers.get('X-RAF-Workspace')).toBe('case-7');
    expect(calls[0]!.url.pathname).toBe('/api/v1/objects/file%3Aapp-01%7C%2Fusr%2Fbin%2Fcurl');
  });

  it('parses the error envelope into an ApiError', async () => {
    mockFetch([
      {
        path: '/objects/nope',
        status: 404,
        body: {
          error: {
            code: 'raf.not_found',
            message: "No object named 'nope' exists in this workspace.",
            hint: 'Import data first.',
            suggestions: ['raf search nope'],
          },
        },
      },
    ]);
    const error = await api.get('/objects/nope').catch((reason: unknown) => reason);
    expect(error).toBeInstanceOf(ApiError);
    const apiError = error as ApiError;
    expect(apiError.status).toBe(404);
    expect(apiError.code).toBe('raf.not_found');
    expect(apiError.message).toBe("No object named 'nope' exists in this workspace.");
    expect(apiError.hint).toBe('Import data first.');
    expect(apiError.suggestions).toEqual(['raf search nope']);
    expect(apiError.isNotFound).toBe(true);
    expect(apiError.isUnavailable).toBe(false);
  });

  it('treats missing routes and 503 as "not available yet"', async () => {
    mockFetch([
      {
        path: '/lab/status',
        status: 503,
        body: { error: { code: 'raf.dependency_unavailable', message: 'Docker missing' } },
      },
    ]);
    const missing = (await api.get('/blast/alice').catch((reason: unknown) => reason)) as ApiError;
    expect(missing.code).toBe('raf.http_404');
    expect(missing.isUnavailable).toBe(true);
    expect(missing.isNotFound).toBe(false);
    const dependency = (await api.get('/lab/status').catch((reason: unknown) => reason)) as ApiError;
    expect(dependency.isUnavailable).toBe(true);
  });

  it('maps network failures and proxy errors to a clear message', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.reject(new TypeError('Failed to fetch'))),
    );
    const network = (await api.get('/status').catch((reason: unknown) => reason)) as ApiError;
    expect(network.isNetwork).toBe(true);
    expect(network.message).toBe('Cannot reach the R$F API.');
    expect(network.hint).toContain('raf serve');

    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.resolve(new Response('Bad gateway', { status: 502 }))),
    );
    const proxy = (await api.get('/status').catch((reason: unknown) => reason)) as ApiError;
    expect(proxy.status).toBe(502);
    expect(proxy.message).toBe('Cannot reach the R$F API.');
  });

  it('serializes JSON bodies and repeated query parameters', async () => {
    const { calls } = mockFetch([
      { method: 'PATCH', path: '/findings/finding:1', body: { id: 'finding:1' } },
    ]);
    await api.patch('/findings/finding:1', { body: { status: 'RESOLVED', note: null } });
    expect(calls[0]!.headers.get('Content-Type')).toBe('application/json');
    expect(calls[0]!.body).toEqual({ status: 'RESOLVED', note: null });
    expect(buildQuery({ type: ['auth.login', 'process.start'], q: '', limit: 5, empty: undefined })).toBe(
      '?type=auth.login&type=process.start&limit=5',
    );
  });

  it('builds same-origin download URLs scoped by the workspace query parameter', () => {
    expect(downloadUrl('/timeline/export', { ref: 'INC-001', format: 'csv' }, 'default')).toBe(
      '/api/v1/timeline/export?ref=INC-001&format=csv&workspace=default',
    );
  });

  it('sends the bearer token when one is set, and reports 401 raf.unauthorized with the token used', async () => {
    const { calls } = mockFetch([
      {
        path: '/status',
        handler: ({ headers }) =>
          headers.get('Authorization') === 'Bearer abc.DEF-123'
            ? { body: { ok: true } }
            : {
                status: 401,
                body: { error: { code: 'raf.unauthorized', message: 'Missing or invalid token.' } },
              },
      },
    ]);
    const seen: Array<string | null> = [];
    const stop = onUnauthorized((used) => seen.push(used));
    try {
      const refused = (await api.get('/status').catch((reason: unknown) => reason)) as ApiError;
      expect(refused.isUnauthorized).toBe(true);
      expect(refused.isUnavailable).toBe(false);
      expect(refused.hint).toContain('raf serve');
      expect(seen).toEqual([null]);
      expect(calls[0]!.headers.get('Authorization')).toBeNull();

      setApiToken(' abc.DEF-123 ');
      expect(getApiToken()).toBe('abc.DEF-123');
      expect(window.sessionStorage.getItem('raf.api.token')).toBe('abc.DEF-123');
      await expect(api.get('/status')).resolves.toEqual({ ok: true });
      expect(calls[1]!.headers.get('Authorization')).toBe('Bearer abc.DEF-123');
    } finally {
      stop();
      clearApiToken();
    }
    expect(window.sessionStorage.getItem('raf.api.token')).toBeNull();
    expect(() => setApiToken('has space')).toThrow();
  });

  it('exposes the field problems of 422 invalid requests', async () => {
    mockFetch([
      {
        method: 'POST',
        path: '/lab/labs',
        status: 422,
        body: {
          error: {
            code: 'raf.invalid_request',
            message: 'Invalid request.',
            details: { problems: [{ loc: ['body', 'template'], msg: 'Extra inputs are not permitted' }] },
          },
        },
      },
    ]);
    const error = (await api
      .post('/lab/labs', { body: { template: 'x' } })
      .catch((r: unknown) => r)) as ApiError;
    expect(error.problems).toEqual(['template: Extra inputs are not permitted']);
  });

  it('derives safe download file names', () => {
    expect(filenameFromDisposition('attachment; filename="timeline-INC-001.csv"')).toBe(
      'timeline-INC-001.csv',
    );
    expect(filenameFromDisposition("attachment; filename*=UTF-8''a%20b.json")).toBe('a b.json');
    expect(filenameFromDisposition(null)).toBeNull();
    expect(safeFilename('../../etc/passwd', 'x')).toBe('_.._etc_passwd');
    expect(safeFilename('a\u0000b:c.csv', 'x')).toBe('a_b_c.csv');
    expect(safeFilename('', 'fallback.csv')).toBe('fallback.csv');
  });
});
