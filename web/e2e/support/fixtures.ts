/**
 * Test fixtures.
 *
 * - `test`: the shared server started by the global setup, for tests that change nothing.
 * - `isolatedTest`: a server of its own with a fresh demo workspace for every test that changes data.
 * - `tokenTest`: a server of its own that requires a bearer token for every API request.
 *
 * `api` reads the R$F API of the server the page talks to, to check what the UI shows against it.
 */
import { randomBytes } from 'node:crypto';
import { test as base, expect, type APIRequestContext } from '@playwright/test';
import { ENV, startServer, stopServer, type RafServer } from './server';

export { expect };

export interface Api {
  get<T>(path: string): Promise<T>;
  post<T>(path: string, body: unknown): Promise<T>;
}

function apiClient(request: APIRequestContext, token?: string): Api {
  const headers = token ? { Authorization: `Bearer ${token}` } : undefined;
  const parse = async <T>(
    method: string,
    path: string,
    response: Awaited<ReturnType<typeof request.get>>,
  ) => {
    expect(response.ok(), `${method} /api/v1${path} answered HTTP ${response.status()}`).toBe(true);
    return (await response.json()) as T;
  };
  return {
    get: async <T>(path: string) =>
      await parse<T>('GET', path, await request.get(`/api/v1${path}`, { headers })),
    post: async <T>(path: string, body: unknown) =>
      await parse<T>('POST', path, await request.post(`/api/v1${path}`, { headers, data: body })),
  };
}

export const test = base.extend<{ api: Api }>({
  baseURL: async ({}, use) => {
    const url = process.env[ENV.baseURL];
    if (!url) throw new Error(`${ENV.baseURL} is not set: run the suite with \`npm run test:e2e\`.`);
    await use(url);
  },
  api: async ({ request }, use) => {
    await use(apiClient(request));
  },
});

function serverTest(name: string, withToken: boolean) {
  return base.extend<{ server: RafServer; api: Api }>({
    server: [
      async ({}, use) => {
        const root = process.env[ENV.root];
        if (!root) throw new Error(`${ENV.root} is not set: run the suite with \`npm run test:e2e\`.`);
        const token = withToken ? randomBytes(24).toString('base64url') : undefined;
        const server = await startServer({ parent: root, name, token });
        await use(server);
        await stopServer(server);
      },
      // `raf demo load` and the server start are not part of the test's own time budget.
      { timeout: 120_000 },
    ],
    baseURL: async ({ server }, use) => {
      await use(server.baseURL);
    },
    api: async ({ request, server }, use) => {
      await use(apiClient(request, server.token));
    },
  });
}

export const isolatedTest = serverTest('isolated', false);
export const tokenTest = serverTest('token', true);
