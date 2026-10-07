import { QueryClient } from '@tanstack/react-query';
import { render } from '@testing-library/react';
import type { ReactElement, ReactNode } from 'react';
import { createMemoryRouter, Outlet, RouterProvider, type RouteObject } from 'react-router-dom';
import { vi } from 'vitest';
import { AppProviders } from '../app/App';
import { ShellProviders } from '../app/Shell';

export interface MockRoute {
  method?: string;
  /** Path below /api/v1, matched against the decoded pathname. */
  path: string | RegExp;
  status?: number;
  /** JSON payload, or a function `(url, init) => payload`. */
  body: unknown;
}

export interface RecordedCall {
  method: string;
  url: URL;
  path: string;
  headers: Headers;
  body: unknown;
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

export const WORKSPACES = {
  items: [
    {
      name: 'default',
      path: '/tmp/raf/default',
      description: 'Default workspace',
      created_at: '2026-10-07T11:05:47Z',
      current: true,
    },
    {
      name: 'case-7',
      path: '/tmp/raf/case-7',
      description: 'Case seven',
      created_at: '2026-10-07T12:00:00Z',
      current: false,
    },
  ],
  current: 'default',
};

/**
 * Replaces global fetch with a router over `routes`. Unmatched requests answer like a missing API
 * route (404 `raf.http_404`), which the UI treats as "not available yet".
 */
export function mockFetch(routes: MockRoute[]) {
  const calls: RecordedCall[] = [];
  const all: MockRoute[] = [...routes, { path: '/workspaces', body: WORKSPACES }];
  const fn = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const raw = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    const url = new URL(raw, 'http://localhost');
    const method = (init?.method ?? 'GET').toUpperCase();
    const path = decodeURIComponent(url.pathname.replace(/^\/api\/v1/, ''));
    const headers = new Headers(init?.headers);
    let body: unknown = undefined;
    if (typeof init?.body === 'string') body = JSON.parse(init.body) as unknown;
    calls.push({ method, url, path, headers, body });
    const route = all.find(
      (candidate) =>
        (candidate.method ?? 'GET').toUpperCase() === method &&
        (typeof candidate.path === 'string' ? candidate.path === path : candidate.path.test(path)),
    );
    if (!route) return Promise.resolve(json(404, { error: { code: 'raf.http_404', message: 'Not Found' } }));
    const payload =
      typeof route.body === 'function'
        ? (route.body as (u: URL, i?: RequestInit) => unknown)(url, init)
        : route.body;
    return Promise.resolve(json(route.status ?? 200, payload));
  });
  vi.stubGlobal('fetch', fn);
  return { fn, calls };
}

export function createTestClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, staleTime: Infinity, gcTime: Infinity },
      mutations: { retry: false },
    },
  });
}

/**
 * Renders `ui` inside every application provider and a memory router. `extraRoutes` are rendered
 * as siblings so tests can observe navigation.
 */
export function renderWithApp(
  ui: ReactElement,
  { route = '/', extraRoutes = [] }: { route?: string; extraRoutes?: RouteObject[] } = {},
) {
  const client = createTestClient();
  const Layout = ({ children }: { children?: ReactNode }) => (
    <ShellProviders>
      {ui}
      {children ?? <Outlet />}
    </ShellProviders>
  );
  const router = createMemoryRouter(
    [
      {
        path: '/',
        element: <Layout />,
        children: [
          { index: true, element: <p>home view</p> },
          ...extraRoutes,
          { path: '*', element: <p>other view</p> },
        ],
      },
    ],
    { initialEntries: [route] },
  );
  const result = render(
    <AppProviders client={client}>
      <RouterProvider router={router} />
    </AppProviders>,
  );
  return { ...result, client, router };
}
