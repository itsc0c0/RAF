import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, onTestFinished, vi } from 'vitest';
import { API_TOKEN_STORAGE_KEY, setApiToken } from '../api/auth';
import { DownloadLink } from '../components/DownloadLink';
import SettingsPage from '../pages/SettingsPage';
import { mockFetch, renderWithApp, WORKSPACES } from '../test/utils';
import { useWorkspace } from './workspace';

const TOKEN = 's3cret-Token_value';
const UNAUTHORIZED = { error: { code: 'raf.unauthorized', message: 'Missing or invalid token.' } };

/** Every route answers 401 `raf.unauthorized` unless the request carries the right bearer token. */
function protectedApi(extra: Array<{ path: string; body: unknown }> = []) {
  return mockFetch(
    [{ path: '/workspaces', body: WORKSPACES }, ...extra].map((route) => ({
      path: route.path,
      handler: ({ headers }: { headers: Headers }) =>
        headers.get('Authorization') === `Bearer ${TOKEN}`
          ? { body: route.body }
          : { status: 401, body: UNAUTHORIZED },
    })),
  );
}

function WorkspaceProbe() {
  const { workspace } = useWorkspace();
  return <p>workspace: {workspace ?? 'none'}</p>;
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('bearer token', () => {
  it('prompts on 401, stores the token in sessionStorage only and sends it on every request', async () => {
    const user = userEvent.setup();
    const { calls } = protectedApi();
    renderWithApp(<WorkspaceProbe />);

    const dialog = await screen.findByRole('dialog', { name: 'Access token required' });
    expect(screen.getByText('workspace: none')).toBeInTheDocument();
    const input = within(dialog).getByLabelText('Token');
    expect(input).toHaveAttribute('type', 'password');
    await user.type(input, TOKEN);
    await user.click(within(dialog).getByRole('button', { name: 'Use token' }));

    expect(await screen.findByText('workspace: default')).toBeInTheDocument();
    expect(window.sessionStorage.getItem(API_TOKEN_STORAGE_KEY)).toBe(TOKEN);
    expect(Object.values({ ...window.localStorage })).not.toContain(TOKEN);
    const authorized = calls.filter((call) => call.headers.get('Authorization') === `Bearer ${TOKEN}`);
    expect(authorized.length).toBeGreaterThan(0);
    expect(calls[0]!.headers.get('Authorization')).toBeNull();
    // The token is never rendered (the input was type=password and the dialog is gone).
    await waitFor(() =>
      expect(screen.queryByRole('dialog', { name: 'Access token required' })).not.toBeInTheDocument(),
    );
    expect(document.body.textContent).not.toContain(TOKEN);
    const attributes = [...document.querySelectorAll('*')].flatMap((element) =>
      [...element.attributes].map((attribute) => attribute.value),
    );
    expect(attributes.some((value) => value.includes(TOKEN))).toBe(false);
  });

  it('does not reopen the prompt after Cancel, and offers it again from the top-bar style indicator', async () => {
    const user = userEvent.setup();
    protectedApi();
    renderWithApp(<WorkspaceProbe />);
    const dialog = await screen.findByRole('dialog', { name: 'Access token required' });
    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(window.sessionStorage.getItem(API_TOKEN_STORAGE_KEY)).toBeNull();
  });

  it('forgets the token from Settings and says when the server rejects a stored token', async () => {
    const user = userEvent.setup();
    setApiToken('wrong-token');
    protectedApi([
      { path: '/config', body: { items: [] } },
      { path: '/version', body: { raf: '0.1.0', api: 'v1' } },
      { path: '/oracle/status', body: { provider: 'builtin' } },
    ]);
    renderWithApp(<></>, {
      route: '/settings',
      extraRoutes: [{ path: 'settings', element: <SettingsPage /> }],
    });

    const dialog = await screen.findByRole('dialog', { name: 'Access token required' });
    expect(within(dialog).getByText('The server rejected the current token')).toBeInTheDocument();
    await user.type(within(dialog).getByLabelText('Token'), TOKEN);
    await user.click(within(dialog).getByRole('button', { name: 'Use token' }));
    expect(await screen.findByText('TOKEN SET FOR THIS TAB')).toBeInTheDocument();
    expect(window.sessionStorage.getItem(API_TOKEN_STORAGE_KEY)).toBe(TOKEN);

    await user.click(screen.getByRole('button', { name: 'Forget token' }));
    expect(window.sessionStorage.getItem(API_TOKEN_STORAGE_KEY)).toBeNull();
    // Forgetting does not pop the prompt up again by itself.
    await waitFor(() =>
      expect(screen.queryByRole('dialog', { name: 'Access token required' })).not.toBeInTheDocument(),
    );
  });
});

describe('downloads with a token', () => {
  it('fetches exports with the Authorization header and saves them from an object URL', async () => {
    const user = userEvent.setup();
    const created: Blob[] = [];
    // jsdom has no object URLs: provide them for this test only.
    const original = { create: URL.createObjectURL, revoke: URL.revokeObjectURL };
    URL.createObjectURL = vi.fn((blob: Blob) => {
      created.push(blob);
      return 'blob:raf-test';
    });
    URL.revokeObjectURL = vi.fn();
    onTestFinished(() => {
      URL.createObjectURL = original.create;
      URL.revokeObjectURL = original.revoke;
    });
    const clicks: Array<{ href: string; download: string }> = [];
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
      clicks.push({ href: this.getAttribute('href') ?? '', download: this.download });
    });
    const { calls } = mockFetch([{ path: '/timeline/export', body: { items: [] } }]);
    setApiToken(TOKEN);
    renderWithApp(
      <DownloadLink
        path="/timeline/export"
        query={{ ref: 'INC-001', format: 'csv' }}
        filename="raf-timeline.csv"
      >
        CSV
      </DownloadLink>,
    );
    const link = await screen.findByRole('link', { name: 'CSV' });
    await waitFor(() =>
      expect(link).toHaveAttribute(
        'href',
        '/api/v1/timeline/export?ref=INC-001&format=csv&workspace=default',
      ),
    );
    await user.click(link);

    await waitFor(() => expect(clicks).toHaveLength(1));
    const exportCall = calls.find((call) => call.path === '/timeline/export')!;
    expect(exportCall.headers.get('Authorization')).toBe(`Bearer ${TOKEN}`);
    expect(exportCall.url.searchParams.get('workspace')).toBe('default');
    expect(exportCall.url.search).not.toContain(TOKEN);
    expect(clicks[0]).toEqual({ href: 'blob:raf-test', download: 'raf-timeline.csv' });
    expect(created).toHaveLength(1);
  });

  it('keeps plain same-origin links without a token', async () => {
    mockFetch([]);
    renderWithApp(
      <DownloadLink path="/graph/export" query={{ format: 'graphml' }} filename="raf-graph.graphml" nameLink>
        Export
      </DownloadLink>,
    );
    const link = await screen.findByRole('link', { name: 'Export' });
    await waitFor(() =>
      expect(link).toHaveAttribute('href', '/api/v1/graph/export?format=graphml&workspace=default'),
    );
    expect(link).toHaveAttribute('download', 'raf-graph.graphml');
  });
});
