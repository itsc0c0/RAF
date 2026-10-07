import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { RedirectTo } from '../../app/router';
import LabPage from '../../pages/LabPage';
import { mockFetch, renderWithApp } from '../../test/utils';
import { formatCommand, labCreateBody, EMPTY_LAB_FORM, validateLabForm } from './labForm';
import { OUTBOUND_WARNING, ROOT_WARNING } from './LabViews';

const LAB = {
  name: 'proto-test',
  state: 'defined',
  live: false,
  image: 'alpine:3.20',
  network: 'bridge',
  allow_outbound: true,
  mounts: [{ source: '/srv/samples', target: '/lab/input/samples', read_only: true }],
  memory: '256m',
  cpus: '0.5',
  pids_limit: 256,
  user: '0:0',
  root: true,
  backend: 'auto',
  container: 'raf-lab-default-proto-test',
  container_id: null,
  description: 'parser tests',
  created_at: '2026-10-07T13:13:34.054334Z',
  updated_at: '2026-10-07T13:13:34.054334Z',
  state_at: null,
  note: 'last known state; docker is unavailable',
  container_args: [
    'docker',
    'create',
    '--name',
    'raf-lab-default-proto-test',
    '--network',
    'bridge',
    '-c',
    'trap "exit 0" TERM',
  ],
};

function setup(labs: unknown[] = []) {
  const api = mockFetch([
    {
      path: '/lab/status',
      body: {
        backend: 'docker',
        available: false,
        reason: 'cannot connect to the Docker daemon',
        version: null,
      },
    },
    { path: '/lab/labs', body: { items: labs, total: labs.length } },
    { path: '/lab/labs/proto-test', body: LAB },
    {
      path: '/config',
      body: {
        items: [
          {
            key: 'lab.default_image',
            value: 'alpine:3.20',
            origin: 'default',
            secret: false,
            description: '',
          },
        ],
      },
    },
    { method: 'POST', path: '/lab/labs', status: 201, body: LAB },
    {
      method: 'DELETE',
      path: '/lab/labs/proto-test',
      body: {
        name: 'proto-test',
        destroyed: true,
        container: 'raf-lab-default-proto-test',
        container_removed: false,
      },
    },
  ]);
  const view = renderWithApp(<></>, { route: '/lab', extraRoutes: [{ path: 'lab', element: <LabPage /> }] });
  return { ...view, api };
}

describe('Lab page', () => {
  it('creates a lab with exactly the fields the API accepts', async () => {
    const user = userEvent.setup();
    const { api, router } = setup();
    const form = await screen.findByRole('form', { name: 'New lab' });

    await user.type(within(form).getByLabelText('Name'), 'proto-test');
    await user.type(within(form).getByLabelText('Image (optional)'), 'alpine:3.20');
    await user.click(within(form).getByRole('button', { name: 'Add mount' }));
    await user.type(within(form).getByLabelText('Mount path 1'), '/srv/samples');
    await user.type(within(form).getByLabelText('Memory (optional)'), '256m');
    await user.type(within(form).getByLabelText('CPUs (optional)'), '0.5');
    await user.type(within(form).getByLabelText('Description (optional)'), 'parser tests');

    // Both risky options explain themselves when chosen.
    expect(within(form).queryByText(OUTBOUND_WARNING)).not.toBeInTheDocument();
    await user.click(within(form).getByLabelText('Allow outbound network access'));
    expect(within(form).getByText(OUTBOUND_WARNING)).toBeInTheDocument();
    await user.click(within(form).getByLabelText('Run as root inside the container'));
    expect(within(form).getByText(ROOT_WARNING)).toBeInTheDocument();

    await user.click(within(form).getByRole('button', { name: 'Create lab' }));
    await waitFor(() => expect(api.calls.some((call) => call.method === 'POST')).toBe(true));
    const post = api.calls.find((call) => call.method === 'POST' && call.path === '/lab/labs')!;
    expect(post.body).toEqual({
      name: 'proto-test',
      image: 'alpine:3.20',
      mounts: ['/srv/samples'],
      allow_outbound: true,
      memory: '256m',
      cpus: '0.5',
      root: true,
      description: 'parser tests',
    });
    expect(post.body).not.toHaveProperty('template');
    // The new lab opens in the detail drawer (its URL is deep-linkable).
    await waitFor(() => expect(router.state.location.search).toBe('?lab=proto-test'));
  });

  it('checks the form before sending: names and absolute mount paths', async () => {
    const user = userEvent.setup();
    const { api } = setup();
    const form = await screen.findByRole('form', { name: 'New lab' });
    await user.type(within(form).getByLabelText('Name'), 'Bad_Name');
    await user.click(within(form).getByRole('button', { name: 'Add mount' }));
    await user.type(within(form).getByLabelText('Mount path 1'), 'samples');
    await user.click(within(form).getByRole('button', { name: 'Create lab' }));
    expect(await within(form).findByText(/lowercase letters, digits/)).toBeInTheDocument();
    expect(
      within(form).getByText('Mount paths must be absolute: they are resolved on the R$F server.'),
    ).toBeInTheDocument();
    expect(api.calls.some((call) => call.method === 'POST')).toBe(false);
  });

  it('lists labs with network, mounts, user and lifecycle; destroy can forget; no exec route', async () => {
    const user = userEvent.setup();
    const { router } = setup([LAB]);
    const table = await screen.findByRole('table', { name: 'Labs' });
    const row = within(table).getAllByRole('row')[1]!;
    expect(row).toHaveTextContent('proto-test');
    expect(row).toHaveTextContent('OUTBOUND');
    expect(row).toHaveTextContent('ROOT');
    expect(row).toHaveTextContent('256m · 0.5 CPU · 256 pids');
    expect(row).toHaveTextContent('last known state; docker is unavailable');
    // The backend is down: start/stop are disabled with the reason, destroy stays possible.
    expect(within(row).getByRole('button', { name: 'Start lab proto-test' })).toBeDisabled();
    expect(within(row).getByRole('button', { name: 'Destroy lab proto-test' })).toBeEnabled();
    expect(screen.getAllByText(/raf lab exec/).length).toBeGreaterThan(0);

    await user.click(within(row).getByRole('button', { name: 'Destroy lab proto-test' }));
    const dialog = await screen.findByRole('dialog', { name: 'Destroy lab “proto-test”?' });
    expect(within(dialog).getByLabelText('Forget only (keep what cannot be removed)')).not.toBeChecked();
    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }));

    await user.click(within(row).getByText('proto-test'));
    await waitFor(() => expect(router.state.location.search).toBe('?lab=proto-test'));
    const drawer = await screen.findByRole('dialog', { name: 'proto-test' });
    expect(await within(drawer).findByText('/lab/input/samples')).toBeInTheDocument();
    expect(within(drawer).getByText('READ-ONLY')).toBeInTheDocument();
    expect(within(drawer).getByText(formatCommand(LAB.container_args))).toBeInTheDocument();
  });

  it('destroys from the drawer with "forget", closes it and never refetches the deleted lab', async () => {
    const user = userEvent.setup();
    const { api, router } = setup([LAB]);
    await user.click(within(await screen.findByRole('table', { name: 'Labs' })).getByText('proto-test'));
    const drawer = await screen.findByRole('dialog', { name: 'proto-test' });
    await within(drawer).findByText('/lab/input/samples');

    await user.click(within(drawer).getByRole('button', { name: 'Destroy lab proto-test' }));
    const dialog = await screen.findByRole('dialog', { name: 'Destroy lab “proto-test”?' });
    await user.click(within(dialog).getByLabelText('Forget only (keep what cannot be removed)'));
    await user.type(within(dialog).getByLabelText(/to confirm/), 'proto-test');
    await user.click(within(dialog).getByRole('button', { name: 'Destroy' }));

    await waitFor(() => expect(router.state.location.search).toBe(''));
    const deleteIndex = api.calls.findIndex((call) => call.method === 'DELETE');
    expect(api.calls[deleteIndex]?.url.searchParams.get('forget')).toBe('true');
    // The list is refreshed; the deleted lab's detail is not requested again (it would be a 404).
    await waitFor(() =>
      expect(api.calls.slice(deleteIndex + 1).some((call) => call.path === '/lab/labs')).toBe(true),
    );
    expect(api.calls.slice(deleteIndex + 1).some((call) => call.path === '/lab/labs/proto-test')).toBe(false);
  });

  it('keeps /labs as a redirect to /lab', async () => {
    mockFetch([]);
    const { router } = renderWithApp(<></>, {
      route: '/labs?lab=x',
      extraRoutes: [
        { path: 'labs', element: <RedirectTo to="/lab" /> },
        { path: 'lab', element: <p>lab view</p> },
      ],
    });
    expect(await screen.findByText('lab view')).toBeInTheDocument();
    expect(router.state.location.pathname).toBe('/lab');
    expect(router.state.location.search).toBe('?lab=x');
  });
});

describe('lab form helpers', () => {
  it('omits unset optional fields but always sends the flags as booleans', () => {
    expect(labCreateBody({ ...EMPTY_LAB_FORM, name: ' plain ' })).toEqual({
      name: 'plain',
      allow_outbound: false,
      root: false,
    });
    expect(validateLabForm({ ...EMPTY_LAB_FORM, name: 'ok-name', memory: '2g', cpus: '16' })).toEqual({});
    expect(validateLabForm({ ...EMPTY_LAB_FORM, name: 'ok-name', cpus: '0.01' }).cpus).toBeDefined();
    expect(formatCommand(['sh', '-c', "it's"])).toBe(`sh -c 'it'\\''s'`);
  });
});
