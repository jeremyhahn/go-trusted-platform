import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer, type SentRequest } from '@/test/control-plane-fetch';
import ProxyRoutesPage from './page';
import { parseProxyHosts, proxyRouteFromForm } from './proxy-route-dialog';

// #2061: the Proxy routes page reaches ListRoutes, GetRoute, CreateRoute,
// UpdateRoute, DeleteRoute, GetProxyStatus and ReloadProxyConfig through
// the real SDK client on client.proxy; refusals reach the operator.

const UPDATED_AT = '1795233143';

function shared(): Record<string, Answer> {
  return {
    'GET /api/v1/proxy/status': ok({ version: '7', routeCount: 1, poolCount: 1, updatedAt: UPDATED_AT }),
    'GET /api/v1/proxy/routes': ok({
      routes: [{ id: 'r1', hosts: ['a.example', 'b.example'], pathPrefix: '/api', poolId: 'p1', auth: { mode: 'mtls' } }],
      version: '7',
    }),
  };
}

function count(sent: SentRequest[], method: string, path: string): number {
  return sent.filter((r) => r.method === method && r.path === path).length;
}

async function renderPage() {
  render(withControlPlane(<ProxyRoutesPage />));
}

async function renderLoaded() {
  await renderPage();
  await within(await screen.findByTestId('proxy-routes')).findByText('r1');
}

async function click(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

function type(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

async function toastText(text: string) {
  await waitFor(() => {
    expect(screen.getAllByTestId('toast').map((t) => t.textContent)).toContain(text);
  });
}

describe('ProxyRoutesPage', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('shows the status and the routes', async () => {
    stubControlPlane(shared());
    await renderLoaded();

    const status = within(await screen.findByTestId('proxy-status'));
    expect(await status.findByText('7')).toBeTruthy();
    expect(status.getByText(new Date(Number(UPDATED_AT) * 1000).toISOString())).toBeTruthy();

    const table = within(screen.getByTestId('proxy-routes'));
    expect(table.getByText('r1')).toBeTruthy();
    expect(table.getByText('a.example, b.example /api')).toBeTruthy();
    expect(table.getByText('p1')).toBeTruthy();
    expect(table.getByText('mtls')).toBeTruthy();
  });

  it('creates a route', async () => {
    const sent = stubControlPlane({
      ...shared(),
      'POST /api/v1/proxy/routes': ok({ route: { id: 'r2' }, version: '8' }),
    });
    await renderLoaded();

    await click('New route');
    type('Route ID', 'r2');
    type('Hosts', ' a.example , b.example ');
    type('Path prefix', '/v2');
    type('Pool ID', 'p1');
    await click('Save');

    await toastText('Route created: version 8');
    const post = sent.find((r) => r.method === 'POST' && r.path === '/api/v1/proxy/routes');
    expect(post?.body).toEqual({ route: { id: 'r2', hosts: ['a.example', 'b.example'], pathPrefix: '/v2', poolId: 'p1' } });
    await waitFor(() => expect(count(sent, 'GET', '/api/v1/proxy/routes')).toBe(2));
  });

  it('edits a route and keeps its auth', async () => {
    const sent = stubControlPlane({
      ...shared(),
      'GET /api/v1/proxy/routes/r1': ok({
        route: { id: 'r1', hosts: ['a.example'], pathPrefix: '/api', poolId: 'p1', auth: { mode: 'mtls' }, stripPrefix: true },
      }),
      'PUT /api/v1/proxy/routes/r1': ok({ route: { id: 'r1' }, version: '9' }),
    });
    await renderLoaded();

    await click('Edit r1');
    const id = (await screen.findByLabelText('Route ID')) as HTMLInputElement;
    expect(id.disabled).toBe(true);
    expect(id.value).toBe('r1');
    type('Path prefix', '/v3');
    await click('Save');

    await toastText('Route updated: version 9');
    const put = sent.find((r) => r.method === 'PUT' && r.path === '/api/v1/proxy/routes/r1');
    expect(put?.body).toEqual({
      route: { id: 'r1', hosts: ['a.example'], pathPrefix: '/v3', poolId: 'p1', auth: { mode: 'mtls' }, stripPrefix: true },
    });
  });

  it('deletes a route only after the confirm', async () => {
    const sent = stubControlPlane({
      ...shared(),
      'DELETE /api/v1/proxy/routes/r1': ok({ version: '10' }),
    });
    await renderLoaded();

    await click('Delete r1');
    await screen.findByText('Delete route r1? Traffic it matches will no longer be proxied.');
    await click('Cancel');
    expect(count(sent, 'DELETE', '/api/v1/proxy/routes/r1')).toBe(0);

    await click('Delete r1');
    const dialog = within(await screen.findByRole('dialog'));
    await act(async () => {
      fireEvent.click(dialog.getByRole('button', { name: 'Delete' }));
    });

    await toastText('Route deleted: version 10');
    expect(count(sent, 'DELETE', '/api/v1/proxy/routes/r1')).toBe(1);
  });

  it('reloads the config', async () => {
    const sent = stubControlPlane({
      ...shared(),
      'POST /api/v1/proxy/reload': ok({ version: '11' }),
    });
    await renderLoaded();

    await click('Reload config');

    await toastText('Config reloaded: version 11');
    const post = sent.find((r) => r.method === 'POST' && r.path === '/api/v1/proxy/reload');
    expect(post?.body).toEqual({});
    await waitFor(() => expect(count(sent, 'GET', '/api/v1/proxy/status')).toBe(2));
  });

  it('keeps the dialog open on a refused create', async () => {
    stubControlPlane({
      ...shared(),
      'POST /api/v1/proxy/routes': refused(409, 'proxy: route r1 already exists'),
    });
    await renderLoaded();

    await click('New route');
    type('Route ID', 'r1');
    type('Pool ID', 'p1');
    await click('Save');

    await waitFor(() => {
      const destructive = screen
        .getAllByTestId('toast')
        .filter((t) => t.getAttribute('data-variant') === 'destructive');
      expect(destructive.map((t) => t.textContent).join('\n')).toContain('proxy: route r1 already exists');
    });
    expect(screen.getByRole('heading', { name: 'New route' })).toBeTruthy();
  });

  it('shows a refused list', async () => {
    stubControlPlane({
      ...shared(),
      'GET /api/v1/proxy/routes': refused(403, 'proxy: read scope required'),
    });
    await renderPage();

    expect((await screen.findByRole('alert')).textContent).toContain('proxy: read scope required');
  });
});

describe('proxy route form helpers', () => {
  it('parses hosts and builds the route to send', () => {
    expect(parseProxyHosts(' a.example , ,b.example ')).toEqual(['a.example', 'b.example']);
    expect(proxyRouteFromForm({ id: ' r3 ', hosts: '', pathPrefix: '', poolId: ' p2 ' })).toEqual({
      id: 'r3',
      hosts: [],
      pathPrefix: '',
      poolId: 'p2',
    });
  });
});
