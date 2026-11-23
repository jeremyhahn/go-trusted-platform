import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { CAPABILITIES_LOADING_REASON } from '@/hooks/use-capabilities';
import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import ProxyPoolsPage from './page';
import { parseProxyBackends, proxyPoolToForm } from './proxy-pool-dialog';

// #2061: the proxy pools page reaches ListPools, GetPool, CreatePool,
// UpdatePool, DeletePool, GetProxyConfig and GetZoneMatrix through the real
// SDK client on client.proxy; a refusal reaches the operator as a
// destructive toast or an alert.

vi.mock('next/navigation', () => ({
  useParams: () => ({}),
  usePathname: () => '/networking/proxy/pools',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const PROXY_OPS = [
  'GET /api/v1/proxy/routes',
  'POST /api/v1/proxy/routes',
  'GET /api/v1/proxy/routes/{id}',
  'PUT /api/v1/proxy/routes/{id}',
  'DELETE /api/v1/proxy/routes/{id}',
  'GET /api/v1/proxy/pools',
  'POST /api/v1/proxy/pools',
  'GET /api/v1/proxy/pools/{id}',
  'PUT /api/v1/proxy/pools/{id}',
  'DELETE /api/v1/proxy/pools/{id}',
  'GET /api/v1/proxy/config',
  'GET /api/v1/proxy/status',
  'POST /api/v1/proxy/reload',
  'GET /api/v1/proxy/zone-matrix',
] as const;

// The server's capabilities listing: every proxy op enabled except those in off.
function caps(off: string[] = []): Answer {
  const capabilities = PROXY_OPS.map((op) =>
    off.includes(op)
      ? { op, kind: 'route', enabled: false, reason: 'not-configured: proxy' }
      : { op, kind: 'route', enabled: true },
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

function shared(): Record<string, Answer> {
  return {
    'GET /api/v1/capabilities': caps(),
    'GET /api/v1/proxy/pools': ok({
      pools: [
        {
          id: 'p1',
          backends: [{ url: 'https://192.0.2.10:8443', weight: 2 }, { url: 'https://192.0.2.11:8443' }],
          balancer: 'least-conn',
          tls: { trustClass: 'internal' },
        },
      ],
      version: '4',
    }),
    'GET /api/v1/proxy/config': ok({ routes: [{ id: 'r1' }, { id: 'r2' }], pools: [{ id: 'p1' }], version: '4' }),
    'GET /api/v1/proxy/zone-matrix': ok({
      zones: ['mgmt', 'tenant'],
      pairs: [
        { from: 'mgmt', to: 'tenant', services: [] },
        { from: 'tenant', to: 'mgmt', services: ['dns', 'ntp'] },
      ],
    }),
  };
}

async function renderPage() {
  render(withControlPlane(<ProxyPoolsPage />));
  await within(await screen.findByTestId('proxy-pools')).findByText('p1');
  await capabilitiesAnswered();
}

// The rows can render before the capabilities listing answers; until it does
// every gated control is disabled with the loading reason, so a click on it
// opens nothing. Wait until no gated control is still loading.
async function capabilitiesAnswered() {
  await waitFor(() => {
    const gated = Array.from(document.querySelectorAll('[data-capability-op]'));
    expect(gated.length).toBeGreaterThan(0);
    expect(gated.filter((el) => el.getAttribute('title') === CAPABILITIES_LOADING_REASON)).toEqual([]);
  });
}

async function click(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

function type(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

function count(sent: { method: string; path: string }[], method: string, path: string) {
  return sent.filter((r) => r.method === method && r.path === path).length;
}

describe('ProxyPoolsPage', () => {
  it('shows the pools, the config and the zone matrix', async () => {
    stubControlPlane(shared());
    await renderPage();

    const pools = screen.getByTestId('proxy-pools');
    expect(within(pools).getByText('2 backends, least-conn')).toBeTruthy();
    expect(within(pools).getByText('internal')).toBeTruthy();

    const config = screen.getByTestId('proxy-config');
    await within(config).findByText('4');
    expect(within(config).getByText('2')).toBeTruthy();

    const matrix = screen.getByTestId('proxy-zone-matrix');
    await within(matrix).findByText('dns, ntp');
    expect(within(matrix).getAllByText('mgmt').length).toBeGreaterThan(0);
    expect(within(matrix).getAllByText('tenant').length).toBeGreaterThan(0);
    expect(within(matrix).getByText('all')).toBeTruthy();
  });

  it('creates a pool', async () => {
    const sent = stubControlPlane({
      ...shared(),
      'POST /api/v1/proxy/pools': ok({ pool: { id: 'p2' }, version: '5' }),
    });
    await renderPage();

    await click('New pool');
    type('Pool ID', 'p2');
    type('Backends', 'https://192.0.2.20:8443 3\n\nhttps://192.0.2.21:8443');
    await click('Save');

    expect(await screen.findByText('Pool created: version 5')).toBeTruthy();
    const post = sent.find((r) => r.method === 'POST' && r.path === '/api/v1/proxy/pools');
    expect(post?.body).toEqual({
      pool: {
        id: 'p2',
        backends: [{ url: 'https://192.0.2.20:8443', weight: 3 }, { url: 'https://192.0.2.21:8443' }],
      },
    });
    await waitFor(() => expect(count(sent, 'GET', '/api/v1/proxy/pools')).toBe(2));
  });

  it('edits a pool and keeps its tls', async () => {
    const sent = stubControlPlane({
      ...shared(),
      'GET /api/v1/proxy/pools/p1': ok({
        pool: {
          id: 'p1',
          backends: [{ url: 'https://192.0.2.10:8443', weight: 2 }],
          balancer: 'least-conn',
          tls: { trustClass: 'internal' },
        },
      }),
      'PUT /api/v1/proxy/pools/p1': ok({ pool: { id: 'p1' }, version: '6' }),
    });
    await renderPage();

    await click('Edit p1');
    await waitFor(() =>
      expect((screen.getByLabelText('Backends') as HTMLTextAreaElement).value).toBe('https://192.0.2.10:8443 2')
    );
    type('Balancer', 'round-robin');
    await click('Save');

    expect(await screen.findByText('Pool updated: version 6')).toBeTruthy();
    const put = sent.find((r) => r.method === 'PUT' && r.path === '/api/v1/proxy/pools/p1');
    expect(put?.body).toEqual({
      pool: {
        id: 'p1',
        backends: [{ url: 'https://192.0.2.10:8443', weight: 2 }],
        balancer: 'round-robin',
        tls: { trustClass: 'internal' },
      },
    });
  });

  it('deletes a pool only after the confirm', async () => {
    const sent = stubControlPlane({
      ...shared(),
      'DELETE /api/v1/proxy/pools/p1': ok({ version: '7' }),
    });
    await renderPage();

    await click('Delete p1');
    await screen.findByText('Delete pool');
    await click('Cancel');
    await waitFor(() => expect(screen.queryByText('Delete pool')).toBeNull());
    expect(count(sent, 'DELETE', '/api/v1/proxy/pools/p1')).toBe(0);

    await click('Delete p1');
    const dialog = await screen.findByRole('dialog');
    await act(async () => {
      fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }));
    });

    expect(await screen.findByText('Pool deleted: version 7')).toBeTruthy();
    expect(count(sent, 'DELETE', '/api/v1/proxy/pools/p1')).toBe(1);
  });

  it('keeps the dialog open on a refused create', async () => {
    stubControlPlane({
      ...shared(),
      'POST /api/v1/proxy/pools': refused(400, 'proxy: pool p2 has no backends'),
    });
    await renderPage();

    await click('New pool');
    type('Pool ID', 'p2');
    type('Backends', 'https://192.0.2.20:8443');
    await click('Save');

    await waitFor(() => {
      const toast = screen.getAllByTestId('toast').find((t) => t.textContent?.includes('proxy: pool p2 has no backends'));
      expect(toast?.getAttribute('data-variant')).toBe('destructive');
    });
    expect(screen.getByText('New pool', { selector: 'h2' })).toBeTruthy();
  });

  it('shows a refused list', async () => {
    stubControlPlane({
      ...shared(),
      'GET /api/v1/proxy/pools': refused(403, 'proxy: read scope required'),
    });
    render(withControlPlane(<ProxyPoolsPage />));

    const alert = await within(await screen.findByTestId('proxy-pools')).findByRole('alert');
    expect(alert.textContent).toContain('proxy: read scope required');
    await within(screen.getByTestId('proxy-config')).findByText('4');
  });

  it('withholds the controls the server does not offer', async () => {
    stubControlPlane({
      ...shared(),
      'GET /api/v1/capabilities': caps([
        'POST /api/v1/proxy/pools',
        'PUT /api/v1/proxy/pools/{id}',
        'DELETE /api/v1/proxy/pools/{id}',
      ]),
    });
    await renderPage();

    for (const name of ['New pool', 'Edit p1', 'Delete p1']) {
      const button = screen.getByRole('button', { name }) as HTMLButtonElement;
      expect(button.disabled).toBe(true);
      expect(button.getAttribute('data-capability-enabled')).toBe('false');
      expect(button.getAttribute('title')).toBe('not-configured: proxy');
    }
  });

  it('makes no proxy read when the server does not offer them', async () => {
    const sent = stubControlPlane({
      ...shared(),
      'GET /api/v1/capabilities': caps(['GET /api/v1/proxy/pools', 'GET /api/v1/proxy/config', 'GET /api/v1/proxy/zone-matrix']),
    });
    render(withControlPlane(<ProxyPoolsPage />));

    expect((await screen.findByTestId('proxy-not-enabled')).textContent).toContain('not-configured: proxy');
    expect(count(sent, 'GET', '/api/v1/proxy/pools')).toBe(0);
    expect(count(sent, 'GET', '/api/v1/proxy/config')).toBe(0);
    expect(count(sent, 'GET', '/api/v1/proxy/zone-matrix')).toBe(0);
  });

  it('parses the backend lines', () => {
    expect(parseProxyBackends(' https://192.0.2.1 \nhttps://192.0.2.2 5\nhttps://192.0.2.3 x\n')).toEqual([
      { url: 'https://192.0.2.1' },
      { url: 'https://192.0.2.2', weight: 5 },
      { url: 'https://192.0.2.3' },
    ]);
    expect(proxyPoolToForm({ id: 'p', backends: [{ url: 'https://192.0.2.1', weight: 2 }] })).toEqual({
      id: 'p',
      backends: 'https://192.0.2.1 2',
      balancer: '',
    });
  });
});
