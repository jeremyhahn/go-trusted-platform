import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import ConfigPage from './page';

// #2047: the config page reads the tree (GetConfig) and reloads it
// (ReloadConfig) through the real SDK client on PlatformService; a refused
// read shows inline, a refused reload reaches the operator as a destructive
// toast.

vi.mock('next/navigation', () => ({
  useParams: () => ({}),
  usePathname: () => '/platform/config',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const CONFIG_OPS = ['POST /api/v1/platform/config/reload', 'PUT /api/v1/platform/config/sections/{section}'] as const;

// The server's capabilities listing: both config writes enabled.
function caps(): Answer {
  const capabilities = CONFIG_OPS.map((op) => ({ op, kind: 'route', enabled: true }));
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.length });
}

function shared(): Record<string, Answer> {
  return {
    'GET /api/v1/capabilities': caps(),
    'GET /api/v1/platform/config': ok({
      sources: [{ path: '/etc/platformd/config.yaml', format: 'yaml' }],
      tree: { tpm: { device: '/dev/tpmrm0' } },
      generated_at: '2026-11-20T00:00:00Z',
      secrets_hidden: false,
    }),
    'GET /api/v1/platform/config/snapshots': ok({ snapshots: [] }),
  };
}

function count(sent: { method: string; path: string }[], method: string, path: string) {
  return sent.filter((r) => r.method === method && r.path === path).length;
}

async function clickReload() {
  const button = await screen.findByRole('button', { name: /reload/i });
  await waitFor(() => expect((button as HTMLButtonElement).disabled).toBe(false));
  await act(async () => {
    fireEvent.click(button);
  });
}

describe('ConfigPage through the SDK', () => {
  it('reads the configuration tree through the SDK client', async () => {
    const sent = stubControlPlane(shared());
    render(withControlPlane(<ConfigPage />));

    expect(await screen.findByText(/\/dev\/tpmrm0/)).toBeTruthy();
    expect(screen.getByText('/etc/platformd/config.yaml')).toBeTruthy();
    expect(count(sent, 'GET', '/api/v1/platform/config')).toBeGreaterThan(0);
  });

  it('reloads through the SDK client and refreshes the tree', async () => {
    const sent = stubControlPlane({
      ...shared(),
      'POST /api/v1/platform/config/reload': ok({
        reloaded: true,
        sections: ['tpm', 'webservice'],
        pre_reload_snapshot: 'snap-9',
      }),
    });
    render(withControlPlane(<ConfigPage />));
    await screen.findByText(/\/dev\/tpmrm0/);

    await clickReload();

    await waitFor(() => {
      const toast = screen
        .queryAllByTestId('toast')
        .find((t) => t.textContent?.includes('Configuration reloaded'));
      expect(toast?.textContent).toBe(
        'Configuration reloaded: Refreshed 2 sections. Pre-reload snapshot: snap-9',
      );
    });
    expect(count(sent, 'POST', '/api/v1/platform/config/reload')).toBe(1);
    await waitFor(() => expect(count(sent, 'GET', '/api/v1/platform/config')).toBe(2));
  });

  it('shows a refused read inline', async () => {
    stubControlPlane({
      ...shared(),
      'GET /api/v1/platform/config': refused(503, 'config tree unavailable'),
    });
    render(withControlPlane(<ConfigPage />));

    expect(await screen.findByText(/Failed to load configuration:/)).toBeTruthy();
    expect(screen.getByText(/config tree unavailable/)).toBeTruthy();
  });

  it('shows a refused reload as a destructive toast', async () => {
    stubControlPlane({
      ...shared(),
      'POST /api/v1/platform/config/reload': refused(409, 'reload in progress'),
    });
    render(withControlPlane(<ConfigPage />));
    await screen.findByText(/\/dev\/tpmrm0/);

    await clickReload();

    await waitFor(() => {
      const toast = screen.queryAllByTestId('toast').find((t) => t.textContent?.includes('Reload failed'));
      expect(toast?.getAttribute('data-variant')).toBe('destructive');
      expect(toast?.textContent).toContain('reload in progress');
    });
  });
});
