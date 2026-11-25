import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import PXEBootPage from './page';

vi.mock('next/navigation', () => ({
  useParams: () => ({}),
  usePathname: () => '/networking/pxe',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const LIST = 'GET /api/v1/pxe/devices';

function caps(): Answer {
  const capabilities = [LIST].map((op) => ({ op, kind: 'route', enabled: true }));
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.length });
}

function routes(): Record<string, Answer> {
  return {
    'GET /api/v1/capabilities': caps(),
    'GET /api/v1/pxe/devices': ok({
      devices: [
        { id: 'd1', macAddress: '02:00:00:00:00:01', state: 'DISCOVERED' },
        { id: 'node 2', macAddress: '02:00:00:00:00:02', state: 'AUTHORIZED' },
      ],
    }),
    'GET /api/v1/pxe/status': ok({ status: { running: false } }),
  };
}

// Codex P1 on #2368 (review at e666cb220) asked for navigation from the
// devices table to the detail page; 3930ce2a9 added the link this pins.
describe('PXEBootPage device links', () => {
  it('links each device MAC to its detail page', async () => {
    stubControlPlane(routes());
    render(withControlPlane(<PXEBootPage />));

    const link = await screen.findByTestId('pxe-device-link-d1');
    expect(link.tagName).toBe('A');
    expect(link.getAttribute('href')).toBe('/networking/pxe/d1');
    expect(link.textContent).toBe('02:00:00:00:00:01');
  });

  it('escapes the device id in the link', async () => {
    stubControlPlane(routes());
    render(withControlPlane(<PXEBootPage />));

    const link = await screen.findByTestId('pxe-device-link-node 2');
    expect(link.tagName).toBe('A');
    expect(link.getAttribute('href')).toBe('/networking/pxe/node%202');
  });
});
