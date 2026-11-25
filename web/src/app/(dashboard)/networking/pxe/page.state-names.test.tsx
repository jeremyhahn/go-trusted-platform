import { cleanup, render, screen, within } from '@testing-library/react';
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

// The REST server writes the protobuf enum name of each state.
function routes(): Record<string, Answer> {
  return {
    'GET /api/v1/capabilities': caps(),
    'GET /api/v1/pxe/devices': ok({
      devices: [
        { id: 'd1', macAddress: '02:00:00:00:00:01', state: 'PROVISIONING_STATE_DISCOVERED' },
        { id: 'node 2', macAddress: '02:00:00:00:00:02', state: 'PROVISIONING_STATE_QUARANTINED' },
      ],
    }),
    'GET /api/v1/pxe/status': ok({ status: { running: false } }),
  };
}

describe('PXEBootPage state names', () => {
  it('shows each device state under its short name and colour', async () => {
    stubControlPlane(routes());
    render(withControlPlane(<PXEBootPage />));

    const first = (await screen.findByTestId('pxe-device-link-d1')).closest('tr');
    expect(first).not.toBeNull();
    expect(within(first as HTMLElement).getByText('DISCOVERED')).toBeTruthy();

    const second = screen.getByTestId('pxe-device-link-node 2').closest('tr');
    expect(second).not.toBeNull();
    const badge = within(second as HTMLElement).getByText('QUARANTINED');
    expect(badge.className).toContain('text-red-500');

    expect(screen.queryByText(/PROVISIONING_STATE_/)).toBeNull();
  });
});
