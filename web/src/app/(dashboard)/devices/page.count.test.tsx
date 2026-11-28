import { cleanup, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';

// The devices page reads the registered total through the real SDK client
// (DeviceService.countDevices -> GET /devices/count, #2048). Only the heavy
// table and form are stubbed; fetch is the control-plane stub.

vi.mock('next/navigation', () => ({
  usePathname: () => '/devices',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

type TableProps = {
  devices: unknown[];
  onDeviceChange: () => void;
};

vi.mock('@/components/features/devices/device-table', () => ({
  DeviceTable: ({ devices, onDeviceChange }: TableProps) => (
    <div data-testid="device-table">
      <ul>
        {devices.map((d, i) => (
          <li key={i} data-testid="device-row">
            {JSON.stringify(d)}
          </li>
        ))}
      </ul>
      <button onClick={onDeviceChange}>table-change</button>
    </div>
  ),
}));

vi.mock('@/components/features/devices/device-form', () => ({
  DeviceForm: ({ onSuccess, onCancel }: { onSuccess: () => void; onCancel: () => void }) => (
    <div>
      <button onClick={onSuccess}>form-success</button>
      <button onClick={onCancel}>form-cancel</button>
    </div>
  ),
}));

import DevicesPage from './page';

function devicesList(n: number) {
  return Array.from({ length: n }, (_, k) => {
    const i = k + 1;
    return { id: i, serial: 'node-' + i, model: 'X10', state: 'active', created_at: '2026-10-01T00:00:00Z' };
  });
}

function routes(n: number, total: number, count: ReturnType<typeof ok>) {
  return {
    'GET /api/v1/devices': ok({
      devices: devicesList(n),
      pagination: { page: 1, page_size: 100, total, total_pages: 1, has_more: false },
    }),
    'GET /api/v1/attestation/reports': ok({ reports: [], count: 0 }),
    'GET /api/v1/devices/count': count,
  };
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('DevicesPage registered total (#2048)', () => {
  it('shows the registered total from GET /devices/count', async () => {
    const sent = stubControlPlane(routes(3, 3, ok({ count: 3 })));
    render(withControlPlane(<DevicesPage />));

    const line = await screen.findByTestId('device-count');
    expect(line.textContent).toBe('Showing 3 of 3 registered devices');
    expect(sent).toContainEqual({ method: 'GET', path: '/api/v1/devices/count', body: undefined });
    expect(await screen.findAllByTestId('device-row')).toHaveLength(3);
  });

  it('says the list is cut off when the fleet is larger than the loaded page', async () => {
    stubControlPlane(routes(2, 250, ok({ count: 250 })));
    render(withControlPlane(<DevicesPage />));

    await waitFor(() =>
      expect(screen.getByTestId('device-count').textContent).toBe(
        'Showing 2 of 250 registered devices (only the first 2 are loaded)'
      )
    );
  });

  it('hides the total and keeps the list when the count is refused', async () => {
    const sent = stubControlPlane(routes(2, 2, refused(403, 'forbidden')));
    render(withControlPlane(<DevicesPage />));

    expect(await screen.findAllByTestId('device-row')).toHaveLength(2);
    await waitFor(() =>
      expect(sent.some((r) => r.method === 'GET' && r.path === '/api/v1/devices/count')).toBe(true)
    );
    expect(screen.queryByTestId('device-count')).toBeNull();
  });

  it('hides the total when the count refresh after a device change is refused', async () => {
    const r = routes(3, 3, ok({ count: 3 }));
    const sent = stubControlPlane(r);
    render(withControlPlane(<DevicesPage />));

    await waitFor(() =>
      expect(screen.getByTestId('device-count').textContent).toBe('Showing 3 of 3 registered devices')
    );

    r['GET /api/v1/devices/count'] = refused(403, 'forbidden');
    screen.getByText('table-change').click();

    await waitFor(() =>
      expect(
        sent.filter((x) => x.method === 'GET' && x.path === '/api/v1/devices/count').length
      ).toBe(2)
    );
    await waitFor(() => expect(screen.queryByTestId('device-count')).toBeNull());
    expect(screen.getAllByTestId('device-row')).toHaveLength(3);
  });

  it('updates the total when the count refresh after a device change succeeds', async () => {
    const r = routes(3, 3, ok({ count: 3 }));
    stubControlPlane(r);
    render(withControlPlane(<DevicesPage />));

    await waitFor(() =>
      expect(screen.getByTestId('device-count').textContent).toBe('Showing 3 of 3 registered devices')
    );

    r['GET /api/v1/devices/count'] = ok({ count: 2 });
    screen.getByText('table-change').click();

    await waitFor(() =>
      expect(screen.getByTestId('device-count').textContent).toBe('Showing 3 of 2 registered devices')
    );
  });
});
