import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';

const router = { push: vi.fn() };
vi.mock('next/navigation', () => ({ useRouter: () => router, usePathname: () => '/devices' }));

import { DeviceSerialLookup } from './device-serial-lookup';

// #2048: the devices list counts devices (GET /devices/count) and finds one by serial (GET /devices/serial/{serial}) through the SDK, capability-gated.

const COUNT_OP = 'GET /api/v1/devices/count';
const FIND_OP = 'GET /api/v1/devices/serial/{serial}';

// The server's capabilities listing for the count and lookup ops; an op in
// off is listed but disabled.
function caps(off: string[] = []): Answer {
  const capabilities = [COUNT_OP, FIND_OP].map((op) =>
    off.includes(op)
      ? { op, kind: 'route', enabled: false, reason: 'not-configured: device' }
      : { op, kind: 'route', enabled: true }
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

function routes(overrides: Record<string, Answer> = {}): Record<string, Answer> {
  return {
    'GET /api/v1/capabilities': caps(),
    'GET /api/v1/devices/count': ok({ count: 3 }),
    ...overrides,
  };
}

const find = () => screen.getByRole('button', { name: 'Find' });

async function lookUp(serial: string) {
  fireEvent.change(await screen.findByLabelText('Find by serial'), { target: { value: serial } });
  await waitFor(() => expect(find().hasAttribute('disabled')).toBe(false));
  await act(async () => {
    fireEvent.click(find());
  });
}

describe('DeviceSerialLookup', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    router.push.mockReset();
  });

  it('shows the device count', async () => {
    stubControlPlane(routes());
    render(withControlPlane(<DeviceSerialLookup />));

    await screen.findByText('3 devices');
  });

  it('finds a device by serial and opens its page', async () => {
    const sent = stubControlPlane(
      routes({ 'GET /api/v1/devices/serial/node-07': ok({ id: 7, serial: 'node-07', model: 'X10' }) })
    );
    render(withControlPlane(<DeviceSerialLookup />));

    await lookUp('node-07');

    await waitFor(() => expect(router.push).toHaveBeenCalledWith('/devices/7'));
    expect(sent.some((r) => r.method === 'GET' && r.path === '/api/v1/devices/serial/node-07')).toBe(true);
  });

  it('shows a destructive toast when no device has the serial', async () => {
    stubControlPlane(routes({ 'GET /api/v1/devices/serial/node-99': refused(404, 'device not found') }));
    render(withControlPlane(<DeviceSerialLookup />));

    await lookUp('node-99');

    const toast = await screen.findByTestId('toast');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(toast.textContent).toContain('not found');
    expect(router.push).not.toHaveBeenCalled();
  });

  it('withholds Find and the count when the server does not offer them', async () => {
    const sent = stubControlPlane(routes({ 'GET /api/v1/capabilities': caps([COUNT_OP, FIND_OP]) }));
    render(withControlPlane(<DeviceSerialLookup />));

    fireEvent.change(await screen.findByLabelText('Find by serial'), { target: { value: 'node-07' } });
    await waitFor(() => expect(find().getAttribute('title')).toBe('not-configured: device'));
    expect(find().hasAttribute('disabled')).toBe(true);
    expect(find().getAttribute('data-capability-enabled')).toBe('false');
    expect(sent.some((r) => r.path === '/api/v1/devices/count')).toBe(false);
    expect(screen.queryByText(/devices$/)).toBeNull();
  });
});
