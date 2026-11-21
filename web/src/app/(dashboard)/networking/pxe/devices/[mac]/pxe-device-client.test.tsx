import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import PXEDeviceClient from './pxe-device-client';

// #2062: the PXE device page reads one device by MAC with its events, sets
// its state, marks it enrolled and starts or stops the PXE service, all
// through usePXEDeviceDetail on the real SDK client.

vi.mock('next/navigation', () => ({
  useParams: () => ({ mac: '02:00:00:00:00:01' }),
  usePathname: () => '/networking/pxe/devices/02:00:00:00:00:01',
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), back: vi.fn() }),
}));

const MAC_PATH = 'GET /api/v1/pxe/devices/mac/02%3A00%3A00%3A00%3A00%3A01';
const EVENTS_PATH = 'GET /api/v1/pxe/devices/dev-1/events';
const STATE_PATH = 'PUT /api/v1/pxe/devices/dev-1/state';
const ENROLLED_PATH = 'POST /api/v1/pxe/devices/dev-1/enrolled';

const DEVICE = ok({
  device: {
    id: 'dev-1',
    macAddress: '02:00:00:00:00:01',
    state: 'PROVISIONING_STATE_INSTALLING',
    stateReason: 'image fetched',
    currentVlan: 20,
    targetVlan: 30,
    retryCount: 1,
    createdAt: '2026-11-01T00:00:00Z',
    updatedAt: '2026-11-01T00:05:00Z',
  },
});

const EVENTS = ok({
  events: [
    {
      id: 'e1',
      deviceId: 'dev-1',
      timestamp: '2026-11-01T00:01:00Z',
      eventType: 'PXE_BOOT_STARTED',
      fromState: 'DISCOVERED',
      toState: 'BOOTING',
    },
    {
      id: 'e2',
      deviceId: 'dev-1',
      timestamp: '2026-11-01T00:04:00Z',
      eventType: 'INSTALL_STARTED',
      fromState: 'BOOTING',
      toState: 'INSTALLING',
      error: 'mirror slow',
    },
  ],
});

function stub(extra: Record<string, Answer> = {}) {
  return stubControlPlane({ [MAC_PATH]: DEVICE, [EVENTS_PATH]: EVENTS, ...extra });
}

async function renderPage() {
  render(withControlPlane(<PXEDeviceClient />));
  await screen.findByText('dev-1');
}

function count(sent: { method: string; path: string }[], key: string) {
  return sent.filter((r) => `${r.method} ${r.path}` === key).length;
}

describe('PXEDeviceClient', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('shows the device and its events newest first', async () => {
    stub();
    await renderPage();

    const device = screen.getByTestId('pxe-device');
    expect(within(device).getByText('dev-1')).toBeDefined();
    expect(within(device).getByText('Installing')).toBeDefined();
    expect(within(device).getByText('image fetched')).toBeDefined();
    expect(within(device).getByText('1')).toBeDefined();
    expect(within(screen.getByTestId('pxe-enrolled')).getByText('Not enrolled')).toBeDefined();

    const events = screen.getByTestId('pxe-events');
    await within(events).findByText('INSTALL_STARTED');
    const rows = within(events).getAllByRole('row').slice(1);
    expect(rows[0].textContent).toContain('INSTALL_STARTED');
    expect(rows[0].textContent).toContain('mirror slow');
    expect(rows[1].textContent).toContain('PXE_BOOT_STARTED');
    expect(rows[1].textContent).toContain('Booting');
  });

  it('sets the state with a reason', async () => {
    const sent = stub({ [STATE_PATH]: ok({ status: { success: true } }) });
    await renderPage();

    fireEvent.change(screen.getByLabelText('State'), { target: { value: 'FAILED' } });
    fireEvent.change(screen.getByLabelText('Reason'), { target: { value: 'operator stop' } });
    fireEvent.click(screen.getByRole('button', { name: 'Set state' }));

    await screen.findByText(/State updated/);
    const put = sent.find((r) => `${r.method} ${r.path}` === STATE_PATH);
    expect(put?.body).toEqual({ state: 'PROVISIONING_STATE_FAILED', reason: 'operator stop' });
    await waitFor(() => expect(count(sent, MAC_PATH)).toBe(2));
  });

  it('marks the device enrolled', async () => {
    const sent = stub({ [ENROLLED_PATH]: ok({ status: { success: true } }) });
    await renderPage();

    const button = screen.getByRole('button', { name: 'Mark enrolled' }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    fireEvent.change(screen.getByLabelText('Certificate serial'), { target: { value: 'ab12cd' } });
    expect(button.disabled).toBe(false);
    fireEvent.click(button);

    await screen.findByText(/Device enrolled/);
    const post = sent.find((r) => `${r.method} ${r.path}` === ENROLLED_PATH);
    expect(post?.body).toEqual({ certificateSerial: 'ab12cd' });
  });

  it('starts and stops the PXE service', async () => {
    const sent = stub({
      'POST /api/v1/pxe/start': ok({ status: { success: true } }),
      'POST /api/v1/pxe/stop': ok({ status: { success: true } }),
    });
    await renderPage();

    fireEvent.click(screen.getByRole('button', { name: 'Start PXE service' }));
    await screen.findByText(/PXE service started/);
    fireEvent.click(screen.getByRole('button', { name: 'Stop PXE service' }));
    await screen.findByText(/PXE service stopped/);

    expect(count(sent, 'POST /api/v1/pxe/start')).toBe(1);
    expect(count(sent, 'POST /api/v1/pxe/stop')).toBe(1);
  });

  it('toasts a refused state change', async () => {
    stub({ [STATE_PATH]: refused(409, 'pxe: transition INSTALLING -> ENROLLED not allowed') });
    await renderPage();

    fireEvent.change(screen.getByLabelText('State'), { target: { value: 'ENROLLED' } });
    fireEvent.click(screen.getByRole('button', { name: 'Set state' }));

    const toast = await screen.findByText(/pxe: transition INSTALLING -> ENROLLED not allowed/);
    expect(toast.getAttribute('data-variant')).toBe('destructive');
  });

  it('shows a refused device read', async () => {
    const sent = stub({ [MAC_PATH]: refused(404, 'pxe: device not found') });
    render(withControlPlane(<PXEDeviceClient />));

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('pxe: device not found');
    expect(screen.queryByTestId('pxe-state')).toBeNull();
    expect(count(sent, EVENTS_PATH)).toBe(0);
  });

  it('shows a refused events read', async () => {
    stub({ [EVENTS_PATH]: refused(403, 'pxe: read scope required') });
    await renderPage();

    expect(screen.getByTestId('pxe-device')).toBeDefined();
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('pxe: read scope required');
  });
});
