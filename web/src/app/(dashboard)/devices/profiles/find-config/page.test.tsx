import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import FindDeviceConfigPage from './page';

vi.mock('next/navigation', () => ({
  usePathname: () => '/devices/profiles/find-config',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

const ROUTE = 'GET /api/v1/device/profiles/find-config';

const PROFILE = ok({
  id: '12',
  name: 'edge-gw',
  role: 'gateway',
  ek_serial: 'EK-1',
  mac_address: 'aa:bb:cc:dd:ee:ff',
  assigned: true,
  created_at: '2026-11-20T00:00:00Z',
  updated_at: '2026-11-20T00:00:00Z',
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

async function findByEKSerial(ekSerial: string) {
  render(withControlPlane(<FindDeviceConfigPage />));
  fireEvent.change(screen.getByLabelText('EK serial'), { target: { value: ekSerial } });
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Find config' }));
  });
}

describe('FindDeviceConfigPage', () => {
  it('keeps Find config disabled until an identity is typed', () => {
    stubControlPlane({ [ROUTE]: PROFILE });
    render(withControlPlane(<FindDeviceConfigPage />));

    const button = screen.getByRole('button', { name: 'Find config' });
    expect((button as HTMLButtonElement).disabled).toBe(true);

    fireEvent.change(screen.getByLabelText('MAC address'), { target: { value: 'aa:bb:cc:dd:ee:ff' } });
    expect((button as HTMLButtonElement).disabled).toBe(false);
  });

  it('shows the matched profile', async () => {
    stubControlPlane({ [ROUTE]: PROFILE });
    await findByEKSerial('EK-1');

    await screen.findByText('edge-gw');
    expect(screen.getByText('Assigned')).toBeTruthy();
    expect(screen.getByText('Profile ID 12')).toBeTruthy();
  });

  it('says no profile matches on a 404', async () => {
    stubControlPlane({ [ROUTE]: refused(404, 'no matching config') });
    await findByEKSerial('EK-9');

    await screen.findByText('No profile matches this device.');
  });

  it('shows a refusal on a 403', async () => {
    stubControlPlane({ [ROUTE]: refused(403, 'forbidden') });
    await findByEKSerial('EK-1');

    expect((await screen.findByRole('alert')).textContent).toBe('Lookup refused: forbidden');
  });
});
