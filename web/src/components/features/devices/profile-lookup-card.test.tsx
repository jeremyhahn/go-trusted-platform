import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { ProfileLookupCard } from './profile-lookup-card';

const MAC_PATH = '/api/v1/device/profiles/mac/aa%3Abb%3Acc%3Add%3Aee%3Aff';
const SERIAL_PATH = '/api/v1/device/profiles/serial/SN-1';

const baseProfile = {
  id: '42',
  name: 'edge-node',
  model: 'rpi4',
  role: 'worker',
  mac_address: 'aa:bb:cc:dd:ee:ff',
  ek_serial: '0a1b',
  enrollment_network: 'provisioning',
  post_enrollment_network: 'production',
  assigned: true,
};

describe('ProfileLookupCard', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('finds a profile by MAC', async () => {
    const sent = stubControlPlane({ [`GET ${MAC_PATH}`]: ok(baseProfile) });
    render(withControlPlane(<ProfileLookupCard />));

    fireEvent.change(screen.getByLabelText('MAC address'), { target: { value: 'aa:bb:cc:dd:ee:ff' } });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Find by MAC' }));
    });

    const result = await screen.findByTestId('profile-lookup-result');
    expect(sent).toHaveLength(1);
    expect(sent[0]).toMatchObject({ method: 'GET', path: MAC_PATH });
    expect(result.textContent).toContain('edge-node');
    expect(result.textContent).toContain('42');
    expect(result.textContent).toContain('rpi4');
    expect(result.textContent).toContain('provisioning');
    expect(screen.getByTestId('profile-lookup-assigned').textContent).toBe('Assigned');
  });

  it('finds a profile by serial', async () => {
    const sent = stubControlPlane({ [`GET ${SERIAL_PATH}`]: ok({ ...baseProfile, assigned: false }) });
    render(withControlPlane(<ProfileLookupCard />));

    fireEvent.change(screen.getByLabelText('Serial number'), { target: { value: 'SN-1' } });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Find by serial' }));
    });

    await screen.findByTestId('profile-lookup-result');
    expect(sent).toHaveLength(1);
    expect(sent[0]).toMatchObject({ method: 'GET', path: SERIAL_PATH });
    expect(screen.getByTestId('profile-lookup-assigned').textContent).toBe('Unassigned');
  });

  it('shows a not-found refusal verbatim', async () => {
    stubControlPlane({ [`GET ${SERIAL_PATH}`]: refused(404, 'profile not found for serial SN-1') });
    render(withControlPlane(<ProfileLookupCard />));

    fireEvent.change(screen.getByLabelText('Serial number'), { target: { value: 'SN-1' } });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Find by serial' }));
    });

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('profile not found for serial SN-1');
    expect(screen.queryByTestId('profile-lookup-result')).toBeNull();
  });

  it('refuses a blank MAC without a request', async () => {
    const sent = stubControlPlane({});
    render(withControlPlane(<ProfileLookupCard />));

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Find by MAC' }));
    });

    const toast = await screen.findByText('MAC address required: enter a value to look up');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(sent).toHaveLength(0);
  });

  it('refuses a blank serial without a request', async () => {
    const sent = stubControlPlane({});
    render(withControlPlane(<ProfileLookupCard />));

    fireEvent.change(screen.getByLabelText('Serial number'), { target: { value: '   ' } });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Find by serial' }));
    });

    const toast = await screen.findByText('Serial number required: enter a value to look up');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(sent).toHaveLength(0);
  });
});
