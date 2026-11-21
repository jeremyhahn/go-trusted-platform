import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { ProfileLookupCard } from './profile-lookup-card';

const MATCH_KEY = 'POST /api/v1/device/profiles/match';

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

describe('ProfileLookupCard match', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('matches on all three fields', async () => {
    const sent = stubControlPlane({ [MATCH_KEY]: ok(baseProfile) });
    render(withControlPlane(<ProfileLookupCard />));

    fireEvent.change(screen.getByLabelText('MAC address'), { target: { value: 'aa:bb:cc:dd:ee:ff' } });
    fireEvent.change(screen.getByLabelText('Serial number'), { target: { value: 'SN-1' } });
    fireEvent.change(screen.getByLabelText('Model'), { target: { value: 'rpi4' } });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Match' }));
    });

    const result = await screen.findByTestId('profile-lookup-result');
    expect(sent).toHaveLength(1);
    expect(sent[0].method).toBe('POST');
    expect(sent[0].body).toEqual({ mac_address: 'aa:bb:cc:dd:ee:ff', serial: 'SN-1', model: 'rpi4' });
    expect(result.textContent).toContain('edge-node');
  });

  it('sends only the fields given', async () => {
    const sent = stubControlPlane({ [MATCH_KEY]: ok(baseProfile) });
    render(withControlPlane(<ProfileLookupCard />));

    fireEvent.change(screen.getByLabelText('Model'), { target: { value: ' rpi4 ' } });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Match' }));
    });

    await screen.findByTestId('profile-lookup-result');
    expect(sent).toHaveLength(1);
    expect(sent[0].body).toEqual({ model: 'rpi4' });
  });

  it('shows a match refusal verbatim', async () => {
    stubControlPlane({ [MATCH_KEY]: refused(404, 'no matching profile found') });
    render(withControlPlane(<ProfileLookupCard />));

    fireEvent.change(screen.getByLabelText('Model'), { target: { value: 'rpi4' } });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Match' }));
    });

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('no matching profile found');
  });

  it('refuses empty criteria without a request', async () => {
    const sent = stubControlPlane({});
    render(withControlPlane(<ProfileLookupCard />));

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Match' }));
    });

    const toast = await screen.findByText('Match criteria required: enter a MAC address, serial or model');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(sent).toHaveLength(0);
  });
});
