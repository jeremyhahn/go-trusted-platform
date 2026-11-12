import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { IDevIDForm } from './idevid-form';

const twoDevices = ok({
  devices: [
    { id: 7, serial: 'SN-7', state: 'active' },
    { id: 8, serial: '', state: 'pending' },
  ],
});

async function submit() {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Issue Certificate' }));
  });
}

describe('IDevIDForm', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('renders the fields with their defaults: 365 days and RSA with a key size', async () => {
    stubControlPlane({ 'GET /api/v1/devices': twoDevices });
    render(withControlPlane(<IDevIDForm />));

    expect((screen.getByLabelText('Validity Period (Days)') as HTMLInputElement).value).toBe('365');
    expect((screen.getByLabelText('Certificate Subject') as HTMLInputElement).value).toBe('');
    expect(screen.getByText('Key Size (bits)')).toBeDefined();
    expect(screen.queryByText('Curve')).toBeNull();
    expect(screen.getByRole('button', { name: 'Issue Certificate' })).toBeDefined();
  });

  it('lists the devices from the control plane', async () => {
    const sent = stubControlPlane({ 'GET /api/v1/devices': twoDevices });
    render(withControlPlane(<IDevIDForm />));

    await waitFor(() => expect(sent.some((r) => r.method === 'GET' && r.path === '/api/v1/devices')).toBe(true));
    const trigger = screen.getAllByRole('combobox')[0];
    await waitFor(() => expect(trigger.hasAttribute('disabled')).toBe(false));
  });

  it('shows a destructive toast when the device list is refused', async () => {
    stubControlPlane({ 'GET /api/v1/devices': refused(500, 'store down') });
    render(withControlPlane(<IDevIDForm />));

    const toast = await screen.findByText('Error: Failed to load devices');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    const trigger = screen.getAllByRole('combobox')[0];
    expect(trigger.hasAttribute('disabled')).toBe(false);
  });

  it('refuses to submit without a device and a subject, and sends nothing', async () => {
    const sent = stubControlPlane({ 'GET /api/v1/devices': twoDevices });
    render(withControlPlane(<IDevIDForm />));

    await submit();

    expect(await screen.findByText('Device is required')).toBeDefined();
    expect(screen.getByText('Subject is required')).toBeDefined();
    expect(sent.filter((r) => r.method !== 'GET')).toEqual([]);
  });

  it('refuses a validity below one day', async () => {
    stubControlPlane({ 'GET /api/v1/devices': twoDevices });
    render(withControlPlane(<IDevIDForm />));

    fireEvent.change(screen.getByLabelText('Validity Period (Days)'), { target: { value: '0' } });
    await submit();

    expect(await screen.findByText('Validity must be at least 1 day')).toBeDefined();
  });

  it('renders Cancel only with an onCancel handler, and calls it', () => {
    stubControlPlane({ 'GET /api/v1/devices': twoDevices });
    const onCancel = vi.fn();
    const { unmount } = render(withControlPlane(<IDevIDForm />));
    expect(screen.queryByRole('button', { name: 'Cancel' })).toBeNull();
    unmount();

    render(withControlPlane(<IDevIDForm onCancel={onCancel} />));
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(onCancel).toHaveBeenCalledTimes(1);
  });
});
