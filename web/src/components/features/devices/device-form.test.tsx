import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { DeviceForm } from './device-form';

const created = ok({ device: { id: 9, serial: 'SN-1', state: 'pending' } });

async function register(serial: string) {
  fireEvent.change(screen.getByLabelText('Serial Number'), { target: { value: serial } });
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Register Device' }));
  });
}

describe('DeviceForm', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('has no name field: a device carries no display name (#455)', () => {
    stubControlPlane({});
    render(withControlPlane(<DeviceForm />));

    expect(screen.queryByLabelText('Device Name')).toBeNull();
    expect(screen.queryByPlaceholderText('my-device')).toBeNull();
    expect(screen.getByLabelText('Serial Number')).toBeDefined();
  });

  it('collects only the serial: the create contract stores no type, description or TPM details (#455)', () => {
    stubControlPlane({});
    render(withControlPlane(<DeviceForm />));

    for (const label of [
      'Device Type',
      'Description (Optional)',
      'TPM Manufacturer',
      'TPM Version',
      'Firmware Version',
    ]) {
      expect(screen.queryByLabelText(label)).toBeNull();
    }
    expect(screen.queryByText('TPM Information (Optional)')).toBeNull();
    expect(screen.queryByRole('combobox')).toBeNull();
    expect(screen.getAllByRole('textbox').map((input) => input.getAttribute('name'))).toEqual(['serial']);
  });

  it('posts exactly the serial in the CreateDeviceRequest envelope REST decodes', async () => {
    const sent = stubControlPlane({ 'POST /api/v1/devices': created });
    const onSuccess = vi.fn();
    render(withControlPlane(<DeviceForm onSuccess={onSuccess} />));

    await register('  SN-1 ');

    await waitFor(() => expect(onSuccess).toHaveBeenCalledTimes(1));
    expect(sent).toEqual([{ method: 'POST', path: '/api/v1/devices', body: { device: { serial: 'SN-1' } } }]);
    expect(screen.getByText('Success: Device registered successfully')).toBeDefined();
  });

  it('sends nothing without a serial', async () => {
    const sent = stubControlPlane({ 'POST /api/v1/devices': created });
    render(withControlPlane(<DeviceForm />));

    await register('   ');

    expect(await screen.findByText('Serial number is required')).toBeDefined();
    expect(sent).toEqual([]);
  });

  it('shows the REST refusal to the operator instead of swallowing it', async () => {
    stubControlPlane({
      'POST /api/v1/devices': refused(409, 'device with serial SN-1 already exists'),
    });
    const onSuccess = vi.fn();
    render(withControlPlane(<DeviceForm onSuccess={onSuccess} />));

    await register('SN-1');

    const toast = await screen.findByText('Error: device with serial SN-1 already exists');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(onSuccess).not.toHaveBeenCalled();
  });
});
