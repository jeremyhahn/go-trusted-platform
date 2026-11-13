import type { ReactNode } from 'react';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { IDevIDForm } from './idevid-form';

// Radix Select does not open in jsdom; a native select drives the same props.
vi.mock('@/components/ui/select', () => ({
  Select: ({
    children,
    onValueChange,
    defaultValue,
    disabled,
  }: {
    children: ReactNode;
    onValueChange: (value: string) => void;
    defaultValue?: string;
    disabled?: boolean;
  }) => (
    <select defaultValue={defaultValue} disabled={disabled} onChange={(e) => onValueChange(e.target.value)}>
      <option value="" />
      {children}
    </select>
  ),
  SelectTrigger: () => null,
  SelectValue: () => null,
  SelectContent: ({ children }: { children: ReactNode }) => <>{children}</>,
  SelectItem: ({ children, value }: { children: ReactNode; value: string }) => <option value={value}>{children}</option>,
}));

const csr = ok({ csr: 'CSR-PEM' });

async function pickDevice(id: string) {
  const device = screen.getAllByRole('combobox')[0];
  await waitFor(() => expect(device.hasAttribute('disabled')).toBe(false));
  await waitFor(() => expect(screen.getByRole('option', { name: 'SN-7' })).toBeDefined());
  fireEvent.change(device, { target: { value: id } });
}

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
    stubControlPlane({ 'GET /api/v1/devices': refused(403, 'admin role required') });
    render(withControlPlane(<IDevIDForm />));

    const toast = await screen.findByText('Error: Failed to load devices', undefined, { timeout: 4000 });
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
    const sent = stubControlPlane({ 'GET /api/v1/devices': twoDevices });
    render(withControlPlane(<IDevIDForm />));

    const validity = screen.getByLabelText('Validity Period (Days)') as HTMLInputElement;
    fireEvent.change(validity, { target: { value: '0' } });
    // The browser's own range check stops the submit button first.
    expect(validity.validity.rangeUnderflow).toBe(true);
    await act(async () => {
      fireEvent.submit(validity.form as HTMLFormElement);
    });

    expect(await screen.findByText('Validity must be at least 1 day')).toBeDefined();
    expect(sent.filter((r) => r.method !== 'GET')).toEqual([]);
  });

  it('refuses a validity above ten years', async () => {
    stubControlPlane({ 'GET /api/v1/devices': twoDevices });
    render(withControlPlane(<IDevIDForm />));

    const validity = screen.getByLabelText('Validity Period (Days)') as HTMLInputElement;
    fireEvent.change(validity, { target: { value: '3651' } });
    expect(validity.validity.rangeOverflow).toBe(true);
    await act(async () => {
      fireEvent.submit(validity.form as HTMLFormElement);
    });

    expect(validity.getAttribute('aria-invalid')).toBe('true');
  });

  it('fills the subject from the device serial, or its id when the serial is empty', async () => {
    stubControlPlane({ 'GET /api/v1/devices': twoDevices });
    render(withControlPlane(<IDevIDForm />));
    const subject = screen.getByLabelText('Certificate Subject') as HTMLInputElement;

    await pickDevice('7');
    expect(subject.value).toBe('CN=SN-7');
    await pickDevice('8');
    expect(subject.value).toBe('CN=8');
  });

  it('generates an RSA key, then posts the CSR with the subject, and reports success', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/devices': twoDevices,
      'POST /api/v1/idevid/generate': ok({}),
      'POST /api/v1/idevid/csr': csr,
    });
    const onSuccess = vi.fn();
    render(withControlPlane(<IDevIDForm onSuccess={onSuccess} />));

    await pickDevice('7');
    await submit();

    await waitFor(() => expect(onSuccess).toHaveBeenCalledTimes(1));
    expect(sent.filter((r) => r.method === 'POST')).toEqual([
      { method: 'POST', path: '/api/v1/idevid/generate', body: { config: { algorithm: 'RSA_2048', hierarchy: 'endorsement' } } },
      { method: 'POST', path: '/api/v1/idevid/csr', body: { template: { commonName: 'CN=SN-7' } } },
    ]);
    expect(screen.getByText('Success: IDevID certificate issued successfully')).toBeDefined();
    expect((screen.getByLabelText('Certificate Subject') as HTMLInputElement).value).toBe('');
  });

  it('offers curves for ECC and generates an ECDSA P-256 key', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/devices': twoDevices,
      'POST /api/v1/idevid/generate': ok({}),
      'POST /api/v1/idevid/csr': csr,
    });
    const onSuccess = vi.fn();
    render(withControlPlane(<IDevIDForm onSuccess={onSuccess} />));

    await pickDevice('7');
    fireEvent.change(screen.getAllByRole('combobox')[1], { target: { value: 'ECC' } });
    expect(await screen.findByText('Curve')).toBeDefined();
    expect(screen.queryByText('Key Size (bits)')).toBeNull();
    expect(screen.getByRole('option', { name: 'P-384 (NIST)' })).toBeDefined();
    await submit();

    await waitFor(() => expect(onSuccess).toHaveBeenCalledTimes(1));
    expect(sent.find((r) => r.path === '/api/v1/idevid/generate')?.body).toEqual({
      config: { algorithm: 'ECDSA_P256', hierarchy: 'endorsement' },
    });
  });

  it('stops at a refused key generation: no CSR, the REST reason shown', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/devices': twoDevices,
      'POST /api/v1/idevid/generate': refused(409, 'IDevID key already exists'),
      'POST /api/v1/idevid/csr': csr,
    });
    const onSuccess = vi.fn();
    render(withControlPlane(<IDevIDForm onSuccess={onSuccess} />));

    await pickDevice('7');
    await submit();

    const toast = await screen.findByText('Error: IDevID key already exists');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(sent.some((r) => r.path === '/api/v1/idevid/csr')).toBe(false);
    expect(onSuccess).not.toHaveBeenCalled();
  });

  it('shows a refused CSR with its REST reason', async () => {
    stubControlPlane({
      'GET /api/v1/devices': twoDevices,
      'POST /api/v1/idevid/generate': ok({}),
      'POST /api/v1/idevid/csr': refused(400, 'subject is not a distinguished name'),
    });
    const onSuccess = vi.fn();
    render(withControlPlane(<IDevIDForm onSuccess={onSuccess} />));

    await pickDevice('7');
    await submit();

    expect(await screen.findByText('Error: subject is not a distinguished name')).toBeDefined();
    expect(onSuccess).not.toHaveBeenCalled();
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
