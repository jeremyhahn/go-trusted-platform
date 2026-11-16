import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const { toast, deviceService, attestationService } = vi.hoisted(() => ({
  toast: vi.fn(),
  deviceService: { listDevices: vi.fn() },
  attestationService: { listDeviceReports: vi.fn() },
}));

vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast }) }));

// The page's data flow runs through the SDK's real useApi; only the
// services it calls are mocked.
vi.mock('@/hooks', async () => {
  const sdk = await import('trusted-platform-sdk');
  return {
    useApi: sdk.useApi,
    useDevice: () => deviceService,
    useAttestation: () => attestationService,
  };
});

type TableProps = {
  devices: unknown[];
  onDeviceChange: () => void;
  reports: Map<string, unknown>;
  reportsState: string;
};

vi.mock('@/components/features/devices/device-table', () => ({
  DeviceTable: ({ devices, onDeviceChange, reports, reportsState }: TableProps) => (
    <div data-testid="device-table">
      <span data-testid="reports-state">{reportsState}</span>
      <span data-testid="report-ids">{[...reports.keys()].join(',')}</span>
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

// Radix Select does not open in jsdom; a native select keeps the page's
// value / onValueChange contract testable.
vi.mock('@/components/ui/select', () => ({
  Select: ({ value, onValueChange, children }: { value: string; onValueChange: (v: string) => void; children: ReactNode }) => (
    <select data-testid="select" value={value} onChange={(e) => onValueChange(e.target.value)}>
      {children}
    </select>
  ),
  SelectTrigger: () => null,
  SelectValue: () => null,
  SelectContent: ({ children }: { children: ReactNode }) => <>{children}</>,
  SelectItem: ({ value, children }: { value: string; children: ReactNode }) => <option value={value}>{children}</option>,
}));

import DevicesPage from './page';

const fresh = () => new Date(Date.now() - 10_000).toISOString();
const stale = () => new Date(Date.now() - 60 * 60_000).toISOString();

function sdkDevices() {
  return [
    {
      id: 1,
      serial: 'node-a',
      model: 'SuperMicro X10',
      state: 'active',
      last_heartbeat_at: fresh(),
      created_at: '2026-01-01T00:00:00Z',
      attest_pub: 'pub',
      ek_cert: 'ek',
    },
    { id: 2, serial: '', model: 'Model-Only', state: 'active', last_heartbeat_at: stale(), created_at: '2026-01-02T00:00:00Z' },
    { id: 3, state: 'revoked', attest_pub: 'pub', attest_cert: 'ak' },
    { id: 4 },
  ];
}

type Row = {
  id: string;
  name: string;
  type: string;
  status: string;
  state?: string;
  serial?: string;
  model?: string;
  lastSeen?: string;
  registeredAt: string;
  tpm?: { manufacturer: string; version: string; firmwareVersion: string; hasEK: boolean; hasSRK: boolean; hasAKCert: boolean };
};

function rows(): Row[] {
  return screen.queryAllByTestId('device-row').map((li) => JSON.parse(li.textContent ?? '{}') as Row);
}

function names(): string[] {
  return rows().map((r) => r.name);
}

async function renderLoaded() {
  render(<DevicesPage />);
  await waitFor(() => expect(screen.getByTestId('device-table')).toBeTruthy());
  await waitFor(() => expect(screen.getByTestId('reports-state').textContent).not.toBe('loading'));
}

beforeEach(() => {
  toast.mockReset();
  deviceService.listDevices.mockReset();
  attestationService.listDeviceReports.mockReset();
  deviceService.listDevices.mockImplementation(() => Promise.resolve({ data: { devices: sdkDevices() } }));
  attestationService.listDeviceReports.mockImplementation(() =>
    Promise.resolve({ data: { reports: [{ device_id: 1 }, { device_id: 3 }] } }),
  );
});

afterEach(() => {
  cleanup();
});

describe('DevicesPage', () => {
  it('shows the loading state while the device list is pending', () => {
    deviceService.listDevices.mockImplementation(() => new Promise(() => {}));
    render(<DevicesPage />);
    expect(screen.getByText('Loading devices...')).toBeTruthy();
    expect(screen.queryByTestId('device-table')).toBeNull();
  });

  it('requests the first page of 100 devices', async () => {
    await renderLoaded();
    expect(deviceService.listDevices).toHaveBeenCalledWith({ page: 1, pageSize: 100 });
  });

  it('maps SDK devices to table rows', async () => {
    await renderLoaded();
    const [a, b, c, d] = rows();

    expect(a).toMatchObject({
      id: '1',
      name: 'node-a',
      type: 'physical',
      status: 'online',
      state: 'active',
      serial: 'node-a',
      model: 'SuperMicro X10',
      registeredAt: '2026-01-01T00:00:00Z',
      tpm: { manufacturer: 'SuperMicro X10', version: '2.0', firmwareVersion: '1.0', hasEK: true, hasSRK: false, hasAKCert: false },
    });
    expect(a.lastSeen).toBeTruthy();

    // No serial: the name falls back to the model; no attest key: no TPM.
    expect(b).toMatchObject({ id: '2', name: 'Model-Only', status: 'offline', model: 'Model-Only' });
    expect(b.serial).toBeUndefined();
    expect(b.tpm).toBeUndefined();

    // An enforcement state wins over a missing heartbeat.
    expect(c).toMatchObject({ id: '3', name: 'Unknown', status: 'disabled', state: 'revoked' });
    expect(c.tpm).toMatchObject({ manufacturer: 'Unknown', hasEK: false, hasAKCert: true });

    // A bare device: every optional field empty.
    expect(d).toMatchObject({ id: '4', name: 'Unknown', status: 'unknown', registeredAt: '' });
    expect(d.state).toBeUndefined();
    expect(d.lastSeen).toBeUndefined();
    expect(d.tpm).toBeUndefined();
  });

  it('renders an empty table when the response has no devices', async () => {
    deviceService.listDevices.mockImplementation(() => Promise.resolve({ data: {} }));
    await renderLoaded();
    expect(rows()).toHaveLength(0);
    expect(toast).not.toHaveBeenCalled();
  });

  it('toasts the API error message', async () => {
    deviceService.listDevices.mockImplementation(() => Promise.resolve({ error: { message: 'denied', status: 403 } }));
    await renderLoaded();
    expect(toast).toHaveBeenCalledWith({ title: 'Error', description: 'denied', variant: 'destructive' });
    expect(rows()).toHaveLength(0);
  });

  it('toasts the default message for an error without a message', async () => {
    deviceService.listDevices.mockImplementation(() => Promise.reject({ message: '' }));
    await renderLoaded();
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ description: 'Failed to fetch devices' }));
  });

  it('joins fleet reports by stringified device id', async () => {
    await renderLoaded();
    expect(screen.getByTestId('reports-state').textContent).toBe('ready');
    expect(screen.getByTestId('report-ids').textContent).toBe('1,3');
  });

  it('passes an empty report map when the reports response has none', async () => {
    attestationService.listDeviceReports.mockImplementation(() => Promise.resolve({ data: {} }));
    await renderLoaded();
    expect(screen.getByTestId('reports-state').textContent).toBe('ready');
    expect(screen.getByTestId('report-ids').textContent).toBe('');
  });

  it('reports not-configured on a 503 and error on any other failure', async () => {
    attestationService.listDeviceReports.mockImplementation(() => Promise.resolve({ error: { status: 503, message: 'x' } }));
    await renderLoaded();
    expect(screen.getByTestId('reports-state').textContent).toBe('not-configured');
    cleanup();

    attestationService.listDeviceReports.mockImplementation(() => Promise.resolve({ error: { status: 500, message: 'x' } }));
    await renderLoaded();
    expect(screen.getByTestId('reports-state').textContent).toBe('error');
  });

  it('filters by search on name, case-insensitively, and clears it', async () => {
    await renderLoaded();
    const input = screen.getByPlaceholderText('Search devices...') as HTMLInputElement;
    fireEvent.change(input, { target: { value: 'NODE' } });
    await waitFor(() => expect(names()).toEqual(['node-a']));
    fireEvent.change(input, { target: { value: 'model-only' } });
    await waitFor(() => expect(names()).toEqual(['Model-Only']));
    fireEvent.change(input, { target: { value: 'no-such-device' } });
    await waitFor(() => expect(rows()).toHaveLength(0));
    fireEvent.change(input, { target: { value: '' } });
    await waitFor(() => expect(rows()).toHaveLength(4));
    expect(screen.queryByText('Clear filters')).toBeNull();
  });

  it('filters by type: every SDK device is physical', async () => {
    await renderLoaded();
    const [type] = screen.getAllByTestId('select') as HTMLSelectElement[];
    fireEvent.change(type, { target: { value: 'virtual' } });
    await waitFor(() => expect(rows()).toHaveLength(0));
    fireEvent.change(type, { target: { value: 'physical' } });
    await waitFor(() => expect(rows()).toHaveLength(4));
    fireEvent.change(type, { target: { value: 'all' } });
    expect(type.value).toBe('all');
    expect(screen.queryByText('Clear filters')).toBeNull();
  });

  it('filters by derived status and Clear filters resets every filter', async () => {
    await renderLoaded();
    const status = screen.getAllByTestId('select')[1] as HTMLSelectElement;
    fireEvent.change(status, { target: { value: 'online' } });
    await waitFor(() => expect(names()).toEqual(['node-a']));
    fireEvent.change(status, { target: { value: 'disabled' } });
    await waitFor(() => expect(rows().map((r) => r.id)).toEqual(['3']));
    fireEvent.change(status, { target: { value: 'unknown' } });
    await waitFor(() => expect(rows().map((r) => r.id)).toEqual(['4']));

    fireEvent.click(screen.getByText('Clear filters'));
    await waitFor(() => expect(rows()).toHaveLength(4));
    expect(status.value).toBe('all');
    expect(screen.queryByText('Clear filters')).toBeNull();
  });

  it('refetches the devices when a filter changes', async () => {
    await renderLoaded();
    const before = deviceService.listDevices.mock.calls.length;
    fireEvent.change(screen.getByPlaceholderText('Search devices...'), { target: { value: 'n' } });
    await waitFor(() => expect(deviceService.listDevices.mock.calls.length).toBeGreaterThan(before));
  });

  it('refetches devices and reports when the table reports a change', async () => {
    await renderLoaded();
    const devicesBefore = deviceService.listDevices.mock.calls.length;
    const reportsBefore = attestationService.listDeviceReports.mock.calls.length;
    await act(async () => {
      fireEvent.click(screen.getByText('table-change'));
    });
    await waitFor(() => expect(deviceService.listDevices.mock.calls.length).toBe(devicesBefore + 1));
    expect(attestationService.listDeviceReports.mock.calls.length).toBe(reportsBefore + 1);
  });

  it('opens the register dialog and closes it on cancel without a refetch', async () => {
    await renderLoaded();
    expect(screen.queryByText('Register New Device')).toBeNull();
    fireEvent.click(screen.getByText('Register Device'));
    expect(screen.getByText('Register New Device')).toBeTruthy();
    const before = deviceService.listDevices.mock.calls.length;
    fireEvent.click(screen.getByText('form-cancel'));
    await waitFor(() => expect(screen.queryByText('Register New Device')).toBeNull());
    expect(deviceService.listDevices.mock.calls.length).toBe(before);
  });

  it('closes the dialog and refetches after a successful registration', async () => {
    await renderLoaded();
    fireEvent.click(screen.getByText('Register Device'));
    const before = deviceService.listDevices.mock.calls.length;
    await act(async () => {
      fireEvent.click(screen.getByText('form-success'));
    });
    await waitFor(() => expect(screen.queryByText('Register New Device')).toBeNull());
    await waitFor(() => expect(deviceService.listDevices.mock.calls.length).toBe(before + 1));
  });
});
