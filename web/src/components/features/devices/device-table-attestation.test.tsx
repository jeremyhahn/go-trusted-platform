import type { ReactNode } from 'react';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { DeviceReport } from 'trusted-platform-sdk';

import { stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import type { Answer } from '@/test/control-plane-fetch';
import type { Device, TPMInfo } from '@/types/device';
import { DeviceTable } from './device-table';

// #2035 (Codex round 3 on #2341): the fleet table's Attestation column for
// collected reports, which the real-server harness cannot produce: each
// verdict beside its age, never collected as neither green nor red, the
// unsynced-clock flag on its own row, a node without the reporting service,
// and the row menu's Refresh attestation re-reading the fleet.

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

// Opening a Radix menu in jsdom costs tens of seconds, so the row menu
// renders its items inline. The item's onClick and disabled state are the
// table's own; only the popup machinery is replaced.
vi.mock('@/components/ui/dropdown-menu', () => ({
  DropdownMenu: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DropdownMenuTrigger: ({ children }: { children: ReactNode }) => <>{children}</>,
  DropdownMenuContent: ({ children }: { children: ReactNode }) => <div role="menu">{children}</div>,
  DropdownMenuLabel: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DropdownMenuSeparator: () => <hr />,
  DropdownMenuItem: ({
    children,
    disabled,
    title,
    onClick,
  }: {
    children: ReactNode;
    disabled?: boolean;
    title?: string;
    onClick?: () => void;
  }) => (
    <div role="menuitem" aria-disabled={disabled} title={title} onClick={disabled ? undefined : onClick}>
      {children}
    </div>
  ),
}));

const tpm: TPMInfo = {
  manufacturer: 'Example TPM',
  version: '2.0',
  firmwareVersion: '1.0',
  hasEK: true,
  hasSRK: true,
  hasAKCert: true,
};

function device(overrides: Partial<Device> = {}): Device {
  return {
    id: '7',
    name: 'node-07',
    type: 'physical',
    status: 'online',
    state: 'attested',
    registeredAt: '2026-10-01T00:00:00Z',
    ...overrides,
  };
}

function report(overrides: Partial<DeviceReport> = {}): DeviceReport {
  return {
    device_id: '7',
    verified: true,
    ak_certificate_verified: true,
    signature_valid: true,
    nonce_valid: true,
    pcrs_valid: true,
    cryptographic_failure: false,
    pcr_baseline_source: 'signed',
    pcr_baseline_captured: false,
    status: 'attested',
    attested_at: '2026-11-01T11:58:00Z',
    collected_at: '2026-11-01T11:58:00Z',
    fresh: true,
    age_seconds: 120,
    as_of: '2026-11-01T12:00:00Z',
    ...overrides,
  };
}

const accepted: Answer = { status: 202, body: { code: 202, success: true, payload: { enqueued: true } } };

function row(name: string) {
  return within(screen.getByRole('row', { name: new RegExp(name) }));
}

describe('DeviceTable Attestation column', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('every row shows its verdict beside its age; never collected is neither green nor red', () => {
    stubControlPlane({});
    const devices = [
      device({ id: '1', name: 'Fresh-Pass' }),
      device({ id: '2', name: 'Stale-Pass' }),
      device({ id: '3', name: 'Crypto-Fail' }),
      device({ id: '4', name: 'Never-Collected' }),
    ];
    const reports = new Map<string, DeviceReport>([
      ['1', report({ device_id: '1', time_synced: true })],
      ['2', report({ device_id: '2', fresh: false, age_seconds: 7200 })],
      [
        '3',
        report({
          device_id: '3',
          verified: false,
          pcrs_valid: false,
          cryptographic_failure: true,
          message: 'PCR 7 does not match the profile baseline',
        }),
      ],
    ]);
    render(withControlPlane(<DeviceTable devices={devices} reports={reports} reportsState="ready" />));

    const fresh = row('Fresh-Pass').getByTestId('fleet-report');
    expect(fresh.textContent).toContain('Verified');
    expect(fresh.textContent).toContain('old');
    expect(fresh.getAttribute('data-fresh')).toBe('true');
    expect(row('Fresh-Pass').queryByTestId('fleet-clock-unsynced')).toBeNull();

    const stale = row('Stale-Pass').getByTestId('fleet-report');
    expect(stale.textContent).toContain('stale');
    expect(stale.textContent).toContain('2 hours');
    expect(stale.getAttribute('data-fresh')).toBe('false');

    expect(row('Crypto-Fail').getByTestId('fleet-report').textContent).toContain('Failed');

    expect(row('Never-Collected').getByTestId('fleet-never-collected').textContent).toBe('Never collected');
    expect(row('Never-Collected').queryByTestId('fleet-report')).toBeNull();
  });

  it('flags an unsynced clock only on that row', () => {
    stubControlPlane({});
    const devices = [device({ id: '1', name: 'Clock-Off' }), device({ id: '2', name: 'Clock-On' })];
    const reports = new Map<string, DeviceReport>([
      ['1', report({ device_id: '1', time_synced: false })],
      ['2', report({ device_id: '2', time_synced: true })],
    ]);
    render(withControlPlane(<DeviceTable devices={devices} reports={reports} reportsState="ready" />));

    expect(row('Clock-Off').getByTestId('fleet-clock-unsynced').textContent).toBe('Clock unsynced');
    expect(row('Clock-On').queryByTestId('fleet-clock-unsynced')).toBeNull();
  });

  it('a node without the reporting service says so on every row and disables Refresh', () => {
    stubControlPlane({});
    const devices = [device({ id: '1', name: 'Node-A', tpm }), device({ id: '2', name: 'Node-B', tpm })];
    render(withControlPlane(<DeviceTable devices={devices} reports={new Map()} reportsState="not-configured" />));

    for (const name of ['Node-A', 'Node-B']) {
      expect(row(name).getByText('Reporting not configured')).toBeDefined();
      expect(row(name).queryByTestId('fleet-never-collected')).toBeNull();
      expect(row(name).getByRole('menuitem', { name: 'Refresh attestation' }).getAttribute('aria-disabled')).toBe(
        'true'
      );
    }
  });

  it('Refresh attestation from the row menu enqueues and re-reads the fleet', async () => {
    const sent = stubControlPlane({ 'POST /api/v1/attestation/reports/7/refresh': accepted });
    const onDeviceChange = vi.fn();
    render(
      withControlPlane(
        <DeviceTable
          devices={[device({ tpm })]}
          reports={new Map([['7', report({ fresh: false, age_seconds: 10800 })]])}
          reportsState="ready"
          onDeviceChange={onDeviceChange}
        />
      )
    );

    await act(async () => {
      fireEvent.click(screen.getByRole('menuitem', { name: 'Refresh attestation' }));
    });

    await waitFor(() => expect(onDeviceChange).toHaveBeenCalledTimes(1));
    expect(sent.some((r) => r.method === 'POST' && r.path === '/api/v1/attestation/reports/7/refresh')).toBe(true);
    expect(await screen.findByText(/^Collection enqueued/)).toBeDefined();
  });
});
