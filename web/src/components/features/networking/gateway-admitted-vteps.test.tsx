import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';

import { GatewayAdmittedVTEPs, type GatewayOverlay } from './gateway-admitted-vteps';

// The overlay section renders what the gateway's telemetry snapshot reported
// (#2051): the VTEPs it admitted, each with its full admission record. A
// field the gateway did not report shows '-', never "undefined" or 0.

function overlay(overrides: Partial<GatewayOverlay> = {}): GatewayOverlay {
  return {
    running: true,
    local_vtep: '192.0.2.1',
    vni_count: 3,
    remote_vtep_count: 2,
    refused_bindings: 1,
    admitted_vteps: [
      {
        vtep: '192.0.2.10',
        device_id: 7,
        hostname: 'host-a.example.test',
        serial: 'SN-0001',
        baseline_source: 'golden',
        profile_id: 2,
        verdict_at: '2026-11-21T10:00:00Z',
      },
      { vtep: '192.0.2.11', host_id: 'h-2' },
    ],
    nd_counters: { punted: 0, answered: 0 },
    ...overrides,
  };
}

describe('GatewayAdmittedVTEPs', () => {
  afterEach(() => cleanup());

  it('lists each admitted VTEP', () => {
    render(<GatewayAdmittedVTEPs overlay={overlay()} />);

    const rows = screen.getAllByTestId('gateway-admitted-vtep-row');
    expect(rows).toHaveLength(2);
    expect(within(rows[0]).getByText('192.0.2.10')).toBeDefined();
    expect(within(rows[0]).getByText('host-a.example.test')).toBeDefined();
    expect(within(rows[1]).getByText('192.0.2.11')).toBeDefined();
    // No hostname: the host id stands in; no serial: '-'.
    expect(within(rows[1]).getByText('h-2')).toBeDefined();
    expect(within(rows[1]).getAllByText('-').length).toBeGreaterThan(0);
    expect(rows[1].textContent).not.toContain('undefined');
  });

  it('shows the overlay summary', () => {
    render(<GatewayAdmittedVTEPs overlay={overlay()} />);

    const summary = screen.getByTestId('gateway-overlay-summary');
    expect(within(summary).getByText('192.0.2.1')).toBeDefined();
    expect(within(summary).getByText('VNIs').nextSibling?.textContent).toBe('3');
    expect(within(summary).getByText('Remote VTEPs').nextSibling?.textContent).toBe('2');
    expect(within(summary).getByText('Refused bindings').nextSibling?.textContent).toBe('1');
    expect(screen.getByText('Running')).toBeDefined();
  });

  it('says no VTEP is admitted when the list is empty', () => {
    render(<GatewayAdmittedVTEPs overlay={overlay({ admitted_vteps: undefined })} />);

    expect(screen.getByText('No VTEP is admitted')).toBeDefined();
    expect(screen.queryAllByTestId('gateway-admitted-vtep-row')).toHaveLength(0);
  });

  it('opens one VTEP with every field it reported', () => {
    render(<GatewayAdmittedVTEPs overlay={overlay()} />);

    expect(screen.queryByTestId('gateway-admitted-vtep-detail')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Details 192.0.2.10' }));

    const detail = screen.getByTestId('gateway-admitted-vtep-detail');
    const field = (label: string) =>
      within(detail).getByText(label).nextSibling?.textContent;
    expect(field('Device')).toBe('7');
    expect(field('Serial')).toBe('SN-0001');
    expect(field('Baseline')).toBe('golden');
    expect(field('Profile')).toBe('2');
    expect(field('Verdict at')).toBe('2026-11-21T10:00:00Z');

    fireEvent.click(within(detail).getByRole('button', { name: 'Close' }));
    expect(screen.queryByTestId('gateway-admitted-vtep-detail')).toBeNull();

    // A VTEP that reported only its address and host id.
    fireEvent.click(screen.getByRole('button', { name: 'Details 192.0.2.11' }));
    const sparse = screen.getByTestId('gateway-admitted-vtep-detail');
    const sparseField = (label: string) =>
      within(sparse).getByText(label).nextSibling?.textContent;
    expect(sparseField('Host ID')).toBe('h-2');
    for (const label of ['Device', 'Serial', 'Hostname', 'Allocation', 'Baseline', 'Profile', 'Verdict at']) {
      expect(sparseField(label)).toBe('-');
    }
    expect(sparse.textContent).not.toContain('undefined');
  });

  it('marks a stopped overlay', () => {
    render(<GatewayAdmittedVTEPs overlay={overlay({ running: false })} />);

    expect(screen.getByText('Stopped')).toBeDefined();
    expect(screen.queryByText('Running')).toBeNull();
  });
});
