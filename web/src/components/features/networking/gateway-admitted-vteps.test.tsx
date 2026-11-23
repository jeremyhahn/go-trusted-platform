import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { GatewayAdmittedVTEPs, type GatewayAdmittedVTEP, type GatewayOverlay } from './gateway-admitted-vteps';

// The overlay section renders what the gateway's telemetry snapshot reported
// (#2051): the VTEPs it admitted, each with its full admission record. A
// field the gateway did not report shows '-', never "undefined" or 0.
// Refresh lists the VTEPs again and Details reads one through the SDK
// (useGatewayAdmittedVTEPs), each behind the capability gate of its route.

const LIST_OP = 'GET /api/v1/gateway/state/{id}/admitted-vteps';
const GET_OP = 'GET /api/v1/gateway/state/{id}/admitted-vteps/{vtep}';

const { off, hook } = vi.hoisted(() => ({
  off: new Set<string>(),
  hook: {
    vteps: [] as unknown[],
    isLoading: false,
    error: null as string | null,
    refetch: (() => Promise.resolve()) as () => Promise<void>,
    get: ((_vtep: string) => Promise.reject(new Error('unset'))) as (vtep: string) => Promise<unknown>,
    calls: [] as unknown[][],
  },
}));

vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({
    loading: false,
    error: undefined,
    capability: (op: string) =>
      off.has(op) ? { enabled: false, reason: 'not-configured: gateway' } : { enabled: true },
  }),
}));

vi.mock('@/hooks/use-gateway-admitted-vteps', () => ({
  useGatewayAdmittedVTEPs: (...args: unknown[]) => {
    hook.calls.push(args);
    return hook;
  },
}));

function answerGet(list: GatewayAdmittedVTEP[]) {
  hook.get = vi.fn((vtep: string) => {
    const found = list.find((v) => v.vtep === vtep);
    return found ? Promise.resolve(found) : Promise.reject(new Error('HTTP 404: vtep not admitted'));
  });
}

beforeEach(() => {
  off.clear();
  hook.vteps = [];
  hook.error = null;
  hook.calls = [];
  hook.refetch = vi.fn(() => Promise.resolve());
  answerGet(overlay().admitted_vteps ?? []);
});

function button(name: string): HTMLButtonElement {
  return screen.getByRole('button', { name }) as HTMLButtonElement;
}

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
    render(<GatewayAdmittedVTEPs gatewayId="gw-1" overlay={overlay()} />);

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
    render(<GatewayAdmittedVTEPs gatewayId="gw-1" overlay={overlay()} />);

    const summary = screen.getByTestId('gateway-overlay-summary');
    expect(within(summary).getByText('192.0.2.1')).toBeDefined();
    expect(within(summary).getByText('VNIs').nextSibling?.textContent).toBe('3');
    expect(within(summary).getByText('Remote VTEPs').nextSibling?.textContent).toBe('2');
    expect(within(summary).getByText('Refused bindings').nextSibling?.textContent).toBe('1');
    expect(screen.getByText('Running')).toBeDefined();
  });

  it('says no VTEP is admitted when the list is empty', () => {
    render(<GatewayAdmittedVTEPs gatewayId="gw-1" overlay={overlay({ admitted_vteps: undefined })} />);

    expect(screen.getByText('No VTEP is admitted')).toBeDefined();
    expect(screen.queryAllByTestId('gateway-admitted-vtep-row')).toHaveLength(0);
  });

  it('opens one VTEP with every field it reported', async () => {
    render(<GatewayAdmittedVTEPs gatewayId="gw-1" overlay={overlay()} />);

    expect(screen.queryByTestId('gateway-admitted-vtep-detail')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Details 192.0.2.10' }));

    const detail = await screen.findByTestId('gateway-admitted-vtep-detail');
    expect(hook.get).toHaveBeenCalledWith('192.0.2.10');
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
    await waitFor(() =>
      expect(screen.getByTestId('gateway-admitted-vtep-detail').textContent).toContain('VTEP 192.0.2.11')
    );
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
    render(<GatewayAdmittedVTEPs gatewayId="gw-1" overlay={overlay({ running: false })} />);

    expect(screen.getByText('Stopped')).toBeDefined();
    expect(screen.queryByText('Running')).toBeNull();
  });

  it('reads through the hook for its gateway without listing on mount', () => {
    render(<GatewayAdmittedVTEPs gatewayId="gw-1" overlay={overlay()} />);

    expect(hook.calls[0]?.[0]).toBe('gw-1');
    expect(hook.refetch).not.toHaveBeenCalled();
  });

  it('gates Refresh on the admitted-VTEP list route and replaces the list with its answer', async () => {
    render(<GatewayAdmittedVTEPs gatewayId="gw-1" overlay={overlay()} />);

    const refresh = button('Refresh');
    await waitFor(() => expect(refresh.getAttribute('data-capability-enabled')).toBe('true'));
    expect(refresh.getAttribute('data-capability-op')).toBe(LIST_OP);

    hook.vteps = [{ vtep: '2001:db8::5', hostname: 'host-c.example.com' }];
    await act(async () => {
      fireEvent.click(refresh);
    });

    expect(hook.refetch).toHaveBeenCalledTimes(1);
    const rows = await screen.findAllByTestId('gateway-admitted-vtep-row');
    expect(rows).toHaveLength(1);
    expect(within(rows[0]).getByText('2001:db8::5')).toBeDefined();
    expect(screen.queryByText('192.0.2.10')).toBeNull();
  });

  it('shows a refused refresh inline', async () => {
    render(<GatewayAdmittedVTEPs gatewayId="gw-1" overlay={overlay()} />);

    hook.error = 'HTTP 503: overlay telemetry is not available for this gateway';
    await act(async () => {
      fireEvent.click(button('Refresh'));
    });

    expect(await screen.findByText('HTTP 503: overlay telemetry is not available for this gateway')).toBeDefined();
  });

  it('gates each Details on the one-VTEP route', async () => {
    render(<GatewayAdmittedVTEPs gatewayId="gw-1" overlay={overlay()} />);

    const details = button('Details 192.0.2.10');
    await waitFor(() => expect(details.getAttribute('data-capability-enabled')).toBe('true'));
    expect(details.getAttribute('data-capability-op')).toBe(GET_OP);
    expect(button('Details 192.0.2.11').getAttribute('data-capability-op')).toBe(GET_OP);
  });

  it('withholds Refresh and Details when the server does not offer them', async () => {
    off.add(LIST_OP);
    off.add(GET_OP);
    render(<GatewayAdmittedVTEPs gatewayId="gw-1" overlay={overlay()} />);

    const refresh = button('Refresh');
    const details = button('Details 192.0.2.10');
    expect(refresh.disabled).toBe(true);
    expect(refresh.getAttribute('title')).toBe('not-configured: gateway');
    expect(details.disabled).toBe(true);

    await act(async () => {
      fireEvent.click(refresh);
      fireEvent.click(details);
    });
    expect(hook.refetch).not.toHaveBeenCalled();
    expect(hook.get).not.toHaveBeenCalled();
    off.clear();
  });

  it('shows a refused Details read inline in the detail', async () => {
    answerGet([]);
    render(<GatewayAdmittedVTEPs gatewayId="gw-1" overlay={overlay()} />);

    await act(async () => {
      fireEvent.click(button('Details 192.0.2.10'));
    });

    const detail = await screen.findByTestId('gateway-admitted-vtep-detail');
    expect(detail.textContent).toContain('HTTP 404: vtep not admitted');
    expect(hook.get).toHaveBeenCalledWith('192.0.2.10');
  });
});
