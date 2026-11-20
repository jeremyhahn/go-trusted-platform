import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { cleanup, render, screen, fireEvent, waitFor } from '@testing-library/react';
import type { GatewayVIPRow } from '@/hooks/use-gateway-vips';

const toast = vi.fn();
vi.mock('@/hooks', () => ({ useToast: () => ({ toast }) }));

const hook = {
  vips: [] as GatewayVIPRow[],
  isLoading: false,
  error: undefined as Error | undefined,
  lbStatus: undefined as Record<string, unknown> | undefined,
  lbError: undefined as Error | undefined,
  nat64Status: undefined as Record<string, unknown> | undefined,
  nat64Error: undefined as Error | undefined,
  refetch: vi.fn(),
  getVIP: vi.fn(),
  addVIP: vi.fn(),
  removeVIP: vi.fn(),
  setVIPBackends: vi.fn(),
};

vi.mock('@/hooks/use-gateway-vips', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/hooks/use-gateway-vips')>()),
  useGatewayVIPs: () => hook,
}));

import GatewayVIPsPage from './page';

const row: GatewayVIPRow = {
  address: '198.51.100.20',
  port: 8443,
  protocol: 'tcp',
  algorithm: 'maglev',
  ctZone: 4096,
  groupId: 7,
  backends: [
    { address: '10.0.0.11', port: 443, weight: 1, healthy: true },
    { address: '10.0.0.12', port: 443, weight: 1, healthy: false },
  ],
};

describe('GatewayVIPsPage', () => {
  afterEach(cleanup);

  beforeEach(() => {
    vi.clearAllMocks();
    hook.vips = [row];
    hook.error = undefined;
    hook.lbStatus = { vipCount: 1, healthy: true };
    hook.lbError = undefined;
    hook.nat64Status = undefined;
    hook.nat64Error = new Error('NAT64 not configured');
    hook.getVIP.mockResolvedValue(row);
    hook.addVIP.mockResolvedValue(undefined);
    hook.removeVIP.mockResolvedValue(undefined);
    hook.setVIPBackends.mockResolvedValue(undefined);
  });

  it('lists VIPs under the Virtual IPs heading', () => {
    render(<GatewayVIPsPage />);
    expect(screen.getByRole('heading', { name: 'Virtual IPs' })).toBeTruthy();
    expect(screen.getByText('198.51.100.20')).toBeTruthy();
    expect(screen.getByText('1/2')).toBeTruthy();
  });

  it('shows the LB status and an unavailable NAT64 card', () => {
    render(<GatewayVIPsPage />);
    expect(screen.getByTestId('gateway-lb-status').textContent).toContain('vipCount');
    expect(screen.getByTestId('gateway-nat64-status').textContent).toContain(
      'unavailable: NAT64 not configured'
    );
  });

  it('adds a VIP with the parsed backends', async () => {
    render(<GatewayVIPsPage />);
    fireEvent.change(screen.getByLabelText('VIP address'), { target: { value: '198.51.100.21' } });
    fireEvent.change(screen.getByLabelText('VIP port'), { target: { value: '80' } });
    fireEvent.change(screen.getByLabelText('Backends'), {
      target: { value: '10.0.0.11:443, [2001:db8::1]:8080@3' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Add VIP' }));
    await waitFor(() =>
      expect(hook.addVIP).toHaveBeenCalledWith({
        address: '198.51.100.21',
        port: 80,
        protocol: 'tcp',
        backends: [
          { address: '10.0.0.11', port: 443 },
          { address: '2001:db8::1', port: 8080, weight: 3 },
        ],
      })
    );
  });

  it('refuses a malformed backend without calling the server', async () => {
    render(<GatewayVIPsPage />);
    fireEvent.change(screen.getByLabelText('VIP address'), { target: { value: '198.51.100.21' } });
    fireEvent.change(screen.getByLabelText('VIP port'), { target: { value: '80' } });
    fireEvent.change(screen.getByLabelText('Backends'), { target: { value: '10.0.0.11' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add VIP' }));
    await waitFor(() => expect(toast).toHaveBeenCalled());
    expect(hook.addVIP).not.toHaveBeenCalled();
    expect(toast.mock.calls[0][0].variant).toBe('destructive');
  });

  it('removes a VIP only after Confirm', async () => {
    render(<GatewayVIPsPage />);
    fireEvent.click(screen.getByRole('button', { name: 'Remove 198.51.100.20:8443' }));
    expect(hook.removeVIP).not.toHaveBeenCalled();
    fireEvent.click(await screen.findByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(hook.removeVIP).toHaveBeenCalledWith('198.51.100.20', 8443, 'tcp'));
  });

  it('shows backends from GetVIP and saves an edited list', async () => {
    render(<GatewayVIPsPage />);
    fireEvent.click(screen.getByRole('button', { name: 'Backends of 198.51.100.20:8443' }));
    expect(await screen.findByText('10.0.0.12')).toBeTruthy();
    expect(hook.getVIP).toHaveBeenCalledWith('198.51.100.20', 8443, 'tcp');
    fireEvent.change(screen.getByLabelText('New backends'), {
      target: { value: '10.0.0.13:443' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Save backends' }));
    await waitFor(() =>
      expect(hook.setVIPBackends).toHaveBeenCalledWith({
        address: '198.51.100.20',
        port: 8443,
        protocol: 'tcp',
        backends: [{ address: '10.0.0.13', port: 443 }],
      })
    );
  });

  it('reports a failed VIP list', () => {
    hook.vips = [];
    hook.error = new Error('gateway service unavailable');
    render(<GatewayVIPsPage />);
    expect(screen.getByText('gateway service unavailable')).toBeTruthy();
    expect(screen.getByText('No virtual IPs.')).toBeTruthy();
  });
});
