import * as React from 'react';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import SwitchPortsClient from './switch-ports-client';

vi.mock('next/navigation', () => ({
  useParams: () => ({ switch: 'core-1' }),
  usePathname: () => '/networking/switches/core-1',
}));

// The Radix portal does not settle in jsdom: render the dialog inline.
vi.mock('@/components/ui/dialog', () => ({
  Dialog: ({ open, children }: { open: boolean; children?: React.ReactNode }) =>
    open ? <div role="dialog">{children}</div> : null,
  DialogTitle: ({ children }: { children?: React.ReactNode }) => <h2>{children}</h2>,
  DialogContent: ({ children }: { children?: React.ReactNode }) => <>{children}</>,
  DialogHeader: ({ children }: { children?: React.ReactNode }) => <>{children}</>,
  DialogFooter: ({ children }: { children?: React.ReactNode }) => <>{children}</>,
  DialogDescription: ({ children }: { children?: React.ReactNode }) => <>{children}</>,
}));

const hook = vi.hoisted(() => ({
  ports: [{ port: 'Eth1/2', mode: 'access', access_vlan: 10, enabled: false, link_up: false, description: 'uplink' }],
  isLoading: false,
  error: null,
  refetch: vi.fn(),
  // The server's single-port enabled reads `Switchport: Enabled`: true for a shut-down port.
  getPortStatus: vi.fn(async () => ({ port: 'Eth1/2', mode: 'access', access_vlan: 10, enabled: true, link_up: false })),
  enablePort: vi.fn(),
  disablePort: vi.fn(),
  setPortVLAN: vi.fn(),
}));

vi.mock('@/hooks', () => ({
  useToast: () => ({ toast: vi.fn() }),
  useSwitchPorts: () => hook,
}));

afterEach(() => {
  cleanup();
});

describe('SwitchPortsClient status dialog', () => {
  it("the status dialog shows the list's admin state, not the switchport flag", async () => {
    render(<SwitchPortsClient />);

    fireEvent.click(screen.getByRole('button', { name: 'Status' }));

    const status = await waitFor(() => screen.getByTestId('port-status'));
    const admin = Array.from(status.querySelectorAll('dt')).find((dt) => dt.textContent === 'Admin');
    expect(admin?.nextElementSibling?.tagName).toBe('DD');
    expect(admin?.nextElementSibling?.textContent).toBe('disabled');
  });

  it("the status dialog shows the list's description, absent from the single-port reply", async () => {
    render(<SwitchPortsClient />);

    fireEvent.click(screen.getByRole('button', { name: 'Status' }));

    const status = await waitFor(() => screen.getByTestId('port-status'));
    const description = Array.from(status.querySelectorAll('dt')).find((dt) => dt.textContent === 'Description');
    expect(description?.nextElementSibling?.tagName).toBe('DD');
    expect(description?.nextElementSibling?.textContent).toBe('uplink');
  });
});
