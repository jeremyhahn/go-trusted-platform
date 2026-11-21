import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { UseBMCResult } from '@/hooks';
import BMCProfileClient from './bmc-profile-client';

// #1675 Codex round 10 (F28): the daemon builds the BMC gRPC service with a
// nil baremetal service and never sets one, so every provision answers 503.
// The page shows provisioning as unavailable instead of offering it.

vi.mock('next/navigation', () => ({
  useParams: () => ({ profileID: '7' }),
  usePathname: () => '/devices/bmc/7',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

let hook: UseBMCResult;
const provision = vi.fn(async () => {});

vi.mock('@/hooks', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/hooks')>();
  return {
    ...actual,
    useBMC: () => hook,
    useToast: () => ({ toast: vi.fn() }),
  };
});

function state(over: Partial<UseBMCResult>): UseBMCResult {
  return {
    power: null,
    bootDevice: null,
    virtualMedia: null,
    sensors: null,
    systemInfo: null,
    provisionStatus: null,
    certificate: null,
    isLoading: false,
    errors: {},
    refetch: vi.fn(async () => {}),
    setBootDevice: vi.fn(async () => {}),
    mountISO: vi.fn(async () => {}),
    unmountISO: vi.fn(async () => {}),
    provision,
    ...over,
  };
}

function provisionButton(): HTMLButtonElement {
  return screen.getByRole('button', { name: 'Provision' }) as HTMLButtonElement;
}

describe('BMCProfileClient provisioning is unavailable (#1675 F28)', () => {
  beforeEach(() => {
    provision.mockClear();
    hook = state({});
  });

  afterEach(() => {
    cleanup();
  });

  it('the Provision button is disabled as not available on this server', () => {
    render(<BMCProfileClient />);

    expect(provisionButton().disabled).toBe(true);
    expect(provisionButton().getAttribute('title') ?? '').toContain('not available on this server');
  });

  it('clicking Provision opens no dialog and never provisions', () => {
    render(<BMCProfileClient />);

    fireEvent.click(provisionButton());

    expect(screen.queryByRole('dialog')).toBeNull();
    expect(provision).not.toHaveBeenCalled();
  });

  it('a 503 provision status shows the unavailable notice, not the error', () => {
    hook = state({ errors: { provisionStatus: '503 Service Unavailable: baremetal provisioning not configured' } });
    render(<BMCProfileClient />);

    expect(screen.getAllByText(/Provisioning is not available on this server/).length).toBeGreaterThan(0);
    expect(screen.queryByTestId('bmc-provisionStatus-error')).toBeNull();
    expect(screen.queryByText(/baremetal provisioning not configured/)).toBeNull();
  });
});
