import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import VMDetailPage from './vm-detail-client';

// The Verify Attestation button calls two server ops (attest, then
// attest/verify): a server that withholds either shows it disabled with the
// server's reason (#2045).

const caps = vi.hoisted(() => ({ capability: vi.fn() }));
const compute = vi.hoisted(() => ({ getVM: vi.fn() }));
const verify = vi.hoisted(() => vi.fn());

const ATTEST_OP = 'POST /api/v1/compute/vms/{id}/attest';
const VERIFY_OP = 'POST /api/v1/compute/vms/{id}/attest/verify';

vi.mock('next/navigation', () => ({
  useParams: () => ({ id: 'vm-1' }),
  usePathname: () => '/compute/vms/vm-1',
  useRouter: () => ({ push: vi.fn() }),
}));

vi.mock('@/hooks', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/hooks')>();
  return {
    ...actual,
    useCompute: () => compute,
    useToast: () => ({ toast: vi.fn() }),
    useVMAttestationVerify: () => verify,
  };
});

vi.mock('./vm-operations', () => ({ VMOperations: () => null }));

vi.mock('@/components/features/compute/vm-metrics', () => ({ VMMetricsCard: () => null }));

vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({ loading: false, error: undefined, capability: caps.capability }),
}));

function capsOff(op: string, reason: string) {
  caps.capability.mockImplementation((asked: string) =>
    asked === op ? { enabled: false, reason } : { enabled: true }
  );
}

beforeEach(() => {
  caps.capability.mockReset();
  caps.capability.mockImplementation(() => ({ enabled: true }));
  compute.getVM.mockReset();
  compute.getVM.mockResolvedValue({
    success: true,
    data: {
      vm: {
        id: 'vm-1',
        state: 'VM_STATE_RUNNING',
        createdAt: '2026-01-01T00:00:00Z',
        config: { name: 'vm-one' },
      },
    },
  });
  verify.mockReset();
  verify.mockResolvedValue({ valid: true });
});

afterEach(() => {
  cleanup();
});

describe('VM Verify Attestation capability gate', () => {
  it('withholds Verify Attestation when the server does not offer the attest op', async () => {
    capsOff(ATTEST_OP, 'attest not offered');
    render(<VMDetailPage />);
    const button = await screen.findByRole('button', { name: /Verify Attestation/ });
    expect((button as HTMLButtonElement).disabled).toBe(true);
    expect(button.getAttribute('title')).toBe('attest not offered');
    fireEvent.click(button);
    expect(screen.queryByText('Verify VM attestation?')).toBeNull();
    expect(verify).not.toHaveBeenCalled();
  });

  it('withholds Verify Attestation when the server does not offer the verify op', async () => {
    capsOff(VERIFY_OP, 'verify not offered');
    render(<VMDetailPage />);
    const button = await screen.findByRole('button', { name: /Verify Attestation/ });
    expect((button as HTMLButtonElement).disabled).toBe(true);
    expect(button.getAttribute('title')).toBe('verify not offered');
    expect(button.getAttribute('data-capability-op')).toBe(VERIFY_OP);
    expect(button.getAttribute('data-capability-enabled')).toBe('false');
  });

  it('verifies after the confirm when both ops are offered', async () => {
    render(<VMDetailPage />);
    const button = await screen.findByRole('button', { name: /Verify Attestation/ });
    expect((button as HTMLButtonElement).disabled).toBe(false);
    expect(button.getAttribute('data-capability-enabled')).toBe('true');
    fireEvent.click(button);
    fireEvent.click(await screen.findByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(verify).toHaveBeenCalledTimes(1));
  });
});
