import { act, cleanup, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import VMDetailPage from './vm-detail-client';

// A refused first load must not leave the page spinning: a node without
// compute answers the structured not-configured 503 and the page says so;
// any other refusal shows the load error (#2045).

const caps = vi.hoisted(() => ({ capability: vi.fn() }));
const compute = vi.hoisted(() => ({ getVM: vi.fn() }));
const verify = vi.hoisted(() => vi.fn());

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

const GOOD_VM = {
  success: true,
  data: {
    vm: {
      id: 'vm-1',
      state: 'VM_STATE_RUNNING',
      createdAt: '2026-01-01T00:00:00Z',
      config: { name: 'vm-one' },
    },
  },
};

// The SDK's structured not-configured 503: status 503 and the
// SERVICE_NOT_CONFIGURED reason in details, as the client hands it over in
// ApiResponse.error and on the ApiError it throws.
function notConfiguredError() {
  return Object.assign(new Error('compute service is not configured on this node'), {
    status: 503,
    code: 'SERVICE_UNAVAILABLE',
    details: { reason: 'SERVICE_NOT_CONFIGURED', service: 'compute' },
  });
}

const BOOM = { success: false, error: { message: 'boom', status: 500 } };

beforeEach(() => {
  caps.capability.mockReset();
  caps.capability.mockImplementation(() => ({ enabled: true }));
  compute.getVM.mockReset();
  verify.mockReset();
  verify.mockResolvedValue({ valid: true });
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

function expectNoDetail() {
  expect(screen.queryByText('Virtual Machine Details')).toBeNull();
  expect(screen.queryByRole('button', { name: /Verify Attestation/ })).toBeNull();
}

describe('VMDetailPage on a refused load', () => {
  it('shows that compute is not available when the server answers not-configured', async () => {
    compute.getVM.mockResolvedValue({ success: false, error: notConfiguredError() });
    render(<VMDetailPage />);
    await screen.findByText('Compute is not available on this node');
    expect(screen.queryByRole('alert')).toBeNull();
    expectNoDetail();
  });

  it('shows not available when getVM throws the not-configured error', async () => {
    compute.getVM.mockRejectedValue(notConfiguredError());
    render(<VMDetailPage />);
    await screen.findByText('Compute is not available on this node');
    expect(screen.queryByRole('alert')).toBeNull();
    expectNoDetail();
  });

  it('shows the load error for any other refusal', async () => {
    compute.getVM.mockResolvedValue(BOOM);
    const { container } = render(<VMDetailPage />);
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('Failed to load VM');
    expect(alert.textContent).toContain('boom');
    expect(container.querySelector('.animate-spin')).toBeNull();
    expectNoDetail();
  });

  it('keeps the detail on a later refusal of the 5 s refresh', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    compute.getVM.mockResolvedValueOnce(GOOD_VM).mockResolvedValue(BOOM);
    render(<VMDetailPage />);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(screen.getAllByText('vm-one').length).toBeGreaterThan(0);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5000);
    });
    expect(compute.getVM).toHaveBeenCalledTimes(2);
    expect(screen.getAllByText('vm-one').length).toBeGreaterThan(0);
    expect(screen.queryByRole('alert')).toBeNull();
  });
});
