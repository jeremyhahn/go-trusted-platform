// #2033: the group detail page reads the capability gate. The group is not
// fetched when its GET op is off or the capabilities are still loading, and
// Delete follows the DELETE op.
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import GroupDetailClient from './group-detail-client';

const router = { push: vi.fn(), back: vi.fn() };
vi.mock('next/navigation', () => ({
  useParams: () => ({ id: 'g1' }),
  usePathname: () => '/iam/groups/g1',
  useRouter: () => router,
}));

vi.mock('@/utils/dynamic-route', () => ({
  resolveDynamicId: () => 'g1',
}));

const authResult = { tenantId: 't-1', isLoading: false };
vi.mock('@/contexts/AuthContext', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/contexts/AuthContext')>()),
  useAuth: () => authResult,
}));

const caps = vi.hoisted(() => ({ loading: false, capability: vi.fn() }));
vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({
    loading: caps.loading,
    error: undefined,
    capability: caps.capability,
  }),
}));

const h = vi.hoisted(() => ({
  toast: vi.fn(),
  iam: { getGroup: vi.fn(), deleteGroup: vi.fn() },
}));
vi.mock('@/hooks', () => ({
  useIAM: () => h.iam,
  useToast: () => ({ toast: h.toast }),
  useApi: (fetcher: () => unknown, _deps: unknown[], opts?: { enabled?: boolean }) => {
    if (opts?.enabled !== false) {
      fetcher();
    }
    return {
      data: { group: { name: 'admins', description: '', members: [], roles: [] } },
      loading: false,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    };
  },
  useMutation: (
    fn: (v: unknown) => unknown,
    opts?: { onSuccess?: (r: unknown) => void; onError?: (e: unknown) => void },
  ) => ({
    mutate: (v: unknown) => Promise.resolve(fn(v)).then(opts?.onSuccess, opts?.onError),
    isLoading: false,
  }),
}));

const getOp = 'GET /api/v1/iam/tenants/{tenant}/groups/{id}';
const deleteOp = 'DELETE /api/v1/iam/tenants/{tenant}/groups/{id}';
const reason = 'not-configured: iam';

function offOnly(off: string) {
  caps.capability.mockImplementation((op: string) =>
    op === off ? { enabled: false, reason } : { enabled: true },
  );
}

function button(name: string) {
  return screen.getByRole('button', { name }) as HTMLButtonElement;
}

describe('GroupDetailClient capability gate', () => {
  beforeEach(() => {
    caps.loading = false;
    caps.capability.mockReset();
    caps.capability.mockImplementation(() => ({ enabled: true }));
    h.iam.getGroup.mockReset();
    h.iam.deleteGroup.mockReset();
    router.push.mockReset();
    vi.spyOn(window, 'confirm').mockReturnValue(true);
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it('does not read the group and shows the reason when the read op is off', () => {
    offOnly(getOp);
    render(<GroupDetailClient />);

    expect(h.iam.getGroup).not.toHaveBeenCalled();
    expect(screen.getByTestId('iam-group-not-enabled').textContent).toContain(reason);
    expect(screen.queryByText(/Error loading group/)).toBeNull();
  });

  it('shows the spinner while the capabilities load', () => {
    caps.loading = true;
    caps.capability.mockImplementation(() => ({ enabled: false, reason: 'loading' }));
    render(<GroupDetailClient />);

    expect(screen.getByText('Loading group…')).toBeTruthy();
    expect(h.iam.getGroup).not.toHaveBeenCalled();
    expect(screen.queryByTestId('iam-group-not-enabled')).toBeNull();
  });

  it('withholds Delete while the delete op is off', () => {
    offOnly(deleteOp);
    render(<GroupDetailClient />);

    const del = button('Delete');
    expect(del.disabled).toBe(true);
    expect(del.getAttribute('title')).toBe(reason);
    expect(del.getAttribute('data-capability-op')).toBe(deleteOp);

    fireEvent.click(del);
    expect(window.confirm).not.toHaveBeenCalled();
    expect(h.iam.deleteGroup).not.toHaveBeenCalled();
  });

  it('offers Delete when the server does', () => {
    render(<GroupDetailClient />);

    expect(h.iam.getGroup).toHaveBeenCalledTimes(1);
    const del = button('Delete');
    expect(del.disabled).toBe(false);
    expect(del.hasAttribute('title')).toBe(false);
  });
});
