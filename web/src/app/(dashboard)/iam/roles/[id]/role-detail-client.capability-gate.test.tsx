// #2033: the role detail page reads the capability gate. The role is not
// fetched when its GET op is off (a not-enabled card shows the reason), and
// Edit Role and Save Changes follow the PUT op.
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import RoleDetailPage from './role-detail-client';

const router = { push: vi.fn(), back: vi.fn() };
vi.mock('next/navigation', () => ({
  useParams: () => ({ id: 'r1' }),
  usePathname: () => '/iam/roles/r1',
  useRouter: () => router,
}));

const authResult = { tenantId: 't-1', isLoading: false };
vi.mock('@/contexts/AuthContext', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/contexts/AuthContext')>()),
  useAuth: () => authResult,
}));

const caps = vi.hoisted(() => ({ capability: vi.fn() }));
vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({
    loading: false,
    error: undefined,
    capability: caps.capability,
  }),
}));

const h = vi.hoisted(() => ({
  toast: vi.fn(),
  iam: { getRole: vi.fn(), updateRole: vi.fn() },
}));
vi.mock('@/hooks', () => ({
  useIAM: () => h.iam,
  useToast: () => ({ toast: h.toast }),
  useApi: (fetcher: () => unknown, _deps: unknown[], opts?: { enabled?: boolean }) => {
    if (opts?.enabled !== false) {
      fetcher();
    }
    return {
      data: { id: 'r1', name: 'auditor', description: 'reads', permissions: ['iam:read'] },
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

vi.mock('@/components/features/iam/permission-tree', () => ({ PermissionTree: () => null }));

const getOp = 'GET /api/v1/iam/tenants/{tenant}/roles/{id}';
const updateOp = 'PUT /api/v1/iam/tenants/{tenant}/roles/{id}';
const reason = 'not-configured: iam';

function offOnly(off: string) {
  caps.capability.mockImplementation((op: string) =>
    op === off ? { enabled: false, reason } : { enabled: true },
  );
}

function button(name: string) {
  return screen.getByRole('button', { name }) as HTMLButtonElement;
}

describe('RoleDetailPage capability gate', () => {
  beforeEach(() => {
    caps.capability.mockReset();
    caps.capability.mockImplementation(() => ({ enabled: true }));
    h.iam.getRole.mockReset();
    h.iam.updateRole.mockReset();
    h.iam.getRole.mockResolvedValue({});
    h.iam.updateRole.mockResolvedValue({});
    router.push.mockReset();
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it('does not fetch the role and shows the reason when the get op is off', () => {
    offOnly(getOp);
    render(<RoleDetailPage />);

    expect(h.iam.getRole).not.toHaveBeenCalled();
    expect(screen.getByTestId('role-not-enabled').textContent).toContain(reason);
    expect(screen.queryByText('Loading role details...')).toBeNull();
  });

  it('withholds Edit Role with the server reason when the update op is off', () => {
    offOnly(updateOp);
    render(<RoleDetailPage />);

    const edit = button('Edit Role');
    expect(edit.disabled).toBe(true);
    expect(edit.title).toBe(reason);
    expect(edit.getAttribute('data-capability-op')).toBe(updateOp);
    expect(edit.getAttribute('data-capability-enabled')).toBe('false');
    fireEvent.click(edit);
    expect(screen.queryByText('Save Changes')).toBeNull();
  });

  it('offers Edit Role and Save Changes when the server does', () => {
    render(<RoleDetailPage />);

    expect(h.iam.getRole).toHaveBeenCalled();
    fireEvent.click(button('Edit Role'));
    const save = button('Save Changes');
    expect(save.disabled).toBe(false);
    expect(save.getAttribute('data-capability-enabled')).toBe('true');
    fireEvent.click(save);
    expect(h.iam.updateRole).toHaveBeenCalledTimes(1);
  });
});
