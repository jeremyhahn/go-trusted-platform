// #2033: the user detail page reads the capability gate. The user is not
// fetched when its GET op is off (a not-enabled card shows the reason), Edit
// User follows the PUT op and each Remove role follows the role DELETE op.
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import UserDetailPage from './user-detail-client';

const router = { push: vi.fn(), back: vi.fn() };
vi.mock('next/navigation', () => ({
  useParams: () => ({ id: 'u1' }),
  usePathname: () => '/iam/users/u1',
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
  iam: { getUser: vi.fn(), listRoles: vi.fn(), updateUser: vi.fn(), revokeRole: vi.fn() },
}));
vi.mock('@/hooks', () => ({
  useIAM: () => h.iam,
  useToast: () => ({ toast: h.toast }),
  useApi: (fetcher: () => unknown, _deps: unknown[], opts?: { enabled?: boolean }) => {
    if (opts?.enabled !== false) {
      // The roles fetch rejects while the edit form is closed; swallow it.
      Promise.resolve()
        .then(fetcher)
        .catch(() => undefined);
    }
    return {
      data: { id: 'u1', email: 'alice@example.com', name: 'Alice', roles: ['r1'] },
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
    mutateAsync: (v: unknown) => Promise.resolve(fn(v)),
    isLoading: false,
  }),
}));

vi.mock('@/components/features/iam/user-form', () => ({
  UserForm: ({ open }: { open: boolean }) => (open ? <div data-testid="user-form" /> : null),
}));

const getOp = 'GET /api/v1/iam/tenants/{tenant}/users/{id}';
const updateOp = 'PUT /api/v1/iam/tenants/{tenant}/users/{id}';
const revokeOp = 'DELETE /api/v1/iam/tenants/{tenant}/users/{id}/roles/{role}';
const reason = 'not-configured: iam';

function offOnly(off: string) {
  caps.capability.mockImplementation((op: string) =>
    op === off ? { enabled: false, reason } : { enabled: true },
  );
}

function button(name: string) {
  return screen.getByRole('button', { name }) as HTMLButtonElement;
}

// The fetchers run on a microtask in the useApi mock above.
const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

describe('UserDetailPage capability gate', () => {
  beforeEach(() => {
    caps.capability.mockReset();
    caps.capability.mockImplementation(() => ({ enabled: true }));
    for (const fn of Object.values(h.iam)) {
      fn.mockReset();
      fn.mockResolvedValue({});
    }
    router.push.mockReset();
    vi.spyOn(window, 'confirm').mockReturnValue(true);
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it('does not fetch the user and shows the reason when the get op is off', async () => {
    offOnly(getOp);
    render(<UserDetailPage />);
    await flush();

    expect(h.iam.getUser).not.toHaveBeenCalled();
    expect(screen.getByTestId('user-not-enabled').textContent).toContain(reason);
    expect(screen.queryByText('Loading user details...')).toBeNull();
  });

  it('withholds Edit User with the server reason when the update op is off', () => {
    offOnly(updateOp);
    render(<UserDetailPage />);

    const edit = button('Edit User');
    expect(edit.disabled).toBe(true);
    expect(edit.title).toBe(reason);
    expect(edit.getAttribute('data-capability-op')).toBe(updateOp);
    expect(edit.getAttribute('data-capability-enabled')).toBe('false');
    fireEvent.click(edit);
    expect(screen.queryByTestId('user-form')).toBeNull();
  });

  it('withholds Remove role with the server reason when the revoke op is off', async () => {
    offOnly(revokeOp);
    render(<UserDetailPage />);

    const remove = button('Remove role r1');
    expect(remove.disabled).toBe(true);
    expect(remove.title).toBe(reason);
    expect(remove.getAttribute('data-capability-op')).toBe(revokeOp);
    fireEvent.click(remove);
    await flush();
    expect(h.iam.revokeRole).not.toHaveBeenCalled();
  });

  it('offers Edit User and Remove role when the server does', async () => {
    render(<UserDetailPage />);
    await flush();

    expect(h.iam.getUser).toHaveBeenCalled();
    const edit = button('Edit User');
    expect(edit.getAttribute('data-capability-enabled')).toBe('true');
    fireEvent.click(edit);
    expect(screen.getByTestId('user-form')).toBeTruthy();

    const remove = button('Remove role r1');
    expect(remove.disabled).toBe(false);
    fireEvent.click(remove);
    await flush();
    expect(h.iam.revokeRole).toHaveBeenCalledTimes(1);
  });
});
