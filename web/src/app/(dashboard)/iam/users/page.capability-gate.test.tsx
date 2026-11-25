// #2033: the users list page reads the capability gate. The list is not
// fetched when its GET op is off, Add User follows POST, Edit and Disable
// follow PUT, Delete and Delete selected follow DELETE.
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import type { ReactNode } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import UsersPage from './page';

const router = { push: vi.fn(), back: vi.fn() };
vi.mock('next/navigation', () => ({
  usePathname: () => '/iam/users',
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
  iam: {
    listUsers: vi.fn(),
    listRoles: vi.fn(),
    createUser: vi.fn(),
    deleteUser: vi.fn(),
    updateUser: vi.fn(),
  },
}));
vi.mock('@/hooks', () => ({
  useIAM: () => h.iam,
  useToast: () => ({ toast: h.toast }),
  useApi: (fetcher: () => unknown, _deps: unknown[], opts?: { enabled?: boolean }) => {
    if (opts?.enabled !== false) {
      fetcher();
    }
    return {
      data: {
        users: [
          { id: 'u1', username: 'alice', email: 'alice@example.com', status: 'active', roles: [] },
        ],
      },
      loading: false,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    };
  },
  useMutation: (
    fn: (v: unknown) => unknown,
    opts?: { onSuccess?: (r: unknown, v: unknown) => void; onError?: (e: unknown) => void },
  ) => ({
    mutate: (v: unknown) =>
      Promise.resolve(fn(v)).then((r) => opts?.onSuccess?.(r, v), opts?.onError),
    mutateAsync: (v: unknown) => Promise.resolve(fn(v)),
    isLoading: false,
  }),
}));

vi.mock('@/components/features/iam/user-form', () => ({
  UserForm: () => null,
}));

interface MockColumn {
  id?: string;
  cell?: (ctx: { row: { original: unknown; getValue: (k: string) => unknown } }) => ReactNode;
}
interface MockAction {
  label: string;
  disabled?: boolean;
  title?: string;
  onClick: (arg: unknown) => void;
}

vi.mock('@/components/ui/data-table', () => ({
  createSelectColumn: () => ({ id: 'select' }),
  DataTable: ({
    columns,
    data,
    bulkActions,
  }: {
    columns: MockColumn[];
    data: Record<string, unknown>[];
    bulkActions?: MockAction[];
  }) => (
    <div>
      {data.map((row, i) => (
        <div data-testid="row" key={i}>
          {columns
            .filter((c) => c.id !== 'select' && c.cell)
            .map((c, j) => (
              <div key={j}>
                {c.cell!({ row: { original: row, getValue: (k: string) => row[k] } })}
              </div>
            ))}
        </div>
      ))}
      {(bulkActions ?? []).map((a) => (
        <button key={a.label} disabled={a.disabled} title={a.title} onClick={() => a.onClick(data)}>
          {a.label}
        </button>
      ))}
    </div>
  ),
}));

vi.mock('@/components/ui/data-table-row-actions', () => ({
  DataTableRowActions: ({ row, actions }: { row: unknown; actions: MockAction[] }) => (
    <div>
      {actions.map((a) => (
        <button key={a.label} disabled={a.disabled} title={a.title} onClick={() => a.onClick(row)}>
          {a.label}
        </button>
      ))}
    </div>
  ),
}));

const listOp = 'GET /api/v1/iam/tenants/{tenant}/users';
const createOp = 'POST /api/v1/iam/tenants/{tenant}/users';
const updateOp = 'PUT /api/v1/iam/tenants/{tenant}/users/{id}';
const deleteOp = 'DELETE /api/v1/iam/tenants/{tenant}/users/{id}';
const reason = 'not-configured: iam';

function offOnly(off: string) {
  caps.capability.mockImplementation((op: string) =>
    op === off ? { enabled: false, reason } : { enabled: true },
  );
}

function button(name: string) {
  return screen.getByRole('button', { name }) as HTMLButtonElement;
}

describe('UsersPage capability gate', () => {
  beforeEach(() => {
    caps.capability.mockReset();
    caps.capability.mockImplementation(() => ({ enabled: true }));
    for (const fn of Object.values(h.iam)) fn.mockReset();
    router.push.mockReset();
    vi.spyOn(window, 'confirm').mockReturnValue(true);
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it('does not list users and shows the reason when the list op is off', () => {
    offOnly(listOp);
    render(<UsersPage />);

    expect(h.iam.listUsers).not.toHaveBeenCalled();
    expect(screen.getByTestId('users-not-enabled').textContent).toContain(reason);
    expect(screen.queryByTestId('row')).toBeNull();
  });

  it('withholds Add User with the server reason', () => {
    offOnly(createOp);
    render(<UsersPage />);

    const add = button('Add User');
    expect(add.disabled).toBe(true);
    expect(add.getAttribute('title')).toBe(reason);
    expect(add.getAttribute('data-capability-op')).toBe(createOp);
  });

  it('withholds Edit and Disable while the update op is off', () => {
    offOnly(updateOp);
    render(<UsersPage />);

    for (const name of ['Edit', 'Disable']) {
      const b = button(name);
      expect(b.disabled).toBe(true);
      expect(b.getAttribute('title')).toBe(reason);
    }
    expect(button('View').disabled).toBe(false);

    fireEvent.click(button('Disable'));
    expect(h.iam.updateUser).not.toHaveBeenCalled();
  });

  it('withholds Delete and Delete selected while the delete op is off', () => {
    offOnly(deleteOp);
    render(<UsersPage />);

    const del = button('Delete');
    const bulk = button('Delete selected');
    expect(del.disabled).toBe(true);
    expect(del.getAttribute('title')).toBe(reason);
    expect(bulk.disabled).toBe(true);
    expect(bulk.getAttribute('title')).toBe(reason);

    fireEvent.click(del);
    fireEvent.click(bulk);
    expect(h.iam.deleteUser).not.toHaveBeenCalled();
  });

  it('offers every control when the server does', () => {
    render(<UsersPage />);

    expect(h.iam.listUsers).toHaveBeenCalledTimes(1);
    for (const name of ['Add User', 'Edit', 'Disable', 'Delete', 'Delete selected']) {
      const b = button(name);
      expect(b.disabled).toBe(false);
      expect(b.hasAttribute('title')).toBe(false);
    }
  });
});
