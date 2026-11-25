// #2033: the roles list page reads the capability gate. The list is not
// fetched when its GET op is off, Add Role follows POST, Edit follows PUT,
// Delete and Delete selected follow DELETE.
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import type { ReactNode } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import RolesPage from './page';

const router = { push: vi.fn(), back: vi.fn() };
vi.mock('next/navigation', () => ({
  usePathname: () => '/iam/roles',
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
  iam: { listRoles: vi.fn(), deleteRole: vi.fn() },
}));
vi.mock('@/hooks', () => ({
  useIAM: () => h.iam,
  useToast: () => ({ toast: h.toast }),
  useApi: (fetcher: () => unknown, _deps: unknown[], opts?: { enabled?: boolean }) => {
    if (opts?.enabled !== false) {
      fetcher();
    }
    return {
      data: { roles: [{ id: 'r1', name: 'auditor', description: '', permissions: [] }] },
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

const listOp = 'GET /api/v1/iam/tenants/{tenant}/roles';
const createOp = 'POST /api/v1/iam/tenants/{tenant}/roles';
const updateOp = 'PUT /api/v1/iam/tenants/{tenant}/roles/{id}';
const deleteOp = 'DELETE /api/v1/iam/tenants/{tenant}/roles/{id}';
const reason = 'not-configured: iam';

function offOnly(off: string) {
  caps.capability.mockImplementation((op: string) =>
    op === off ? { enabled: false, reason } : { enabled: true },
  );
}

function button(name: string) {
  return screen.getByRole('button', { name }) as HTMLButtonElement;
}

describe('RolesPage capability gate', () => {
  beforeEach(() => {
    caps.capability.mockReset();
    caps.capability.mockImplementation(() => ({ enabled: true }));
    h.iam.listRoles.mockReset();
    h.iam.deleteRole.mockReset();
    router.push.mockReset();
    vi.spyOn(window, 'confirm').mockReturnValue(true);
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it('does not list roles and shows the reason when the list op is off', () => {
    offOnly(listOp);
    render(<RolesPage />);

    expect(h.iam.listRoles).not.toHaveBeenCalled();
    expect(screen.getByTestId('roles-not-enabled').textContent).toContain(reason);
    expect(screen.queryByTestId('row')).toBeNull();
  });

  it('withholds Add Role with the server reason', () => {
    offOnly(createOp);
    render(<RolesPage />);

    const add = button('Add Role');
    expect(add.disabled).toBe(true);
    expect(add.getAttribute('title')).toBe(reason);
    expect(add.getAttribute('data-capability-op')).toBe(createOp);
  });

  it('withholds Edit while the update op is off', () => {
    offOnly(updateOp);
    render(<RolesPage />);

    const edit = button('Edit');
    expect(edit.disabled).toBe(true);
    expect(edit.getAttribute('title')).toBe(reason);
    expect(button('View').disabled).toBe(false);
  });

  it('withholds Delete and Delete selected while the delete op is off', () => {
    offOnly(deleteOp);
    render(<RolesPage />);

    const del = button('Delete');
    const bulk = button('Delete selected');
    expect(del.disabled).toBe(true);
    expect(del.getAttribute('title')).toBe(reason);
    expect(bulk.disabled).toBe(true);
    expect(bulk.getAttribute('title')).toBe(reason);

    fireEvent.click(del);
    fireEvent.click(bulk);
    expect(h.iam.deleteRole).not.toHaveBeenCalled();
  });

  it('offers every control when the server does', () => {
    render(<RolesPage />);

    expect(h.iam.listRoles).toHaveBeenCalledTimes(1);
    for (const name of ['Add Role', 'Edit', 'Delete', 'Delete selected']) {
      const b = button(name);
      expect(b.disabled).toBe(false);
      expect(b.hasAttribute('title')).toBe(false);
    }
  });
});
