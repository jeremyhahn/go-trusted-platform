// #2033: the permissions page reads the capability gate. Each of the groups,
// policies and roles lists is fetched only when the server offers its GET op
// and the capabilities have loaded; with all three off the page says so.
import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import PermissionsPage from './page';

vi.mock('next/navigation', () => ({
  usePathname: () => '/iam/permissions',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
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
  iam: { listGroups: vi.fn(), listPolicies: vi.fn(), listRoles: vi.fn() },
}));
vi.mock('@/hooks', () => ({
  useIAM: () => h.iam,
  useToast: () => ({ toast: vi.fn() }),
  useApi: (fetcher: () => unknown, _deps: unknown[], opts?: { enabled?: boolean }) => {
    if (opts?.enabled !== false) {
      fetcher();
    }
    return {
      data: { groups: [], policies: [], roles: [] },
      loading: false,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    };
  },
}));

vi.mock('@/components/ui/data-table', () => ({
  createSelectColumn: () => ({ id: 'select' }),
  DataTable: ({ loading }: { loading?: boolean }) => (
    <div data-testid="table" data-loading={String(Boolean(loading))} />
  ),
}));

const groupsOp = 'GET /api/v1/iam/tenants/{tenant}/groups';
const policiesOp = 'GET /api/v1/iam/tenants/{tenant}/policies';
const rolesOp = 'GET /api/v1/iam/tenants/{tenant}/roles';
const reason = 'not-configured: iam';

function off(...ops: string[]) {
  caps.capability.mockImplementation((op: string) =>
    ops.includes(op) ? { enabled: false, reason } : { enabled: true },
  );
}

describe('PermissionsPage capability gate', () => {
  beforeEach(() => {
    caps.loading = false;
    caps.capability.mockReset();
    caps.capability.mockImplementation(() => ({ enabled: true }));
    h.iam.listGroups.mockReset();
    h.iam.listPolicies.mockReset();
    h.iam.listRoles.mockReset();
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it.each([
    [groupsOp, 'listGroups'],
    [policiesOp, 'listPolicies'],
    [rolesOp, 'listRoles'],
  ] as const)('does not call the list when %s is off', (op, call) => {
    off(op);
    render(<PermissionsPage />);

    expect(h.iam[call]).not.toHaveBeenCalled();
    for (const other of ['listGroups', 'listPolicies', 'listRoles'] as const) {
      if (other !== call) {
        expect(h.iam[other]).toHaveBeenCalledTimes(1);
      }
    }
    expect(screen.queryByText('Error Loading Data')).toBeNull();
    expect(screen.queryByTestId('iam-permissions-not-enabled')).toBeNull();
  });

  it('says the page is not enabled when all three lists are off', () => {
    off(groupsOp, policiesOp, rolesOp);
    render(<PermissionsPage />);

    expect(screen.getByTestId('iam-permissions-not-enabled').textContent).toContain(reason);
    expect(h.iam.listGroups).not.toHaveBeenCalled();
    expect(h.iam.listPolicies).not.toHaveBeenCalled();
    expect(h.iam.listRoles).not.toHaveBeenCalled();
    expect(screen.queryByText('Error Loading Data')).toBeNull();
  });

  it('shows the loading state and lists nothing while the capabilities load', () => {
    caps.loading = true;
    caps.capability.mockImplementation(() => ({ enabled: false, reason: 'loading' }));
    render(<PermissionsPage />);

    expect(h.iam.listGroups).not.toHaveBeenCalled();
    expect(h.iam.listPolicies).not.toHaveBeenCalled();
    expect(h.iam.listRoles).not.toHaveBeenCalled();
    expect(screen.queryByTestId('iam-permissions-not-enabled')).toBeNull();
    const tables = screen.getAllByTestId('table');
    expect(tables.length).toBeGreaterThan(0);
    for (const t of tables) {
      expect(t.getAttribute('data-loading')).toBe('true');
    }
  });

  it('lists all three when the server offers them', () => {
    render(<PermissionsPage />);

    expect(h.iam.listGroups).toHaveBeenCalledTimes(1);
    expect(h.iam.listPolicies).toHaveBeenCalledTimes(1);
    expect(h.iam.listRoles).toHaveBeenCalledTimes(1);
    expect(screen.queryByTestId('iam-permissions-not-enabled')).toBeNull();
  });
});
