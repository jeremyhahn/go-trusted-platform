import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ReactNode } from 'react';

// #2064: the SDN policies page lists the policies through useSDNPolicies
// (mocked here) and offers Apply Policy, Details and Delete, each behind the
// capability gate of its /api/v1/sdn/policies route.

const LIST_OP = 'GET /api/v1/sdn/policies';
const GET_OP = 'GET /api/v1/sdn/policies/{id}';
const APPLY_OP = 'POST /api/v1/sdn/policies';
const DELETE_OP = 'DELETE /api/v1/sdn/policies/{id}';

const { off, hook } = vi.hoisted(() => ({
  off: new Set<string>(),
  hook: {
    policies: [] as unknown[],
    isLoading: false,
    error: null as string | null,
    notConfigured: false,
    refetch: (() => Promise.resolve()) as () => Promise<void>,
    get: ((_id: string) => Promise.reject(new Error('unset'))) as (id: string) => Promise<unknown>,
    apply: ((_req: unknown) => Promise.resolve(undefined)) as (req: unknown) => Promise<unknown>,
    remove: ((_id: string) => Promise.resolve()) as (id: string) => Promise<void>,
  },
}));

vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({
    loading: false,
    error: undefined,
    capability: (op: string) =>
      off.has(op) ? { enabled: false, reason: 'not-configured: sdn' } : { enabled: true },
  }),
}));

vi.mock('@/hooks/use-sdn-policies', () => ({
  useSDNPolicies: () => hook,
}));

type Row = Record<string, unknown> & { id: string };
type Column = { id?: string; accessorKey?: string; cell?: (ctx: { row: { getValue: (k: string) => unknown; original: Row } }) => ReactNode };

vi.mock('@/components/ui/data-table', () => ({
  createSelectColumn: () => ({ id: 'select' }),
  DataTable: ({ columns, data }: { columns: Column[]; data: Row[] }) => (
    <div>
      {data.map((r) => (
        <div key={r.id} data-testid={`row-${r.id}`}>
          {columns
            .filter((c) => c.cell)
            .map((c, i) => (
              <div key={i} data-col={c.accessorKey ?? c.id}>
                {c.cell!({ row: { getValue: (k) => r[k], original: r } })}
              </div>
            ))}
        </div>
      ))}
    </div>
  ),
}));

vi.mock('@/components/ui/data-table-row-actions', () => ({
  DataTableRowActions: ({ row, actions }: { row: Row; actions: { label: string; op?: string; onClick: (r: Row) => void }[] }) => (
    <div>
      {actions.map((a) => (
        <button key={a.label} data-op={a.op} onClick={() => a.onClick(row)}>
          {a.label}
        </button>
      ))}
    </div>
  ),
}));

import SDNPoliciesPage from './page';

const P1 = {
  id: 'pol-1',
  config: { name: 'web-acl', type: 'POLICY_TYPE_ACL', priority: 100, enabled: true },
  status: 'POLICY_STATUS_ACTIVE',
  hitCount: '5',
};
const P2 = {
  id: 'pol-2',
  config: { name: 'voice-qos', type: 'POLICY_TYPE_QOS', priority: 200, enabled: false },
  status: 'POLICY_STATUS_INACTIVE',
  hitCount: '0',
};

function cell(rowId: string, col: string): string {
  const row = screen.getByTestId(`row-${rowId}`);
  return (row.querySelector(`[data-col="${col}"]`) as HTMLElement).textContent ?? '';
}

function button(name: string): HTMLButtonElement {
  return screen.getByRole('button', { name }) as HTMLButtonElement;
}

beforeEach(() => {
  off.clear();
  hook.policies = [P1, P2];
  hook.isLoading = false;
  hook.error = null;
  hook.notConfigured = false;
  hook.refetch = vi.fn(() => Promise.resolve());
  hook.get = vi.fn((id: string) => {
    const found = [P1, P2].find((p) => p.id === id);
    return found ? Promise.resolve(found) : Promise.reject(new Error('HTTP 404: policy not found'));
  });
  hook.apply = vi.fn(() => Promise.resolve(undefined));
  hook.remove = vi.fn(() => Promise.resolve());
});

afterEach(() => {
  cleanup();
});

describe('SDNPoliciesPage', () => {
  it('lists name, type, status, priority and hits per policy', () => {
    render(<SDNPoliciesPage />);

    expect(screen.getByRole('heading', { name: 'SDN Policies' })).toBeDefined();
    expect(cell('pol-1', 'name')).toContain('web-acl');
    expect(cell('pol-1', 'type')).toBe('ACL');
    expect(cell('pol-1', 'status')).toBe('ACTIVE');
    expect(cell('pol-1', 'priority')).toBe('100');
    expect(cell('pol-1', 'hits')).toBe('5');
    expect(cell('pol-2', 'name')).toContain('voice-qos');
    expect(cell('pol-2', 'type')).toBe('QOS');
    expect(cell('pol-2', 'status')).toBe('INACTIVE');
  });

  it('gates Refresh on the list route and refetches', async () => {
    render(<SDNPoliciesPage />);

    const refresh = button('Refresh');
    await waitFor(() => expect(refresh.getAttribute('data-capability-enabled')).toBe('true'));
    expect(refresh.getAttribute('data-capability-op')).toBe(LIST_OP);
    await act(async () => {
      fireEvent.click(refresh);
    });
    expect(hook.refetch).toHaveBeenCalledTimes(1);
  });

  it('gates Apply Policy on the apply route and applies the typed policy', async () => {
    render(<SDNPoliciesPage />);

    const open = button('Apply Policy');
    expect(open.getAttribute('data-capability-op')).toBe(APPLY_OP);
    fireEvent.click(open);

    const dialog = await screen.findByRole('dialog');
    fireEvent.change(within(dialog).getByLabelText('Policy ID'), { target: { value: 'pol-3' } });
    fireEvent.change(within(dialog).getByLabelText('Name'), { target: { value: 'dns-acl' } });
    fireEvent.change(within(dialog).getByLabelText('Type'), { target: { value: 'POLICY_TYPE_ROUTING' } });
    fireEvent.change(within(dialog).getByLabelText('Priority'), { target: { value: '50' } });
    fireEvent.click(within(dialog).getByLabelText('Enabled'));
    const submit = within(dialog).getByRole('button', { name: 'Apply' });
    expect(submit.getAttribute('data-capability-op')).toBe(APPLY_OP);
    await act(async () => {
      fireEvent.click(submit);
    });

    expect(hook.apply).toHaveBeenCalledWith({
      policyId: 'pol-3',
      config: { name: 'dns-acl', type: 'POLICY_TYPE_ROUTING', priority: 50, enabled: false },
    });
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
  });

  it('offers the real policy types', async () => {
    render(<SDNPoliciesPage />);
    fireEvent.click(button('Apply Policy'));

    const select = within(await screen.findByRole('dialog')).getByLabelText('Type') as HTMLSelectElement;
    const values = Array.from(select.options).map((o) => o.value);
    expect(values).toEqual(expect.arrayContaining(['POLICY_TYPE_ACL', 'POLICY_TYPE_QOS', 'POLICY_TYPE_ROUTING']));
  });

  it('shows a refused apply inline in the dialog', async () => {
    hook.apply = vi.fn(() => Promise.reject(new Error('HTTP 400: invalid policy')));
    render(<SDNPoliciesPage />);
    fireEvent.click(button('Apply Policy'));

    const dialog = await screen.findByRole('dialog');
    fireEvent.change(within(dialog).getByLabelText('Policy ID'), { target: { value: 'pol-3' } });
    fireEvent.change(within(dialog).getByLabelText('Name'), { target: { value: 'dns-acl' } });
    await act(async () => {
      fireEvent.click(within(dialog).getByRole('button', { name: 'Apply' }));
    });

    expect(await within(dialog).findByText('HTTP 400: invalid policy')).toBeDefined();
    expect(screen.getByRole('dialog')).toBeDefined();
  });

  it('gates Details on the one-policy route and shows the answer', async () => {
    render(<SDNPoliciesPage />);

    const details = within(screen.getByTestId('row-pol-1')).getByText('Details');
    expect(details.getAttribute('data-op')).toBe(GET_OP);
    await act(async () => {
      fireEvent.click(details);
    });

    expect(hook.get).toHaveBeenCalledWith('pol-1');
    const detail = await screen.findByTestId('sdn-policy-detail');
    await waitFor(() => expect(detail.textContent).toContain('web-acl'));
    expect(detail.textContent).toContain('POLICY_STATUS_ACTIVE');
  });

  it('shows a refused Details read in the detail', async () => {
    hook.get = vi.fn(() => Promise.reject(new Error('HTTP 404: policy not found')));
    render(<SDNPoliciesPage />);

    await act(async () => {
      fireEvent.click(within(screen.getByTestId('row-pol-1')).getByText('Details'));
    });

    const detail = await screen.findByTestId('sdn-policy-detail');
    await waitFor(() => expect(detail.textContent).toContain('HTTP 404: policy not found'));
  });

  it('gates Delete on the delete route and removes only after the confirm', async () => {
    render(<SDNPoliciesPage />);

    const del = within(screen.getByTestId('row-pol-1')).getByText('Delete');
    expect(del.getAttribute('data-op')).toBe(DELETE_OP);
    fireEvent.click(del);

    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText('Delete policy web-acl?')).toBeDefined();
    expect(hook.remove).not.toHaveBeenCalled();

    const confirm = within(dialog).getByRole('button', { name: 'Delete' });
    expect(confirm.getAttribute('data-capability-op')).toBe(DELETE_OP);
    await act(async () => {
      fireEvent.click(confirm);
    });
    expect(hook.remove).toHaveBeenCalledWith('pol-1');
  });

  it('shows the not-configured card and no table on 503', () => {
    hook.policies = [];
    hook.error = 'HTTP 503: sdn: not configured';
    hook.notConfigured = true;
    render(<SDNPoliciesPage />);

    expect(screen.getByTestId('sdn-policies-not-configured')).toBeDefined();
    expect(screen.queryByTestId('row-pol-1')).toBeNull();
  });

  it('shows another refused list as an error alert', () => {
    hook.policies = [];
    hook.error = 'HTTP 500: ovs down';
    render(<SDNPoliciesPage />);

    expect(screen.getByRole('alert').textContent).toContain('HTTP 500: ovs down');
    expect(screen.queryByTestId('sdn-policies-not-configured')).toBeNull();
  });

  it('withholds Apply Policy with the reason when the server does not offer it', async () => {
    off.add(APPLY_OP);
    render(<SDNPoliciesPage />);

    const open = button('Apply Policy');
    expect(open.disabled).toBe(true);
    expect(open.getAttribute('title')).toBe('not-configured: sdn');
    fireEvent.click(open);
    expect(screen.queryByRole('dialog')).toBeNull();
  });
});
