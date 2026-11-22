import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ReactNode } from 'react';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';

// #2064: the ports page's Enable/Disable row action asks the operator to
// confirm, then sets the port's admin state through SetPortState
// (PUT /sdn/bridges/{name}/ports/{port}/state) and shows the switch's answer.

type Row = Record<string, unknown> & { id: string };
type Column = { id?: string; accessorKey?: string; cell?: (ctx: { row: { getValue: (k: string) => unknown; original: Row } }) => ReactNode };
type Action = { label: string; onClick: (rows: Row[]) => void };

// The table renders each column's own cell renderer; selection and paging are
// the table's.
vi.mock('@/components/ui/data-table', () => ({
  createSelectColumn: () => ({ id: 'select' }),
  DataTable: ({ columns, data, bulkActions }: { columns: Column[]; data: Row[]; bulkActions: Action[] }) => (
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
      {bulkActions.map((a) => (
        <button key={a.label} onClick={() => a.onClick(data)}>
          bulk-{a.label}
        </button>
      ))}
    </div>
  ),
}));

vi.mock('@/components/ui/data-table-row-actions', () => ({
  DataTableRowActions: ({ row, actions }: { row: Row; actions: { label: string; onClick: (r: Row) => void }[] }) => (
    <div>
      {actions.map((a) => (
        <button key={a.label} onClick={() => a.onClick(row)}>
          {a.label}
        </button>
      ))}
    </div>
  ),
}));

import PortsPage from './page';

const PORTS_PATH = '/api/v1/sdn/bridges/br-int/ports';

function routes(put: Answer): Record<string, Answer> {
  return {
    'GET /api/v1/sdn/bridges': ok({ bridges: [{ id: 'br-int' }] }),
    [`GET ${PORTS_PATH}`]: ok({
      ports: [
        { id: 'p1', config: { name: 'eth0' }, status: 'PORT_STATUS_UP' },
        { id: 'p2', config: { name: 'eth1' }, status: 'PORT_STATUS_DOWN' },
      ],
    }),
    [`PUT ${PORTS_PATH}/p1/state`]: put,
    [`PUT ${PORTS_PATH}/p2/state`]: put,
  };
}

function toasts(): string[] {
  return screen.queryAllByTestId('toast').map((t) => t.textContent ?? '');
}

async function openConfirm(rowId: string, action: string): Promise<HTMLElement> {
  render(withControlPlane(<PortsPage />));
  await screen.findByText('eth1');
  await act(async () => {
    fireEvent.click(within(screen.getByTestId(`row-${rowId}`)).getByText(action));
  });
  return screen.findByRole('dialog');
}

async function click(dialog: HTMLElement, name: string): Promise<void> {
  await act(async () => {
    fireEvent.click(within(dialog).getByRole('button', { name }));
  });
}

function portListReads(sent: { method: string; path: string }[]): number {
  return sent.filter((r) => r.method === 'GET' && r.path === PORTS_PATH).length;
}

describe('SDNPortsPage port state (#2064)', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('disables an up port after the confirm', async () => {
    const sent = stubControlPlane(routes(ok({ status: { success: true, message: 'port down' } })));
    const dialog = await openConfirm('p1', 'Disable');
    expect(within(dialog).getByRole('heading', { name: 'Disable port eth0?' })).toBeDefined();
    const before = portListReads(sent);

    await click(dialog, 'Disable port');

    await waitFor(() => expect(toasts()).toContain('Port disabled: port down'));
    expect(sent).toContainEqual({
      method: 'PUT',
      path: `${PORTS_PATH}/p1/state`,
      body: { adminState: 'down' },
    });
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    await waitFor(() => expect(portListReads(sent)).toBeGreaterThan(before));
  });

  it('enables a down port after the confirm', async () => {
    const sent = stubControlPlane(routes(ok({ status: { success: true, message: 'port up' } })));
    const dialog = await openConfirm('p2', 'Enable');
    expect(within(dialog).getByRole('heading', { name: 'Enable port eth1?' })).toBeDefined();

    await click(dialog, 'Enable port');

    await waitFor(() => expect(toasts()).toContain('Port enabled: port up'));
    expect(sent).toContainEqual({
      method: 'PUT',
      path: `${PORTS_PATH}/p2/state`,
      body: { adminState: 'up' },
    });
  });

  it('Cancel sends nothing', async () => {
    const sent = stubControlPlane(routes(ok({ status: { success: true, message: 'port down' } })));
    const dialog = await openConfirm('p1', 'Disable');

    await click(dialog, 'Cancel');

    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(sent.filter((r) => r.method === 'PUT')).toEqual([]);
  });

  it('shows a refused state change', async () => {
    stubControlPlane(routes(refused(403, 'port state denied by policy')));
    const dialog = await openConfirm('p1', 'Disable');

    await click(dialog, 'Disable port');

    const text = 'Port state change refused: port state denied by policy';
    await waitFor(() => expect(toasts()).toContain(text));
    const toast = screen.getAllByTestId('toast').find((t) => t.textContent === text);
    expect(toast?.getAttribute('data-variant')).toBe('destructive');
  });
});
