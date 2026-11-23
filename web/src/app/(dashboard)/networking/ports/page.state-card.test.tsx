import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ReactNode } from 'react';

import { ok, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';

// #2064: the ports page offers a "Port State" row action that opens a dialog
// hosting SDNPortStateCard for that port, so GetPort
// (GET /sdn/bridges/{name}/ports/{port}/state) and SetPortState (PUT on the
// same path) are reachable from the console through the SDK client.

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

vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({ loading: false, error: undefined, capability: () => ({ enabled: true }) }),
}));

import PortsPage from './page';

const STATE = '/api/v1/sdn/bridges/br-int/ports/p1/state';

function routes(): Record<string, Answer> {
  return {
    'GET /api/v1/sdn/bridges': ok({ bridges: [{ id: 'br-int' }] }),
    'GET /api/v1/sdn/bridges/br-int/ports': ok({
      ports: [{ id: 'p1', config: { name: 'eth0' }, status: 'PORT_STATUS_UP' }],
    }),
    [`GET ${STATE}`]: ok({ port: { id: 'p1', config: { name: 'eth0' }, status: 'PORT_STATUS_UP' } }),
    [`PUT ${STATE}`]: ok({ status: { success: true } }),
  };
}

async function openState(): Promise<HTMLElement> {
  render(withControlPlane(<PortsPage />));
  await screen.findByText('eth0');
  await act(async () => {
    fireEvent.click(within(screen.getByTestId('row-p1')).getByRole('button', { name: 'Port State' }));
  });
  const dialog = await screen.findByRole('dialog');
  expect(within(dialog).getByRole('heading', { name: 'Port state: eth0' })).toBeDefined();
  return dialog;
}

describe('SDNPortsPage port state card (#2064)', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('opens the Port state card for the row from the Port State action', async () => {
    stubControlPlane(routes());
    const dialog = await openState();
    expect(within(dialog).getByText('Port state')).toBeDefined();
  });

  it('reads the port through GET /sdn/bridges/{name}/ports/{port}/state when the dialog opens', async () => {
    const sent = stubControlPlane(routes());
    await openState();
    await waitFor(() => expect(sent.filter((r) => r.method === 'GET' && r.path === STATE).length).toBeGreaterThan(0));
  });

  it('applies the admin state through PUT /sdn/bridges/{name}/ports/{port}/state from the dialog', async () => {
    const sent = stubControlPlane(routes());
    const dialog = await openState();
    await act(async () => {
      fireEvent.click(within(dialog).getByRole('button', { name: 'Apply' }));
    });
    await waitFor(() => expect(sent.filter((r) => r.method === 'PUT' && r.path === STATE)).toHaveLength(1));
  });
});
