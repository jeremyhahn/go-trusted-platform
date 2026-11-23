import { cleanup, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ReactNode } from 'react';

import { refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';

// #2064: platformd answers 503 on the SDN routes when it runs without an SDN
// service. The ports page then says SDN is not configured, as the cluster page
// does for its own 503, instead of showing an error. The SDK retries a 5xx read
// three times with backoff (about 7 s) before the page sees the error.

const SETTLED = { timeout: 20_000 };

type Row = Record<string, unknown> & { id: string };
type Column = { id?: string; accessorKey?: string; cell?: (ctx: { row: { getValue: (k: string) => unknown; original: Row } }) => ReactNode };
type Action = { label: string; onClick: (rows: Row[]) => void };

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

describe('SDN ports page without SDN', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('shows the not-configured card when the bridges read answers 503', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/sdn/bridges': refused(503, 'sdn service unavailable'),
    });
    render(withControlPlane(<PortsPage />));

    const card = await screen.findByTestId('sdn-not-configured', {}, SETTLED);
    expect(card.textContent).toContain('SDN not configured');
    expect(card.textContent).toContain('sdn service unavailable');
    expect(screen.queryByText('Error Loading Ports')).toBeNull();
    expect(sent.some((r) => r.path.startsWith('/api/v1/sdn/bridges/'))).toBe(false);
  }, 30_000);

  it('keeps the error alert for any other refused read', async () => {
    stubControlPlane({
      'GET /api/v1/sdn/bridges': refused(500, 'boom'),
    });
    render(withControlPlane(<PortsPage />));

    expect(await screen.findByText('Error Loading Ports', {}, SETTLED)).toBeDefined();
    await waitFor(() => expect(screen.getByText(/boom/)).toBeDefined());
    expect(screen.queryByTestId('sdn-not-configured')).toBeNull();
  }, 30_000);
});
