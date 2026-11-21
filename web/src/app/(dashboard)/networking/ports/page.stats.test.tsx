import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ReactNode } from 'react';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';

// #2064: the ports page offers a "Port Statistics" row action that reads the
// port's counters through the real SDK client (GET
// /sdn/bridges/{name}/ports/{port}/stats) and shows them, or the switch's
// refusal, in a dialog.

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

const STATS_PATH = 'GET /api/v1/sdn/bridges/br-int/ports/p1/stats';

function routes(stats: Answer): Record<string, Answer> {
  return {
    'GET /api/v1/sdn/bridges': ok({ bridges: [{ id: 'br-int' }] }),
    'GET /api/v1/sdn/bridges/br-int/ports': ok({
      ports: [{ id: 'p1', config: { name: 'eth0' }, status: 'PORT_STATUS_UP' }],
    }),
    [STATS_PATH]: stats,
  };
}

async function openStats(): Promise<HTMLElement> {
  render(withControlPlane(<PortsPage />));
  await screen.findByText('eth0');
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Port Statistics' }));
  });
  return screen.findByRole('dialog');
}

/** statValue reads the value shown next to label in the dialog. */
function statValue(dialog: HTMLElement, label: string): string {
  return within(dialog).getByText(label).nextElementSibling?.textContent ?? '';
}

describe('SDNPortsPage port statistics', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("reads a port's counters through GET /sdn/bridges/{name}/ports/{port}/stats", async () => {
    const sent = stubControlPlane(
      routes(
        ok({
          stats: {
            packetsReceived: '1200',
            packetsSent: '800',
            bytesReceived: '2048',
            bytesSent: '1024',
            errors: '3',
            dropped: '7',
          },
        })
      )
    );
    const dialog = await openStats();

    expect(within(dialog).getByRole('heading', { name: 'Port statistics: eth0' })).toBeDefined();
    await within(dialog).findByText('Packets received');
    expect(statValue(dialog, 'Packets received')).toBe('1,200');
    expect(statValue(dialog, 'Packets sent')).toBe('800');
    expect(statValue(dialog, 'Bytes received')).toBe('2 KB');
    expect(statValue(dialog, 'Bytes sent')).toBe('1 KB');
    expect(statValue(dialog, 'Errors')).toBe('3');
    expect(statValue(dialog, 'Dropped')).toBe('7');
    expect(sent).toContainEqual({ method: 'GET', path: '/api/v1/sdn/bridges/br-int/ports/p1/stats', body: undefined });
  });

  it('shows a refused stats read in the dialog, not zeros', async () => {
    stubControlPlane(routes(refused(404, 'port not found')));
    const dialog = await openStats();

    expect(
      await within(dialog).findByText('The switch returned no statistics for eth0: port not found')
    ).toBeDefined();
    expect(within(dialog).queryByText('Packets received')).toBeNull();
  });
});
