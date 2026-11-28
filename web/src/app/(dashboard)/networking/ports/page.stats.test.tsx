import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
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

const STATS_OP = 'GET /api/v1/sdn/bridges/{name}/ports/{port}/stats';

// Ops the capability gate withholds; every other op is enabled.
const { off } = vi.hoisted(() => ({ off: new Set<string>() }));

vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({
    loading: false,
    error: undefined,
    capability: (op: string) =>
      off.has(op) ? { enabled: false, reason: 'not-configured: sdn' } : { enabled: true },
  }),
}));

// Each row action carries its op; a withheld op disables it, as the real
// row actions' Gated does.
vi.mock('@/components/ui/data-table-row-actions', () => ({
  DataTableRowActions: ({ row, actions }: { row: Row; actions: { label: string; op?: string; onClick: (r: Row) => void }[] }) => (
    <div>
      {actions.map((a) => (
        <button
          key={a.label}
          data-op={a.op}
          disabled={a.op !== undefined && off.has(a.op)}
          onClick={() => a.onClick(row)}
        >
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
    off.clear();
  });

  it('gates Port Statistics on GET /api/v1/sdn/bridges/{name}/ports/{port}/stats', async () => {
    stubControlPlane(routes(ok({ stats: {} })));
    render(withControlPlane(<PortsPage />));
    await screen.findByText('eth0');
    const action = screen.getByRole('button', { name: 'Port Statistics' }) as HTMLButtonElement;
    expect(action.getAttribute('data-op')).toBe(STATS_OP);
    expect(action.disabled).toBe(false);
    cleanup();

    off.add(STATS_OP);
    render(withControlPlane(<PortsPage />));
    await screen.findByText('eth0');
    expect((screen.getByRole('button', { name: 'Port Statistics' }) as HTMLButtonElement).disabled).toBe(true);
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

  // stubDeferredStats answers the bridge and port lists at once and holds
  // every stats read until the test releases it, so reads resolve in the
  // order the test chooses.
  function stubDeferredStats(): (path: string, answer: Answer) => Promise<void> {
    const pending = new Map<string, (a: Answer) => void>();
    const respond = (answer: Answer) =>
      new Response(JSON.stringify(answer.body), {
        status: answer.status,
        headers: { 'Content-Type': 'application/json' },
      });
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = new URL(input instanceof Request ? input.url : String(input));
        const method = (init?.method ?? 'GET').toUpperCase();
        if (method === 'GET' && url.pathname === '/api/v1/sdn/bridges') {
          return respond(ok({ bridges: [{ id: 'br-int' }] }));
        }
        if (method === 'GET' && url.pathname === '/api/v1/sdn/bridges/br-int/ports') {
          return respond(
            ok({
              ports: [
                { id: 'p1', config: { name: 'eth0' }, status: 'PORT_STATUS_UP' },
                { id: 'p2', config: { name: 'eth1' }, status: 'PORT_STATUS_UP' },
              ],
            })
          );
        }
        if (url.pathname.endsWith('/stats')) {
          return new Promise<Response>((resolve) => {
            pending.set(url.pathname, (a) => resolve(respond(a)));
          });
        }
        return respond(refused(404, `no route for ${method} ${url.pathname}`));
      })
    );
    return async (path, answer) => {
      await act(async () => {
        pending.get(path)!(answer);
      });
    };
  }

  async function clickStats(id: string): Promise<void> {
    await act(async () => {
      fireEvent.click(within(screen.getByTestId(`row-${id}`)).getByText('Port Statistics'));
    });
  }

  function statsOf(n: number): Answer {
    return ok({
      stats: {
        packetsReceived: String(n),
        packetsSent: '0',
        bytesReceived: '0',
        bytesSent: '0',
        errors: '0',
        dropped: '0',
      },
    });
  }

  it("a closed dialog's late counters do not replace the next port's", async () => {
    const release = stubDeferredStats();
    render(withControlPlane(<PortsPage />));
    await screen.findByText('eth1');

    await clickStats('p1');
    await act(async () => {
      fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Close' }));
    });
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());

    await clickStats('p2');
    await release('/api/v1/sdn/bridges/br-int/ports/p2/stats', statsOf(2));
    const dialog = screen.getByRole('dialog');
    await within(dialog).findByText('Packets received');
    expect(statValue(dialog, 'Packets received')).toBe('2');

    await release('/api/v1/sdn/bridges/br-int/ports/p1/stats', statsOf(1200));
    const after = screen.getByRole('dialog');
    expect(within(after).getByRole('heading', { name: 'Port statistics: eth1' })).toBeDefined();
    expect(statValue(after, 'Packets received')).toBe('2');
  });

  it("a superseded read's late refusal does not replace the current counters", async () => {
    const release = stubDeferredStats();
    render(withControlPlane(<PortsPage />));
    await screen.findByText('eth1');

    await clickStats('p1');
    await clickStats('p2');
    await release('/api/v1/sdn/bridges/br-int/ports/p2/stats', statsOf(2));
    await within(screen.getByRole('dialog')).findByText('Packets received');

    await release('/api/v1/sdn/bridges/br-int/ports/p1/stats', refused(404, 'port not found'));
    const dialog = screen.getByRole('dialog');
    expect(within(dialog).queryByText(/The switch returned no statistics/)).toBeNull();
    expect(within(dialog).getByRole('heading', { name: 'Port statistics: eth1' })).toBeDefined();
    expect(statValue(dialog, 'Packets received')).toBe('2');
  });
});
