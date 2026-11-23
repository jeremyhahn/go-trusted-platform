import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ReactNode } from 'react';

import { ok, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { certificateToBase64 } from '@/hooks/use-sdn-port-auth';

// #2064: the ports page offers a "Port Authentication" row action that opens
// a dialog hosting SDNPortAuthCard for that port, so AuthenticatePort
// (POST /sdn/bridges/{name}/ports/{port}/auth) and RevokePortAuth (DELETE on
// the same path) are reachable from the console through the SDK client.

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

const AUTH = '/api/v1/sdn/bridges/br-int/ports/p1/auth';
// Made-up bytes, no real certificate.
const PEM = '-----BEGIN CERTIFICATE-----\nTUlJQg==\n-----END CERTIFICATE-----';

function routes(): Record<string, Answer> {
  return {
    'GET /api/v1/sdn/bridges': ok({ bridges: [{ id: 'br-int' }] }),
    'GET /api/v1/sdn/bridges/br-int/ports': ok({
      ports: [{ id: 'p1', config: { name: 'eth0' }, status: 'PORT_STATUS_UP' }],
    }),
    [`POST ${AUTH}`]: ok({
      status: { success: true, message: 'ok' },
      auth: { authenticated: true, certificateCn: 'port-p1.example.com' },
    }),
    [`DELETE ${AUTH}`]: ok({ status: { success: true, message: 'revoked' } }),
  };
}

async function openAuth(): Promise<HTMLElement> {
  render(withControlPlane(<PortsPage />));
  await screen.findByText('eth0');
  await act(async () => {
    fireEvent.click(within(screen.getByTestId('row-p1')).getByRole('button', { name: 'Port Authentication' }));
  });
  const dialog = await screen.findByRole('dialog');
  expect(within(dialog).getByRole('heading', { name: 'Port authentication: eth0' })).toBeDefined();
  return dialog;
}

describe('SDNPortsPage port authentication', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('authenticates the port through POST /sdn/bridges/{name}/ports/{port}/auth from the Port Authentication dialog', async () => {
    const sent = stubControlPlane(routes());
    const dialog = await openAuth();

    fireEvent.change(within(dialog).getByLabelText('Certificate'), { target: { value: PEM } });
    await act(async () => {
      fireEvent.click(within(dialog).getByRole('button', { name: 'Authenticate' }));
    });

    await within(dialog).findByTestId('sdn-port-auth-state');
    const posts = sent.filter((r) => r.method === 'POST' && r.path === AUTH);
    expect(posts).toHaveLength(1);
    expect(posts[0].body).toEqual({ certificate: certificateToBase64(PEM), format: 'PEM' });
  });

  it("revokes the port's authentication after the confirm through DELETE /sdn/bridges/{name}/ports/{port}/auth", async () => {
    const sent = stubControlPlane(routes());
    const dialog = await openAuth();

    await act(async () => {
      fireEvent.click(within(dialog).getByRole('button', { name: 'Revoke' }));
    });
    const dialogs = await screen.findAllByRole('dialog');
    const confirm = dialogs[dialogs.length - 1];
    expect(confirm.textContent).toContain('Revoke port authentication?');
    await act(async () => {
      fireEvent.click(within(confirm).getByRole('button', { name: 'Revoke' }));
    });

    await screen.findByText('Port authentication revoked: Port p1');
    expect(sent.filter((r) => r.method === 'DELETE' && r.path === AUTH)).toHaveLength(1);
  });
});
