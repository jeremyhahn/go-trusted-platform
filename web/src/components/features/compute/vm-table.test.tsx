import type { ReactNode } from 'react';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import type { VM } from '@/types/infrastructure';
import { VMTable } from './vm-table';

// #2044: the VM list's Start, Stop, Reboot and Delete menu items sit behind
// the server's capability gate and send their op through the SDK client.

// Plain elements so every menu item renders without opening the menu, and the
// props Gated clones in reach the DOM.
vi.mock('@/components/ui/dropdown-menu', () => {
  const Plain = ({ children }: { children?: ReactNode }) => <div>{children}</div>;
  return {
    DropdownMenu: Plain,
    DropdownMenuContent: Plain,
    DropdownMenuLabel: Plain,
    DropdownMenuSeparator: Plain,
    DropdownMenuTrigger: Plain,
    DropdownMenuItem: ({ children, ...p }: { children?: ReactNode } & Record<string, unknown>) => (
      <button type="button" role="menuitem" {...p}>
        {children}
      </button>
    ),
  };
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const START_OP = 'POST /api/v1/compute/vms/{id}/start';
const STOP_OP = 'POST /api/v1/compute/vms/{id}/stop';
const REBOOT_OP = 'POST /api/v1/compute/vms/{id}/reboot';
const DELETE_OP = 'DELETE /api/v1/compute/vms/{id}';
const VM_OPS = [START_OP, STOP_OP, REBOOT_OP, DELETE_OP] as const;
const REASON = 'not-configured: compute';

// The server's capabilities listing: every VM op enabled except those in off.
function caps(off: string[] = []): Answer {
  const capabilities = VM_OPS.map((op) =>
    off.includes(op) ? { op, kind: 'route', enabled: false, reason: REASON } : { op, kind: 'route', enabled: true },
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

const stopped: VM = {
  id: 'vm-1',
  name: 'web-1',
  status: 'stopped',
  vcpus: 2,
  memoryMB: 2048,
  storageMB: 20480,
  ipAddress: '192.0.2.10',
  createdAt: '2026-11-01T00:00:00Z',
};

const running: VM = {
  id: 'vm-2',
  name: 'web-2',
  status: 'running',
  vcpus: 4,
  memoryMB: 4096,
  storageMB: 40960,
  ipAddress: '192.0.2.11',
  createdAt: '2026-11-01T00:00:00Z',
};

function renderTable() {
  render(withControlPlane(<VMTable vms={[stopped, running]} onRefresh={vi.fn()} />));
}

function item(name: string, index = 0): HTMLButtonElement {
  return screen.getAllByRole('menuitem', { name })[index] as HTMLButtonElement;
}

async function expectOff(name: string, op: string, index = 0) {
  await waitFor(() => {
    const el = item(name, index);
    expect(el.getAttribute('data-capability-op')).toBe(op);
    expect(el.getAttribute('data-capability-enabled')).toBe('false');
    expect(el.disabled).toBe(true);
    expect(el.title).toBe(REASON);
  });
}

describe('VMTable capability gate', () => {
  it('disables Start when the server does not enable StartVM', async () => {
    stubControlPlane({ 'GET /api/v1/capabilities': caps([START_OP]) });
    renderTable();

    await expectOff('Start', START_OP);
    await waitFor(() => expect(item('Stop').disabled).toBe(false));
  });

  it('disables Stop and Reboot when their ops are off', async () => {
    stubControlPlane({ 'GET /api/v1/capabilities': caps([STOP_OP, REBOOT_OP]) });
    renderTable();

    await expectOff('Stop', STOP_OP);
    await expectOff('Reboot', REBOOT_OP);
    await waitFor(() => expect(item('Start').disabled).toBe(false));
  });

  it('disables Delete when DeleteVM is off', async () => {
    stubControlPlane({ 'GET /api/v1/capabilities': caps([DELETE_OP]) });
    renderTable();

    await expectOff('Delete', DELETE_OP, 0);
    await expectOff('Delete', DELETE_OP, 1);
  });

  it('starts a VM through POST /compute/vms/{id}/start when enabled', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      'POST /api/v1/compute/vms/vm-1/start': ok({ status: { code: 0, message: 'started' } }),
    });
    renderTable();

    await waitFor(() => {
      const start = item('Start');
      expect(start.getAttribute('data-capability-enabled')).toBe('true');
      expect(start.disabled).toBe(false);
    });
    await act(async () => {
      fireEvent.click(item('Start'));
    });

    await waitFor(() => {
      expect(sent.some((r) => r.method === 'POST' && r.path === '/api/v1/compute/vms/vm-1/start')).toBe(true);
    });
  });
});
