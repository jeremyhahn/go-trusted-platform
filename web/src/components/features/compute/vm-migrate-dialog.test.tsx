import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { VMMigrateButton } from './vm-migrate-dialog';

// #2044: the VM detail page's Migrate button opens a dialog that sends
// MigrateVM through the SDK ComputeService (useVMMigration), behind the
// server's capability gate; a refusal reaches the operator as a destructive
// toast and leaves the dialog open.

vi.mock('next/navigation', () => ({
  useParams: () => ({ id: 'vm-1' }),
  usePathname: () => '/compute/vms/vm-1',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const MIGRATE_OP = 'POST /api/v1/compute/vms/{id}/migrate';
const MIGRATE_PATH = 'POST /api/v1/compute/vms/vm-1/migrate';

// The server's capabilities listing: the migrate op enabled unless off.
function caps(off = false): Answer {
  const capabilities = [
    off
      ? { op: MIGRATE_OP, kind: 'route', enabled: false, reason: 'not-configured: compute' }
      : { op: MIGRATE_OP, kind: 'route', enabled: true },
  ];
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

function renderButton(onMigrated: () => void) {
  render(withControlPlane(<VMMigrateButton vmId="vm-1" onMigrated={onMigrated} />));
}

async function openDialog() {
  await waitFor(() => {
    expect(screen.getByRole('button', { name: 'Migrate' }).getAttribute('data-capability-enabled')).toBe('true');
  });
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Migrate' }));
  });
  return screen.findByRole('dialog');
}

describe('VMMigrateButton', () => {
  it('migrates the VM through POST /compute/vms/{id}/migrate', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      [MIGRATE_PATH]: ok({ migrationId: 'mig-1' }),
    });
    const onMigrated = vi.fn();
    renderButton(onMigrated);

    const dialog = await openDialog();
    fireEvent.change(within(dialog).getByLabelText('Destination host'), { target: { value: 'host-b' } });
    fireEvent.click(within(dialog).getByLabelText('Live migration'));
    await act(async () => {
      fireEvent.click(within(dialog).getByRole('button', { name: 'Start migration' }));
    });

    await waitFor(() => {
      expect(sent).toContainEqual({
        method: 'POST',
        path: '/api/v1/compute/vms/vm-1/migrate',
        body: { destinationHost: 'host-b', liveMigration: true },
      });
    });
    await waitFor(() => {
      const toasts = screen.getAllByTestId('toast');
      expect(toasts.some((t) => t.getAttribute('data-variant') === 'success')).toBe(true);
    });
    await waitFor(() => {
      expect(screen.queryByRole('dialog')).toBeNull();
    });
    expect(onMigrated).toHaveBeenCalledTimes(1);
  });

  it('does not send without a destination host', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      [MIGRATE_PATH]: ok({ migrationId: 'mig-1' }),
    });
    renderButton(vi.fn());

    const dialog = await openDialog();
    const start = within(dialog).getByRole('button', { name: 'Start migration' }) as HTMLButtonElement;
    expect(start.disabled).toBe(true);
    fireEvent.change(within(dialog).getByLabelText('Destination host'), { target: { value: '   ' } });
    expect(start.disabled).toBe(true);
    await act(async () => {
      fireEvent.click(start);
    });
    expect(sent.some((r) => r.method === 'POST' && r.path === '/api/v1/compute/vms/vm-1/migrate')).toBe(false);
  });

  it('withholds Migrate when the server does not offer it', async () => {
    stubControlPlane({ 'GET /api/v1/capabilities': caps(true) });
    renderButton(vi.fn());

    await waitFor(() => {
      const button = screen.getByRole('button', { name: 'Migrate' }) as HTMLButtonElement;
      expect(button.getAttribute('title')).toBe('not-configured: compute');
      expect(button.disabled).toBe(true);
      expect(button.getAttribute('data-capability-enabled')).toBe('false');
    });
  });

  it('disables Migrate for a guest with a vTPM', async () => {
    const reason = 'Live migration of a guest with a vTPM is not supported';
    stubControlPlane({ 'GET /api/v1/capabilities': caps() });
    render(withControlPlane(<VMMigrateButton vmId="vm-1" onMigrated={vi.fn()} unsupportedReason={reason} />));

    await waitFor(() => {
      const button = screen.getByRole('button', { name: 'Migrate' }) as HTMLButtonElement;
      expect(button.getAttribute('data-capability-enabled')).toBe('true');
      expect(button.disabled).toBe(true);
    });
    expect(screen.getByText(reason)).toBeDefined();
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Migrate' }));
    });
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('shows a refused migration as a destructive toast and keeps the dialog open', async () => {
    stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      [MIGRATE_PATH]: refused(409, 'compute: destination unreachable'),
    });
    const onMigrated = vi.fn();
    renderButton(onMigrated);

    const dialog = await openDialog();
    fireEvent.change(within(dialog).getByLabelText('Destination host'), { target: { value: 'host-b' } });
    await act(async () => {
      fireEvent.click(within(dialog).getByRole('button', { name: 'Start migration' }));
    });

    await waitFor(() => {
      const toasts = screen.getAllByTestId('toast');
      expect(
        toasts.some(
          (t) => t.getAttribute('data-variant') === 'destructive' && t.textContent?.includes('unreachable'),
        ),
      ).toBe(true);
    });
    expect(screen.getByRole('dialog')).toBeDefined();
    expect(onMigrated).not.toHaveBeenCalled();
  });
});
