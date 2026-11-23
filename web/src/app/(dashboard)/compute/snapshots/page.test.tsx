import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer, type SentRequest } from '@/test/control-plane-fetch';
import SnapshotsPage from './page';

// #2044: the Snapshots page's Create Snapshot opens a gated dialog (source
// VM, name, include memory) that sends CreateSnapshot through the real SDK
// client; a refusal reaches the operator as a destructive toast.

vi.mock('next/navigation', () => ({
  useParams: () => ({}),
  usePathname: () => '/compute/snapshots',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const CREATE_OP = 'POST /api/v1/compute/vms/{id}/snapshots';

const SNAPSHOT_OPS = [
  CREATE_OP,
  'POST /api/v1/compute/vms/{id}/snapshots/{snapshotId}/restore',
  'DELETE /api/v1/compute/vms/{id}/snapshots/{snapshotId}',
] as const;

// The server's capabilities listing: every snapshot op enabled except those in off.
function caps(off: string[] = []): Answer {
  const capabilities = SNAPSHOT_OPS.map((op) =>
    off.includes(op)
      ? { op, kind: 'route', enabled: false, reason: 'not-configured: compute' }
      : { op, kind: 'route', enabled: true },
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

const LIST = '/api/v1/compute/vms/vm-1/snapshots';

function shared(): Record<string, Answer> {
  return {
    'GET /api/v1/capabilities': caps(),
    'GET /api/v1/compute/vms': ok({ vms: [{ id: 'vm-1', config: { name: 'web-1' }, state: 'VM_STATE_RUNNING' }] }),
    [`GET ${LIST}`]: ok({ snapshots: [] }),
  };
}

async function renderPage() {
  render(withControlPlane(<SnapshotsPage />));
  await screen.findByText('No Snapshots Found');
}

async function openDialog() {
  await waitFor(() =>
    expect(screen.getByRole('button', { name: /Create Snapshot/ }).getAttribute('data-capability-enabled')).toBe('true'),
  );
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: /Create Snapshot/ }));
  });
  return within(await screen.findByRole('dialog'));
}

function posts(sent: SentRequest[]) {
  return sent.filter((r) => r.method === 'POST' && r.path === LIST);
}

describe('SnapshotsPage Create Snapshot', () => {
  it('creates a snapshot of the chosen VM through POST /compute/vms/{id}/snapshots', async () => {
    const sent = stubControlPlane({
      ...shared(),
      [`POST ${LIST}`]: ok({
        status: { success: true },
        snapshot: {
          id: 's1',
          vmId: 'vm-1',
          config: { name: 'nightly' },
          createdAt: '2026-11-01T00:00:00Z',
          sizeBytes: 1048576,
          vmState: 'VM_STATE_RUNNING',
        },
      }),
    });
    await renderPage();

    const dialog = await openDialog();
    fireEvent.change(dialog.getByLabelText('Source VM'), { target: { value: 'vm-1' } });
    fireEvent.change(dialog.getByLabelText('Snapshot name'), { target: { value: 'nightly' } });
    fireEvent.click(dialog.getByLabelText('Include memory'));
    await act(async () => {
      fireEvent.click(dialog.getByRole('button', { name: 'Create' }));
    });

    await waitFor(() => expect(posts(sent)).toHaveLength(1));
    expect(posts(sent)[0]).toEqual({
      method: 'POST',
      path: LIST,
      body: { config: { name: 'nightly', memorySnapshot: true } },
    });
    await waitFor(() =>
      expect(screen.getAllByTestId('toast').some((t) => t.getAttribute('data-variant') === 'success')).toBe(true),
    );
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    await waitFor(() => {
      const postAt = sent.findIndex((r) => r.method === 'POST' && r.path === LIST);
      expect(sent.slice(postAt + 1).some((r) => r.method === 'GET' && r.path === LIST)).toBe(true);
    });
  });

  it('does not send without a VM and a name', async () => {
    const sent = stubControlPlane(shared());
    await renderPage();

    const dialog = await openDialog();
    const create = () => dialog.getByRole('button', { name: 'Create' }) as HTMLButtonElement;
    expect(create().disabled).toBe(true);

    fireEvent.change(dialog.getByLabelText('Source VM'), { target: { value: 'vm-1' } });
    expect(create().disabled).toBe(true);

    fireEvent.change(dialog.getByLabelText('Snapshot name'), { target: { value: '   ' } });
    expect(create().disabled).toBe(true);
    await act(async () => {
      fireEvent.click(create());
    });

    fireEvent.change(dialog.getByLabelText('Source VM'), { target: { value: '' } });
    fireEvent.change(dialog.getByLabelText('Snapshot name'), { target: { value: 'nightly' } });
    expect(create().disabled).toBe(true);

    expect(posts(sent)).toHaveLength(0);
  });

  it('withholds Create Snapshot when the server does not offer it', async () => {
    stubControlPlane({ ...shared(), 'GET /api/v1/capabilities': caps([CREATE_OP]) });
    await renderPage();

    await waitFor(() => {
      const button = screen.getByRole('button', { name: /Create Snapshot/ }) as HTMLButtonElement;
      expect(button.getAttribute('data-capability-enabled')).toBe('false');
      expect(button.disabled).toBe(true);
      expect(button.title).toBe('not-configured: compute');
    });
  });

  it('shows a refused create as a destructive toast and keeps the dialog open', async () => {
    stubControlPlane({ ...shared(), [`POST ${LIST}`]: refused(409, 'compute: vm is not running') });
    await renderPage();

    const dialog = await openDialog();
    fireEvent.change(dialog.getByLabelText('Source VM'), { target: { value: 'vm-1' } });
    fireEvent.change(dialog.getByLabelText('Snapshot name'), { target: { value: 'nightly' } });
    await act(async () => {
      fireEvent.click(dialog.getByRole('button', { name: 'Create' }));
    });

    await waitFor(() => {
      const destructive = screen
        .getAllByTestId('toast')
        .filter((t) => t.getAttribute('data-variant') === 'destructive');
      expect(destructive.some((t) => (t.textContent ?? '').includes('not running'))).toBe(true);
    });
    expect(screen.getByRole('dialog')).toBeTruthy();
  });
});

// #2044: each snapshot row offers Restore and Delete as gated buttons; the
// operation is sent through the SDK only after the operator confirms it in a
// dialog, and the Clone and Export placeholders are gone.
describe('SnapshotsPage row actions', () => {
  const ROW = '/api/v1/compute/vms/vm-1/snapshots/s1';
  const RESTORE_OP = 'POST /api/v1/compute/vms/{id}/snapshots/{snapshotId}/restore';
  const DELETE_OP = 'DELETE /api/v1/compute/vms/{id}/snapshots/{snapshotId}';

  function withSnapshot(): Record<string, Answer> {
    return {
      ...shared(),
      [`GET ${LIST}`]: ok({
        snapshots: [
          {
            id: 's1',
            vmId: 'vm-1',
            config: { name: 'nightly' },
            createdAt: '2026-11-01T00:00:00Z',
            sizeBytes: 1048576,
            vmState: 'VM_STATE_RUNNING',
          },
        ],
      }),
    };
  }

  async function renderWithRow() {
    render(withControlPlane(<SnapshotsPage />));
    await screen.findByText('nightly');
  }

  function rowButton(name: string) {
    return screen.getByRole('button', { name }) as HTMLButtonElement;
  }

  async function clickWhenEnabled(name: string) {
    await waitFor(() => expect(rowButton(name).getAttribute('data-capability-enabled')).toBe('true'));
    await act(async () => {
      fireEvent.click(rowButton(name));
    });
  }

  async function confirm(title: string, button: string) {
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText(title)).toBeTruthy();
    await act(async () => {
      fireEvent.click(within(dialog).getByRole('button', { name: button }));
    });
  }

  function toasts(variant: string) {
    return screen.queryAllByTestId('toast').filter((t) => t.getAttribute('data-variant') === variant);
  }

  it('restores a snapshot only after the confirm', async () => {
    const sent = stubControlPlane({
      ...withSnapshot(),
      [`POST ${ROW}/restore`]: ok({ status: { success: true } }),
    });
    await renderWithRow();

    await clickWhenEnabled('Restore nightly');
    const restores = () => sent.filter((r) => r.method === 'POST' && r.path === `${ROW}/restore`);
    expect(restores()).toHaveLength(0);

    await confirm('Restore snapshot?', 'Restore');
    await waitFor(() => expect(restores()).toHaveLength(1));
    expect(restores()[0].method).toBe('POST');
    expect(restores()[0].path).toBe('/api/v1/compute/vms/vm-1/snapshots/s1/restore');
    await waitFor(() => expect(toasts('success').length).toBeGreaterThan(0));
    expect(screen.queryByText('Clone to New Instance')).toBeNull();
    expect(screen.queryByText('Export')).toBeNull();
  });

  it('deletes a snapshot after the confirm and re-lists', async () => {
    const sent = stubControlPlane({
      ...withSnapshot(),
      [`DELETE ${ROW}`]: ok({ status: { success: true } }),
    });
    await renderWithRow();

    await clickWhenEnabled('Delete nightly');
    const deletes = () => sent.filter((r) => r.method === 'DELETE' && r.path === ROW);
    expect(deletes()).toHaveLength(0);

    await confirm('Delete snapshot?', 'Delete');
    await waitFor(() => expect(deletes()).toHaveLength(1));
    await waitFor(() => {
      const deleteAt = sent.findIndex((r) => r.method === 'DELETE' && r.path === ROW);
      expect(sent.slice(deleteAt + 1).some((r) => r.method === 'GET' && r.path === LIST)).toBe(true);
    });
  });

  it('withholds Restore and Delete when the server does not offer them', async () => {
    stubControlPlane({ ...withSnapshot(), 'GET /api/v1/capabilities': caps([RESTORE_OP, DELETE_OP]) });
    await renderWithRow();

    await waitFor(() => {
      for (const name of ['Restore nightly', 'Delete nightly']) {
        const button = rowButton(name);
        expect(button.getAttribute('data-capability-enabled')).toBe('false');
        expect(button.disabled).toBe(true);
        expect(button.title).toBe('not-configured: compute');
      }
    });
  });

  it('shows a refused delete as a destructive toast', async () => {
    stubControlPlane({ ...withSnapshot(), [`DELETE ${ROW}`]: refused(409, 'compute: snapshot in use') });
    await renderWithRow();

    await clickWhenEnabled('Delete nightly');
    await confirm('Delete snapshot?', 'Delete');
    await waitFor(() =>
      expect(toasts('destructive').some((t) => (t.textContent ?? '').includes('in use'))).toBe(true),
    );
  });
});
