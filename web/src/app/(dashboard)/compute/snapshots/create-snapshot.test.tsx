import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import SnapshotsPage from './page';

// #2044: the snapshots page creates a VM snapshot through the SDK
// ComputeService.createSnapshot (POST /vms/{id}/snapshots), driven against
// the real SDK client with only fetch stubbed.

const SNAPSHOTS_PATH = '/api/v1/compute/vms/vm-1/snapshots';

const vm = {
  id: 'vm-1',
  config: { name: 'web-01' },
  state: 'VM_STATE_RUNNING',
  createdAt: '2026-11-20T00:00:00Z',
  updatedAt: '2026-11-20T00:00:00Z',
};

const snapshot = {
  id: 'snap-1',
  vmId: 'vm-1',
  config: { name: 'pre-upgrade' },
  createdAt: '2026-11-21T00:00:00Z',
  sizeBytes: 1048576,
  vmState: 'VM_STATE_RUNNING',
};

const created: Answer = {
  status: 201,
  body: { code: 201, success: true, payload: { snapshot } },
};

function controlPlane(create: Answer): { routes: Record<string, Answer>; sent: ReturnType<typeof stubControlPlane> } {
  const routes: Record<string, Answer> = {
    'GET /api/v1/compute/vms': ok({ vms: [vm] }),
    [`GET ${SNAPSHOTS_PATH}`]: ok({ snapshots: [] }),
    [`POST ${SNAPSHOTS_PATH}`]: create,
  };
  const sent = stubControlPlane(routes);
  return { routes, sent };
}

async function renderPage() {
  render(withControlPlane(<SnapshotsPage />));
  await screen.findByText('No Snapshots Found');
}

async function click(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

function type(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

describe('SnapshotsPage Create Snapshot', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('creates a snapshot through POST /vms/{id}/snapshots and re-reads the list', async () => {
    const { routes, sent } = controlPlane(created);
    await renderPage();

    await click('Create Snapshot');
    type('Name', 'pre-upgrade');
    type('Description', 'before kernel 6.12');

    routes[`GET ${SNAPSHOTS_PATH}`] = ok({ snapshots: [snapshot] });
    await click('Create');

    await waitFor(() =>
      expect(sent).toContainEqual({
        method: 'POST',
        path: SNAPSHOTS_PATH,
        body: {
          config: {
            name: 'pre-upgrade',
            description: 'before kernel 6.12',
            memorySnapshot: true,
            diskSnapshot: true,
          },
        },
      })
    );
    await waitFor(() => {
      const post = sent.findIndex((r) => r.method === 'POST' && r.path === SNAPSHOTS_PATH);
      const reread = sent.findIndex((r, i) => i > post && r.method === 'GET' && r.path === SNAPSHOTS_PATH);
      expect(reread).toBeGreaterThan(post);
    });

    expect(await screen.findByText('pre-upgrade')).toBeTruthy();
    const toasts = await screen.findAllByTestId('toast');
    expect(toasts.map((t) => t.textContent)).toContain('Snapshot created: Snapshot pre-upgrade was created');
  });

  it('submits the default dialog as a full memory-and-disk snapshot and offers no memory toggle', async () => {
    const { sent } = controlPlane(created);
    await renderPage();

    await click('Create Snapshot');
    expect(screen.queryByLabelText('Include memory')).toBeNull();
    expect(screen.getByText(/captures both the VM's memory and its disks/i)).toBeTruthy();

    type('Name', 'nightly');
    await click('Create');

    await waitFor(() =>
      expect(sent).toContainEqual({
        method: 'POST',
        path: SNAPSHOTS_PATH,
        body: { config: { name: 'nightly', memorySnapshot: true, diskSnapshot: true } },
      }),
    );
  });

  it('shows a refused create as a destructive toast and keeps the dialog open', async () => {
    controlPlane(refused(409, 'snapshot pre-upgrade already exists'));
    await renderPage();

    await click('Create Snapshot');
    type('Name', 'pre-upgrade');
    await click('Create');

    await waitFor(() => {
      const destructive = screen
        .queryAllByTestId('toast')
        .filter((t) => t.getAttribute('data-variant') === 'destructive');
      expect(destructive.map((t) => t.textContent)).toContain(
        'Error creating snapshot: snapshot pre-upgrade already exists'
      );
    });
    expect((screen.getByLabelText('Name') as HTMLInputElement).value).toBe('pre-upgrade');
  });

  it('does not send a create until a name is typed', async () => {
    const { sent } = controlPlane(created);
    await renderPage();

    await click('Create Snapshot');

    expect((screen.getByRole('button', { name: 'Create' }) as HTMLButtonElement).disabled).toBe(true);
    expect(sent.some((r) => r.method === 'POST')).toBe(false);
  });
});
