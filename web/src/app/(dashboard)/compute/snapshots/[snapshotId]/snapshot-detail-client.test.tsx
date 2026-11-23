import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer, type SentRequest } from '@/test/control-plane-fetch';
import SnapshotDetailClient from './snapshot-detail-client';

// #2044: the snapshot detail page reads one snapshot through the SDK's
// ComputeService.getSnapshot; the snapshot id comes from the path (the static
// export serves the __placeholder__ page) and the VM id from ?vm=.

let search = new URLSearchParams('vm=vm-1');

vi.mock('next/navigation', () => ({
  useParams: () => ({ snapshotId: '__placeholder__' }),
  usePathname: () => '/compute/snapshots/snap-1',
  useSearchParams: () => search,
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

beforeEach(() => {
  search = new URLSearchParams('vm=vm-1');
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const GET_OP = 'GET /api/v1/compute/vms/{id}/snapshots/{snapshotId}';
const SNAPSHOT_OPS = [GET_OP] as const;
const SNAPSHOT_PATH = '/api/v1/compute/vms/vm-1/snapshots/snap-1';

// The server's capabilities listing: every snapshot op enabled except those in off.
function caps(off: string[] = []): Answer {
  const capabilities = SNAPSHOT_OPS.map((op) =>
    off.includes(op)
      ? { op, kind: 'route', enabled: false, reason: 'not-configured: compute' }
      : { op, kind: 'route', enabled: true },
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

function storedSnapshot(): Answer {
  return ok({
    snapshot: {
      id: 'snap-1',
      vmId: 'vm-1',
      config: { name: 'pre-upgrade', description: 'before the kernel bump', memorySnapshot: true, diskSnapshot: true },
      createdAt: '2026-11-01T00:00:00Z',
      sizeBytes: 1073741824,
      vmState: 'VM_STATE_RUNNING',
    },
  });
}

function reads(sent: SentRequest[]) {
  return sent.filter((r) => r.method === 'GET' && r.path === SNAPSHOT_PATH);
}

function refresh() {
  return screen.getByRole('button', { name: /Refresh/ }) as HTMLButtonElement;
}

describe('SnapshotDetailClient', () => {
  it('reads the snapshot through GET /compute/vms/{id}/snapshots/{snapshotId}', async () => {
    const sent = stubControlPlane({ 'GET /api/v1/capabilities': caps(), [`GET ${SNAPSHOT_PATH}`]: storedSnapshot() });
    render(withControlPlane(<SnapshotDetailClient />));

    await screen.findByRole('heading', { level: 1, name: 'pre-upgrade' });
    expect(sent).toContainEqual({ method: 'GET', path: SNAPSHOT_PATH, body: undefined });
    expect(screen.getByText('before the kernel bump')).toBeTruthy();
    expect(screen.getByText('1.0 GB')).toBeTruthy();
    expect(screen.getByText('vm-1')).toBeTruthy();
    expect(screen.getByText(/running/i)).toBeTruthy();
    const vmLink = screen.getAllByRole('link').find((a) => a.getAttribute('href') === '/compute/vms/vm-1');
    expect(vmLink).toBeTruthy();
  });

  it('re-reads on Refresh', async () => {
    const sent = stubControlPlane({ 'GET /api/v1/capabilities': caps(), [`GET ${SNAPSHOT_PATH}`]: storedSnapshot() });
    render(withControlPlane(<SnapshotDetailClient />));
    await screen.findByRole('heading', { level: 1, name: 'pre-upgrade' });

    await waitFor(() => expect(refresh().disabled).toBe(false));
    await act(async () => {
      fireEvent.click(refresh());
    });
    await waitFor(() => expect(reads(sent)).toHaveLength(2));
  });

  it('disables Refresh when GetSnapshot is off', async () => {
    stubControlPlane({ 'GET /api/v1/capabilities': caps([GET_OP]), [`GET ${SNAPSHOT_PATH}`]: storedSnapshot() });
    render(withControlPlane(<SnapshotDetailClient />));
    await screen.findByRole('heading', { level: 1, name: 'pre-upgrade' });

    await waitFor(() => {
      const button = refresh();
      expect(button.getAttribute('data-capability-op')).toBe(GET_OP);
      expect(button.getAttribute('data-capability-enabled')).toBe('false');
      expect(button.disabled).toBe(true);
      expect(button.title).toBe('not-configured: compute');
    });
  });

  it('shows Snapshot not found on a 404', async () => {
    stubControlPlane({ 'GET /api/v1/capabilities': caps(), [`GET ${SNAPSHOT_PATH}`]: refused(404, 'snapshot not found') });
    render(withControlPlane(<SnapshotDetailClient />));

    await screen.findByText('Snapshot not found');
    await waitFor(() =>
      expect(
        screen.getAllByTestId('toast').some((t) => t.getAttribute('data-variant') === 'destructive'),
      ).toBe(true),
    );
  });

  it('shows the Compute unavailable state, not an error toast, when compute is not configured', async () => {
    const notConfigured: Answer = {
      status: 503,
      body: {
        code: 503,
        success: false,
        error: 'compute service not configured',
        service: 'compute',
        reason: 'SERVICE_NOT_CONFIGURED',
      },
    };
    stubControlPlane({ 'GET /api/v1/capabilities': caps(), [`GET ${SNAPSHOT_PATH}`]: notConfigured });
    render(withControlPlane(<SnapshotDetailClient />));

    // The SDK retries a 503 three times with backoff (1 s, 2 s, 4 s) before
    // it hands the refusal to the page.
    await screen.findByText('Compute is not available on this node', {}, { timeout: 15000 });
    expect(
      screen.queryAllByTestId('toast').some((t) => t.getAttribute('data-variant') === 'destructive'),
    ).toBe(false);
    expect(screen.queryByText('Snapshot not found')).toBeNull();
  }, 20000);

  it('asks for the VM when the vm query is missing', async () => {
    search = new URLSearchParams();
    const sent = stubControlPlane({ 'GET /api/v1/capabilities': caps(), [`GET ${SNAPSHOT_PATH}`]: storedSnapshot() });
    render(withControlPlane(<SnapshotDetailClient />));

    await screen.findByText('No VM given');
    expect(sent.some((r) => r.path.includes('/snapshots/'))).toBe(false);
  });
});
