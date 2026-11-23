import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import VMDetailPage from './vm-detail-client';

// #2044: the VM detail page's Suspend and Resume buttons send SuspendVM and
// ResumeVM through the SDK client, each behind the server's capability gate;
// a refusal reaches the operator as a destructive toast.

vi.mock('next/navigation', () => ({
  useParams: () => ({ id: 'vm-1' }),
  usePathname: () => '/compute/vms/vm-1',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const VM_PATH = 'GET /api/v1/compute/vms/vm-1';
const SUSPEND_OP = 'POST /api/v1/compute/vms/{id}/suspend';
const RESUME_OP = 'POST /api/v1/compute/vms/{id}/resume';
const START_OP = 'POST /api/v1/compute/vms/{id}/start';
const STOP_OP = 'POST /api/v1/compute/vms/{id}/stop';
const REBOOT_OP = 'POST /api/v1/compute/vms/{id}/reboot';
const DELETE_OP = 'DELETE /api/v1/compute/vms/{id}';
const COMPUTE_OPS = [SUSPEND_OP, RESUME_OP, START_OP, STOP_OP, REBOOT_OP, DELETE_OP] as const;

// The server's capabilities listing: every compute op enabled except those in off.
function caps(off: string[] = []): Answer {
  const capabilities = COMPUTE_OPS.map((op) =>
    off.includes(op)
      ? { op, kind: 'route', enabled: false, reason: 'not-configured: compute' }
      : { op, kind: 'route', enabled: true },
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

function storedVM(state: string): Answer {
  return ok({
    vm: {
      id: 'vm-1',
      name: 'web-1',
      config: { name: 'web-1' },
      state,
      vcpus: 2,
      memoryMB: 2048,
      storageMB: 20480,
      osType: 'linux',
      createdAt: '2026-11-01T00:00:00Z',
      metrics: {
        cpuUsagePercent: 1,
        memoryUsagePercent: 2,
        diskUsagePercent: 3,
        networkInMbps: 0,
        networkOutMbps: 0,
      },
      snapshots: [],
    },
  });
}

async function renderPage() {
  render(withControlPlane(<VMDetailPage />));
  await screen.findByRole('heading', { level: 1, name: 'web-1' });
}

async function click(name: string) {
  // The gate holds the control disabled until the capabilities listing arrives.
  await waitFor(() => {
    expect((screen.getByRole('button', { name }) as HTMLButtonElement).disabled).toBe(false);
  });
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

describe('VMDetailPage Suspend / Resume', () => {
  it('suspends a running VM through POST /compute/vms/{id}/suspend', async () => {
    const routes: Record<string, Answer> = {
      'GET /api/v1/capabilities': caps(),
      [VM_PATH]: storedVM('VM_STATE_RUNNING'),
      'POST /api/v1/compute/vms/vm-1/suspend': ok({ status: { code: 0, message: 'suspended' } }),
    };
    const sent = stubControlPlane(routes);
    await renderPage();

    // The control plane records the transition; the re-read returns it.
    routes[VM_PATH] = storedVM('VM_STATE_PAUSED');
    await click('Suspend');

    expect(sent).toContainEqual({ method: 'POST', path: '/api/v1/compute/vms/vm-1/suspend', body: {} });
    await waitFor(() => {
      const toasts = screen.getAllByTestId('toast');
      expect(toasts.some((t) => t.textContent?.includes('VM suspended'))).toBe(true);
      expect(toasts.every((t) => t.getAttribute('data-variant') !== 'destructive')).toBe(true);
    });
    expect(await screen.findByRole('button', { name: 'Resume' })).toBeDefined();
  });

  it('resumes a suspended VM through POST /compute/vms/{id}/resume', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      [VM_PATH]: storedVM('VM_STATE_PAUSED'),
      'POST /api/v1/compute/vms/vm-1/resume': ok({ status: { code: 0, message: 'resumed' } }),
    });
    await renderPage();

    // The server reports a suspended VM as VM_STATE_PAUSED: the status badge
    // reads suspended and Resume is offered.
    await waitFor(() => expect(screen.getByTestId('vm-info').textContent).toContain('suspended'));
    await click('Resume');

    expect(sent).toContainEqual({ method: 'POST', path: '/api/v1/compute/vms/vm-1/resume', body: {} });
    await waitFor(() => {
      const toasts = screen.getAllByTestId('toast');
      expect(toasts.some((t) => t.textContent?.includes('VM resumed'))).toBe(true);
    });
  });

  it('withholds Suspend when the server does not offer it', async () => {
    stubControlPlane({
      'GET /api/v1/capabilities': caps([SUSPEND_OP]),
      [VM_PATH]: storedVM('VM_STATE_RUNNING'),
    });
    await renderPage();

    await waitFor(() => {
      const suspend = screen.getByRole('button', { name: 'Suspend' }) as HTMLButtonElement;
      expect(suspend.getAttribute('data-capability-enabled')).toBe('false');
      expect(suspend.disabled).toBe(true);
      expect(suspend.title).toBe('not-configured: compute');
    });
    expect((screen.getByRole('button', { name: 'Stop' }) as HTMLButtonElement).disabled).toBe(false);
  });

  it('shows a refused suspend as a destructive toast', async () => {
    stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      [VM_PATH]: storedVM('VM_STATE_RUNNING'),
      'POST /api/v1/compute/vms/vm-1/suspend': refused(409, 'compute: vm is not running'),
    });
    await renderPage();

    await click('Suspend');

    await waitFor(() => {
      const toast = screen
        .getAllByTestId('toast')
        .find((t) => t.getAttribute('data-variant') === 'destructive');
      expect(toast?.textContent).toContain('not running');
    });
  });
});

describe('VMDetailPage power and delete gating', () => {
  it('starts a stopped VM through POST /compute/vms/{id}/start', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      [VM_PATH]: storedVM('VM_STATE_STOPPED'),
      'POST /api/v1/compute/vms/vm-1/start': ok({ status: { code: 0, message: 'started' } }),
    });
    await renderPage();

    await click('Start');

    await waitFor(() => {
      expect(sent.some((r) => r.method === 'POST' && r.path === '/api/v1/compute/vms/vm-1/start')).toBe(true);
    });
  });

  it.each([
    ['Start', START_OP, 'VM_STATE_STOPPED'],
    ['Stop', STOP_OP, 'VM_STATE_RUNNING'],
    ['Reboot', REBOOT_OP, 'VM_STATE_RUNNING'],
    ['Delete', DELETE_OP, 'VM_STATE_RUNNING'],
  ])('withholds %s when the server does not offer it', async (name, op, state) => {
    stubControlPlane({
      'GET /api/v1/capabilities': caps([op]),
      [VM_PATH]: storedVM(state),
    });
    await renderPage();

    await waitFor(() => {
      const button = screen.getByRole('button', { name }) as HTMLButtonElement;
      expect(button.getAttribute('data-capability-enabled')).toBe('false');
      expect(button.disabled).toBe(true);
      expect(button.title).toBe('not-configured: compute');
    });
  });

  it('has no Clone control', async () => {
    stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      [VM_PATH]: storedVM('VM_STATE_RUNNING'),
    });
    await renderPage();

    expect(screen.queryByRole('button', { name: 'Clone' })).toBeNull();
  });
});

// The control plane answers GetVM with the SDK VM: name, CPU, memory and
// disks live under config; snapshots come from ListSnapshots and metrics from
// GetVMMetrics, not from the VM itself.
function sdkVM(): Answer {
  return ok({
    vm: {
      id: 'vm-1',
      state: 'VM_STATE_RUNNING',
      createdAt: '2026-11-01T00:00:00Z',
      updatedAt: '2026-11-02T00:00:00Z',
      config: {
        name: 'vm-one',
        cpu: { cores: 2 },
        memory: { sizeMb: 2048 },
        disks: [{ id: 'd1', path: '/var/lib/vm/d1.qcow2', sizeGb: 10, type: 'disk' }],
      },
    },
  });
}

function sdkRoutes(): Record<string, Answer> {
  return {
    'GET /api/v1/capabilities': caps(),
    [VM_PATH]: sdkVM(),
    'GET /api/v1/compute/vms/vm-1/snapshots': ok({
      snapshots: [{ id: 'snap-1', name: 'before-upgrade', vmId: 'vm-1' }],
    }),
    'GET /api/v1/compute/vms/vm-1/metrics': ok({
      metrics: { cpuUsagePercent: 12.5, memoryUsedMb: 512, memoryAvailableMb: 1536 },
    }),
  };
}

async function renderSDKPage() {
  render(withControlPlane(<VMDetailPage />));
  await screen.findByRole('heading', { level: 1, name: 'vm-one' });
}

describe('VMDetailPage loads the SDK VM', () => {
  it('shows an error state when the VM load is refused', async () => {
    stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      [VM_PATH]: refused(503, 'not-configured: compute'),
    });
    render(withControlPlane(<VMDetailPage />));

    // The SDK retries a 503 three times with backoff (1 s, 2 s, 4 s) before
    // it hands the refusal to the page.
    const error = await screen.findByTestId('vm-detail-error', {}, { timeout: 15000 });
    expect(error.textContent).toContain('not-configured: compute');
    expect(document.querySelector('.animate-spin')).toBeNull();
  }, 20000);

  it('shows the Compute unavailable state and stops polling when compute is not configured', async () => {
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
    const sent = stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      [VM_PATH]: notConfigured,
    });
    render(withControlPlane(<VMDetailPage />));

    // The SDK retries a 503 three times with backoff (1 s, 2 s, 4 s) before
    // it hands the refusal to the page.
    await screen.findByText('Compute is not available on this node', {}, { timeout: 15000 });
    expect(screen.queryByTestId('vm-detail-error')).toBeNull();
    expect(document.querySelector('.animate-spin')).toBeNull();

    // The page polls GetVM every 5 s; a node without compute is not polled.
    const reads = () => sent.filter((r) => r.method === 'GET' && r.path === '/api/v1/compute/vms/vm-1').length;
    const n = reads();
    await act(async () => {
      await new Promise((r) => setTimeout(r, 6000));
    });
    expect(reads()).toBe(n);
  }, 30000);

  it('renders the info card from config', async () => {
    stubControlPlane(sdkRoutes());
    await renderSDKPage();

    const info = screen.getByTestId('vm-info');
    expect(info.textContent).toContain('2 vCPUs');
    expect(info.textContent).toContain('2048 MB');
    expect(info.textContent).toContain('/var/lib/vm/d1.qcow2');
  });

  it('lists snapshots through the SDK and has no ungated placeholder buttons', async () => {
    const sent = stubControlPlane(sdkRoutes());
    await renderSDKPage();

    const link = await screen.findByRole('link', { name: 'before-upgrade' });
    expect(link.getAttribute('href')).toBe('/compute/snapshots/snap-1?vm=vm-1');
    expect(sent.some((r) => r.method === 'GET' && r.path === '/api/v1/compute/vms/vm-1/snapshots')).toBe(true);
    expect(screen.queryByRole('button', { name: 'Create Snapshot' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Restore' })).toBeNull();
  });

  it('mounts the gated disks card with the config disks', async () => {
    stubControlPlane(sdkRoutes());
    await renderSDKPage();

    // The disks card's resize field exists only for a disk it lists.
    expect(screen.getByRole('spinbutton', { name: 'New size (GB) for d1' })).toBeDefined();
    const attach = screen.getByRole('button', { name: 'Attach disk' });
    expect(attach.getAttribute('data-capability-op')).toBe('POST /api/v1/compute/vms/{id}/disks');
  });
});
