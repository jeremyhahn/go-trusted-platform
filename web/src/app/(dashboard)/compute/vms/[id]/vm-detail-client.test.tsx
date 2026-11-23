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
const COMPUTE_OPS = [SUSPEND_OP, RESUME_OP] as const;

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
    routes[VM_PATH] = storedVM('VM_STATE_SUSPENDED');
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
      [VM_PATH]: storedVM('VM_STATE_SUSPENDED'),
      'POST /api/v1/compute/vms/vm-1/resume': ok({ status: { code: 0, message: 'resumed' } }),
    });
    await renderPage();

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
