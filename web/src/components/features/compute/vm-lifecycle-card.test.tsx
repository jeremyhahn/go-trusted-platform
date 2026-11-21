import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { VMLifecycleCard } from './vm-lifecycle-card';

const VM_PATH = 'GET /api/v1/compute/vms/vm-1';
const METRICS_PATH = 'GET /api/v1/compute/vms/vm-1/metrics';
const SUSPEND_PATH = 'POST /api/v1/compute/vms/vm-1/suspend';
const RESUME_PATH = 'POST /api/v1/compute/vms/vm-1/resume';
const ATTEST_PATH = 'POST /api/v1/compute/vms/vm-1/attest';

function storedVM(state: string): Answer {
  return ok({ vm: { id: 'vm-1', state, config: { name: 'web-1' } } });
}

function baseRoutes(state = 'VM_STATE_RUNNING'): Record<string, Answer> {
  return {
    [VM_PATH]: storedVM(state),
    [METRICS_PATH]: ok({
      metrics: { cpuUsagePercent: 12.5, memoryUsedMb: '512', memoryAvailableMb: '1536', uptimeSeconds: 3600 },
    }),
  };
}

function posts(sent: { method: string; path: string }[]) {
  return sent.filter((s) => s.method === 'POST').map((s) => s.method + ' ' + s.path);
}

describe('VMLifecycleCard', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('shows the state and the metrics', async () => {
    stubControlPlane(baseRoutes());
    render(withControlPlane(<VMLifecycleCard vmId="vm-1" />));
    await waitFor(() => expect(screen.getByTestId('vm-lifecycle-state').textContent).toBe('Running'));
    const metrics = await screen.findByTestId('vm-lifecycle-metrics');
    await waitFor(() => expect(metrics.textContent).toContain('12.5%'));
    expect(metrics.textContent).toContain('512 / 2048 MB');
    expect(metrics.textContent).toContain('60 min');
  });

  it('suspends only after the confirm and re-reads the state', async () => {
    const routes = { ...baseRoutes(), [SUSPEND_PATH]: ok({ status: { success: true, message: 'ok' } }) };
    const sent = stubControlPlane(routes);
    render(withControlPlane(<VMLifecycleCard vmId="vm-1" />));
    const suspend = await screen.findByTestId('vm-suspend');
    await waitFor(() => expect((suspend as HTMLButtonElement).disabled).toBe(false));

    fireEvent.click(suspend);
    expect(await screen.findByText('Suspend this VM?')).toBeTruthy();
    expect(posts(sent)).toEqual([]);

    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByTestId('vm-suspend-dialog')).toBeNull());
    expect(posts(sent)).toEqual([]);

    fireEvent.click(screen.getByTestId('vm-suspend'));
    const confirm = await screen.findByTestId('vm-suspend-confirm');
    routes[VM_PATH] = storedVM('VM_STATE_PAUSED');
    fireEvent.click(confirm);

    expect(await screen.findByText('Paused')).toBeTruthy();
    expect(posts(sent)).toEqual([SUSPEND_PATH]);
    await waitFor(() => expect((screen.getByTestId('vm-resume') as HTMLButtonElement).disabled).toBe(false));
    expect((screen.getByTestId('vm-suspend') as HTMLButtonElement).disabled).toBe(true);
  });

  it('resumes a paused VM', async () => {
    const sent = stubControlPlane({
      ...baseRoutes('VM_STATE_PAUSED'),
      [RESUME_PATH]: ok({ status: { success: true, message: 'ok' } }),
    });
    render(withControlPlane(<VMLifecycleCard vmId="vm-1" />));
    const resume = await screen.findByTestId('vm-resume');
    await waitFor(() => expect((resume as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(resume);
    await waitFor(() => expect(posts(sent)).toEqual([RESUME_PATH]));
    expect(screen.queryByTestId('vm-suspend-dialog')).toBeNull();
  });

  it('attests and shows the quote summary', async () => {
    const sent = stubControlPlane({
      ...baseRoutes(),
      [ATTEST_PATH]: ok({
        status: { success: true },
        quote: 'cXVvdGU=',
        pcrValues: [{ index: 7, bank: 'PCR_BANK_SHA256', value: 'AA==' }],
        signatureAlgorithm: 'SHA256-RSAPSS',
      }),
    });
    render(withControlPlane(<VMLifecycleCard vmId="vm-1" />));
    fireEvent.click(await screen.findByTestId('vm-attest'));
    const result = await screen.findByTestId('vm-attest-result');
    expect(result.textContent).toBe('Quote received, 1 PCRs, SHA256-RSAPSS');
    const attest = sent.find((s) => s.method + ' ' + s.path === ATTEST_PATH);
    const nonce = (attest?.body as { nonce?: unknown } | undefined)?.nonce;
    expect(typeof nonce).toBe('string');
    expect((nonce as string).length).toBeGreaterThan(0);
  });

  it("shows the server's refusal", async () => {
    stubControlPlane({ ...baseRoutes(), [SUSPEND_PATH]: refused(409, 'compute: vm vm-1 is not running') });
    render(withControlPlane(<VMLifecycleCard vmId="vm-1" />));
    const suspend = await screen.findByTestId('vm-suspend');
    await waitFor(() => expect((suspend as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(suspend);
    fireEvent.click(await screen.findByTestId('vm-suspend-confirm'));
    const error = await screen.findByTestId('vm-lifecycle-error');
    expect(error.textContent).toContain('is not running');
  });

  it('a refused metrics read keeps the card', async () => {
    stubControlPlane({ ...baseRoutes(), [METRICS_PATH]: refused(404, 'compute: no metrics for vm-1') });
    render(withControlPlane(<VMLifecycleCard vmId="vm-1" />));
    const error = await screen.findByTestId('vm-lifecycle-metrics-error');
    expect(error.textContent).toContain('no metrics');
    await waitFor(() => expect(screen.getByTestId('vm-lifecycle-state').textContent).toBe('Running'));
  });
});
