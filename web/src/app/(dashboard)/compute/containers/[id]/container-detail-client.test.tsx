import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { ok, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import type { UseContainerOpsResult } from '@/hooks';
import ContainerDetailPage from './container-detail-client';

// #2045: the container detail page wraps Attest and Run in the capability
// gate, so a control whose op the server does not offer is disabled with
// the server's reason, while the running-container rule still applies when
// the op is offered. containerControlGates stays real.

vi.mock('next/navigation', () => ({
  useParams: () => ({ id: 'c1' }),
  usePathname: () => '/compute/containers/c1',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

let ops: UseContainerOpsResult;

vi.mock('@/hooks', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/hooks')>()),
  useContainerOps: () => ops,
  useToast: () => ({ toast: vi.fn() }),
}));

const ATTEST_OP = 'POST /api/v1/compute/containers/{id}/attest';
const EXEC_OP = 'POST /api/v1/compute/containers/{id}/exec';
const CONTAINER_OPS = [EXEC_OP, ATTEST_OP];

function caps(off: string[] = []): Answer {
  const capabilities = CONTAINER_OPS.map((op) =>
    off.includes(op)
      ? { op, kind: 'route', enabled: false, reason: 'not-configured: compute' }
      : { op, kind: 'route', enabled: true },
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

function container(state: string): UseContainerOpsResult['container'] {
  return { id: 'c1', state, config: { name: 'web', image: 'busybox' } } as unknown as UseContainerOpsResult['container'];
}

async function renderPage(off: string[] = []) {
  stubControlPlane({ 'GET /api/v1/capabilities': caps(off) });
  render(withControlPlane(<ContainerDetailPage />));
  await screen.findByRole('heading', { level: 1, name: 'web' });
}

beforeEach(() => {
  ops = {
    container: container('CONTAINER_STATE_RUNNING'),
    metrics: null,
    loading: false,
    error: null,
    unavailable: false,
    refresh: vi.fn().mockResolvedValue(undefined),
    refreshMetrics: vi.fn().mockResolvedValue(undefined),
    exec: vi.fn(),
    attest: vi.fn(),
  };
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('ContainerDetailPage capability gate', () => {
  it('Attest and Run carry their server ops', async () => {
    await renderPage();
    const attest = screen.getByRole('button', { name: 'Attest' });
    const run = screen.getByRole('button', { name: 'Run' });
    expect(attest.getAttribute('data-capability-op')).toBe(ATTEST_OP);
    expect(run.getAttribute('data-capability-op')).toBe(EXEC_OP);
    await waitFor(() => expect(attest.getAttribute('data-capability-enabled')).toBe('true'));
    fireEvent.change(screen.getByLabelText('Command'), { target: { value: 'ls /' } });
    expect((screen.getByRole('button', { name: 'Run' }) as HTMLButtonElement).disabled).toBe(false);
  });

  it('a control whose op the server does not offer is disabled with the reason', async () => {
    await renderPage([ATTEST_OP, EXEC_OP]);
    fireEvent.change(screen.getByLabelText('Command'), { target: { value: 'ls /' } });
    const attest = screen.getByRole('button', { name: 'Attest' });
    const run = screen.getByRole('button', { name: 'Run' });
    await waitFor(() => expect(attest.getAttribute('data-capability-enabled')).toBe('false'));
    await waitFor(() => expect(run.getAttribute('data-capability-enabled')).toBe('false'));
    expect((attest as HTMLButtonElement).disabled).toBe(true);
    expect(attest.getAttribute('title')).toBe('not-configured: compute');
    expect((run as HTMLButtonElement).disabled).toBe(true);
    expect(run.getAttribute('title')).toBe('not-configured: compute');
  });

  it('keeps the container-state gate when the server offers exec', async () => {
    ops = { ...ops, container: container('CONTAINER_STATE_STOPPED') };
    await renderPage();
    fireEvent.change(screen.getByLabelText('Command'), { target: { value: 'ls /' } });
    const run = screen.getByRole('button', { name: 'Run' });
    await waitFor(() => expect(run.getAttribute('data-capability-enabled')).toBe('true'));
    expect((run as HTMLButtonElement).disabled).toBe(true);
    expect(run.getAttribute('title') ?? '').toMatch(/running/i);
  });
});
