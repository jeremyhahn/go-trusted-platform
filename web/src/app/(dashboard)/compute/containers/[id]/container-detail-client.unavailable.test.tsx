import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { ok, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import type { UseContainerOpsResult } from '@/hooks';
import ContainerDetailPage from './container-detail-client';

// #2045: on a node without compute the container detail page shows the
// not-configured state, the same as the containers list, not a load error.

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

function renderPage() {
  stubControlPlane({ 'GET /api/v1/capabilities': ok({ capabilities: [], total: 0, enabled: 0 }) });
  render(withControlPlane(<ContainerDetailPage />));
}

beforeEach(() => {
  ops = {
    container: null,
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

describe('ContainerDetailPage without compute', () => {
  it('shows that compute is not available instead of an error', async () => {
    ops.unavailable = true;
    renderPage();

    await screen.findByText('Compute is not available on this node');
    expect(screen.queryByRole('alert')).toBeNull();
    expect(screen.queryByRole('button', { name: /Attest/ })).toBeNull();
    expect(screen.queryByRole('button', { name: /Run/ })).toBeNull();
    expect(screen.queryByText('Container Details')).toBeNull();
  });

  it('keeps the load error for any other refusal', async () => {
    ops.error = 'boom';
    renderPage();

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('Failed to load container: boom');
  });
});
