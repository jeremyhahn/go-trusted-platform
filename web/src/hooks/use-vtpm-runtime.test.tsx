import { act, cleanup, renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ReactNode } from 'react';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { useVTPMRuntime } from './use-vtpm-runtime';

// #2072: useVTPMRuntime reads IsVTPMRunning through the SDK's
// VTPMService.getBundleState, GET /api/v1/vtpm/bundles/{id}/state, so the
// run state comes from the server and not only from the last start or stop.

const STATE = 'GET /api/v1/vtpm/bundles/vm-1/state';
const START = 'POST /api/v1/vtpm/bundles/vm-1/start';

function stateAnswer(running: boolean) {
  return ok({ bundle_id: 'vm-1', running, socket_path: '/run/vtpm/vm-1.sock' });
}

function renderRuntime() {
  return renderHook(() => useVTPMRuntime('vm-1'), {
    wrapper: ({ children }: { children: ReactNode }) => withControlPlane(children),
  });
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('useVTPMRuntime checkState', () => {
  it('checkState reads GET /vtpm/bundles/{id}/state and shows running', async () => {
    const sent = stubControlPlane({ [STATE]: stateAnswer(true) });
    const { result } = renderRuntime();
    expect(result.current.runState).toBe('unknown');

    await act(() => result.current.checkState.mutateAsync(undefined));

    expect(sent).toContainEqual({ method: 'GET', path: '/api/v1/vtpm/bundles/vm-1/state', body: undefined });
    expect(result.current.runState).toBe('running');
    expect(result.current.checkState.data?.socket_path).toBe('/run/vtpm/vm-1.sock');
  });

  it('checkState shows stopped for running false', async () => {
    stubControlPlane({ [STATE]: stateAnswer(false) });
    const { result } = renderRuntime();

    await act(() => result.current.checkState.mutateAsync(undefined));

    expect(result.current.runState).toBe('stopped');
  });

  it('a refused state read leaves the run state unknown', async () => {
    const sent = stubControlPlane({ [STATE]: refused(404, 'bundle not found') });
    const { result } = renderRuntime();

    let thrown: unknown;
    await act(async () => {
      try {
        await result.current.checkState.mutateAsync(undefined);
      } catch (err) {
        thrown = err;
      }
    });

    expect(thrown).toBeInstanceOf(Error);
    expect(sent).toContainEqual({ method: 'GET', path: '/api/v1/vtpm/bundles/vm-1/state', body: undefined });
    expect(result.current.runState).toBe('unknown');
  });

  it('start then checkState keeps the server state', async () => {
    stubControlPlane({
      [START]: ok({
        status: { success: true },
        bundle_id: 'vm-1',
        running: true,
        socket_path: '/run/vtpm/vm-1.sock',
      }),
      [STATE]: stateAnswer(false),
    });
    const { result } = renderRuntime();

    await act(() => result.current.start.mutateAsync(undefined));
    expect(result.current.runState).toBe('running');

    await act(() => result.current.checkState.mutateAsync(undefined));
    expect(result.current.runState).toBe('stopped');
  });
});
