import type { ReactNode } from 'react';
import { cleanup, renderHook, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { useSDNBridge } from './use-sdn-bridge';

const SDN = '/api/v1/sdn';

function wrapper({ children }: { children: ReactNode }) {
  return withControlPlane(children);
}

// #2024 Codex round 3 P1: the empty policies stand-in while the list read is
// pending or refused must not be taken for a loaded, empty list.
describe('useSDNBridge policiesLoaded', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  function stub(policies: ReturnType<typeof ok>) {
    stubControlPlane({
      [`GET ${SDN}/bridges/br-1`]: ok({ bridge: { id: 'br-1', config: { name: 'br-int' } } }),
      [`GET ${SDN}/bridges/br-1/ports`]: ok({ ports: [] }),
      [`GET ${SDN}/policies`]: policies,
    });
  }

  it('is false while the read is pending and true once it succeeds', async () => {
    stub(ok({ policies: [] }));
    const { result } = renderHook(() => useSDNBridge('br-1'), { wrapper });
    expect(result.current.policiesLoaded).toBe(false);
    await waitFor(() => expect(result.current.policiesLoaded).toBe(true));
    expect(result.current.policies).toEqual([]);
  });

  it('stays false when the read is refused', async () => {
    stub(refused(403, 'policy list forbidden'));
    const { result } = renderHook(() => useSDNBridge('br-1'), { wrapper });
    await waitFor(() => expect(result.current.policiesError).toContain('policy list forbidden'));
    expect(result.current.policiesLoaded).toBe(false);
  });
});
