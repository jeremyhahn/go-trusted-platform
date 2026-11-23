import { act, cleanup, renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { useVMMigration } from './use-vm-migration';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function render(vmId = 'vm-1') {
  return renderHook(() => useVMMigration(vmId), {
    wrapper: ({ children }) => withControlPlane(children),
  });
}

describe('useVMMigration', () => {
  it('migrates a VM through ComputeService.migrateVM', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/compute/vms/vm-1/migrate': ok({ status: { success: true } }),
    });
    const { result } = render();

    let res: Awaited<ReturnType<typeof result.current.migrate>> | undefined;
    await act(async () => {
      res = await result.current.migrate('host-b', true);
    });

    expect(sent[0].path).toBe('/api/v1/compute/vms/vm-1/migrate');
    expect(sent[0].body).toEqual({ destinationHost: 'host-b', liveMigration: true });
    expect(res?.success).toBe(true);
  });

  it('prepares a receiver', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/compute/migrations/prepare': ok({
        status: { success: true },
        receiverId: 'rx-1',
        port: 49152,
        tlsHostname: 'dest.test',
      }),
    });
    const { result } = render();

    let res: Awaited<ReturnType<typeof result.current.prepare>> | undefined;
    await act(async () => {
      res = await result.current.prepare({
        vmId: 'vm-1',
        vmName: 'web-1',
        mode: 'cold',
        spec: { memoryMb: 2048, cpus: 2, arch: 'x86_64' },
      });
    });

    // #2044: the receiver needs the guest spec; PrepareMigration refuses without it.
    expect(sent[0].body).toEqual({
      vmId: 'vm-1',
      vmName: 'web-1',
      mode: 'cold',
      spec: { memoryMb: 2048, cpus: 2, arch: 'x86_64' },
    });
    expect(res?.data?.receiverId).toBe('rx-1');
  });

  it('commits and aborts a receiver', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/compute/migrations/rx%2F1/finalize': ok({ status: { success: true } }),
    });
    const { result } = render();

    await act(async () => {
      await result.current.finalize('rx/1', true);
      await result.current.finalize('rx/1', false);
    });

    expect(sent.map((r) => r.path)).toEqual([
      '/api/v1/compute/migrations/rx%2F1/finalize',
      '/api/v1/compute/migrations/rx%2F1/finalize',
    ]);
    expect(sent[0].body).toEqual({ commit: true });
    expect(sent[1].body).toEqual({ commit: false });
  });

  it('surfaces a refused migration', async () => {
    stubControlPlane({
      'POST /api/v1/compute/vms/vm-1/migrate': refused(409, 'compute: vm is not running'),
    });
    const { result } = render();

    let res: Awaited<ReturnType<typeof result.current.migrate>> | undefined;
    await act(async () => {
      res = await result.current.migrate('host-b', false);
    });

    expect(res?.success).toBe(false);
    expect(res?.error?.status).toBe(409);
    expect(res?.error?.message).toContain('not running');
  });
});
