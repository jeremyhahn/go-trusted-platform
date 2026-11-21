import { act, cleanup, renderHook } from '@testing-library/react';
import type { ReactNode } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import {
  canResume,
  canSuspend,
  useVMLifecycle,
  vmAttestNonce,
  vmOpPath,
  vmStateLabel,
  wireNumber,
} from './use-vm-lifecycle';

const wrapper = ({ children }: { children: ReactNode }) => withControlPlane(children);

describe('useVMLifecycle', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('reads the VM', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/compute/vms/vm-1': ok({
        vm: { id: 'vm-1', state: 'VM_STATE_RUNNING', config: { name: 'web-1' } },
      }),
    });
    const { result } = renderHook(() => useVMLifecycle('vm-1'), { wrapper });
    let res: Awaited<ReturnType<typeof result.current.getVM>> | undefined;
    await act(async () => {
      res = await result.current.getVM();
    });
    expect(res?.data?.vm.state).toBe('VM_STATE_RUNNING');
    expect(sent).toEqual([{ method: 'GET', path: '/api/v1/compute/vms/vm-1', body: undefined }]);
  });

  it('reads the metrics', async () => {
    stubControlPlane({
      'GET /api/v1/compute/vms/vm-1/metrics': ok({
        metrics: { cpuUsagePercent: 12.5, memoryUsedMb: '512', memoryAvailableMb: '1536', uptimeSeconds: 3600 },
      }),
    });
    const { result } = renderHook(() => useVMLifecycle('vm-1'), { wrapper });
    let res: Awaited<ReturnType<typeof result.current.getMetrics>> | undefined;
    await act(async () => {
      res = await result.current.getMetrics();
    });
    expect(res?.data?.metrics.cpuUsagePercent).toBe(12.5);
  });

  it('suspends and resumes', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/compute/vms/vm-1/suspend': ok({ status: { success: true, message: 'ok' } }),
      'POST /api/v1/compute/vms/vm-1/resume': ok({ status: { success: true, message: 'ok' } }),
    });
    const { result } = renderHook(() => useVMLifecycle('vm-1'), { wrapper });
    let res: Awaited<ReturnType<typeof result.current.resume>> | undefined;
    await act(async () => {
      res = await result.current.suspend();
    });
    await act(async () => {
      res = await result.current.resume();
    });
    expect(sent.map((s) => s.method + ' ' + s.path)).toEqual([
      'POST /api/v1/compute/vms/vm-1/suspend',
      'POST /api/v1/compute/vms/vm-1/resume',
    ]);
    expect(res?.data?.status?.success).toBe(true);
  });

  it('surfaces a refused suspend', async () => {
    stubControlPlane({
      'POST /api/v1/compute/vms/vm-1/suspend': refused(409, 'compute: vm vm-1 is not running'),
    });
    const { result } = renderHook(() => useVMLifecycle('vm-1'), { wrapper });
    let res: Awaited<ReturnType<typeof result.current.suspend>> | undefined;
    await act(async () => {
      res = await result.current.suspend();
    });
    expect(res?.success).toBe(false);
    expect(res?.error?.status).toBe(409);
    expect(res?.error?.message).toContain('not running');
  });

  it('attests with the nonce it is given', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/compute/vms/vm-1/attest': ok({
        status: { success: true },
        quote: 'cXVvdGU=',
        pcrValues: [{ index: 7, bank: 'PCR_BANK_SHA256', value: 'AA==' }],
        signatureAlgorithm: 'SHA256-RSAPSS',
      }),
    });
    const { result } = renderHook(() => useVMLifecycle('vm-1'), { wrapper });
    let res: Awaited<ReturnType<typeof result.current.attest>> | undefined;
    await act(async () => {
      res = await result.current.attest('bm9uY2U=');
    });
    expect(sent[0].body).toMatchObject({ nonce: 'bm9uY2U=' });
    expect(res?.data?.signatureAlgorithm).toBe('SHA256-RSAPSS');
  });

  it('escapes the VM id', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/compute/vms/a%2Fb/resume': ok({ status: { success: true } }),
    });
    const { result } = renderHook(() => useVMLifecycle('a/b'), { wrapper });
    await act(async () => {
      await result.current.resume();
    });
    expect(sent[0].path).toBe('/api/v1/compute/vms/a%2Fb/resume');
    expect(vmOpPath('a/b', 'suspend')).toBe('/v1/compute/vms/a%2Fb/suspend');
  });

  it('labels states and builds a nonce', () => {
    expect(vmStateLabel('VM_STATE_RUNNING')).toBe('Running');
    expect(vmStateLabel('VM_STATE_PAUSED')).toBe('Paused');
    expect(vmStateLabel(undefined)).toBe('Unknown');
    expect(canSuspend('VM_STATE_RUNNING')).toBe(true);
    expect(canSuspend('VM_STATE_PAUSED')).toBe(false);
    expect(canResume('VM_STATE_PAUSED')).toBe(true);
    const a = vmAttestNonce();
    expect(atob(a).length).toBe(32);
    expect(vmAttestNonce()).not.toBe(a);
    expect(wireNumber('512')).toBe(512);
    expect(wireNumber(7)).toBe(7);
    expect(wireNumber(undefined)).toBe(0);
  });
});
