import { act, cleanup, renderHook } from '@testing-library/react';
import type { ReactNode } from 'react';
import { BMCCertService } from 'trusted-platform-sdk';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { bmcPath, failedCeremonySteps, useBMCCertOps } from './use-bmc-cert-ops';

function renderOps() {
  return renderHook(() => useBMCCertOps('42'), {
    wrapper: ({ children }: { children: ReactNode }) => withControlPlane(children),
  });
}

describe('useBMCCertOps', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('enrolls with its overrides through POST /bmc/{id}/enroll', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/bmc/42/enroll': ok({
        device_id: '18446744073709551615',
        endpoint: 'bmc-a',
        hostname: 'bmc-a',
        pin_spki_sha256: 'ab',
        factory_cert_meta: { subject: 'CN=factory' },
        steps: [
          { name: 'capture', ok: true },
          { name: 'replace', ok: true },
        ],
      }),
    });
    const { result } = renderOps();
    let res: Awaited<ReturnType<typeof result.current.enroll>> | undefined;
    await act(async () => {
      res = await result.current.enroll({ replace_certificate: true, dns_register: false });
    });
    expect(res?.data?.device_id).toBe('18446744073709551615');
    expect(sent).toEqual([
      {
        method: 'POST',
        path: '/api/v1/bmc/42/enroll',
        body: { replace_certificate: true, dns_register: false },
      },
    ]);
  });

  it('sends an empty object when enroll has no overrides', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/bmc/42/enroll': ok({ device_id: '42', steps: [] }),
    });
    const { result } = renderOps();
    await act(async () => {
      await result.current.enroll();
    });
    // The server answers 400 on an empty body.
    expect(sent[0].body).toEqual({});
  });

  it('restores the factory certificate through POST /bmc/{id}/cert/restore', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/bmc/42/cert/restore': ok({
        device_id: '42',
        endpoint: 'bmc-a',
        hostname: 'bmc-a',
        new_cert_meta: { subject: 'CN=factory' },
        steps: [{ name: 'restore', ok: false, detail: 'upload refused' }],
      }),
    });
    const { result } = renderOps();
    let res: Awaited<ReturnType<typeof result.current.restoreFactoryCert>> | undefined;
    await act(async () => {
      res = await result.current.restoreFactoryCert();
    });
    expect(sent[0].method).toBe('POST');
    expect(sent[0].path).toBe('/api/v1/bmc/42/cert/restore');
    expect(failedCeremonySteps(res?.data?.steps)).toEqual(['restore']);
  });

  // #2199: the replace rotates no SPKI pin and no TLSA record, so the hook offers none.
  it('offers no web certificate replace', () => {
    const { result } = renderOps();
    expect(Object.keys(result.current).sort()).toEqual(['enroll', 'restoreFactoryCert']);
  });

  it('names the failed steps and the BMC path', () => {
    expect(failedCeremonySteps(undefined)).toEqual([]);
    expect(bmcPath('a/b', 'cert')).toBe('/v1/bmc/a%2Fb/cert');
  });

  it('goes through the SDK BMCCertService', async () => {
    const enrollSpy = vi.spyOn(BMCCertService.prototype, 'enrollBMC');
    const restoreSpy = vi.spyOn(BMCCertService.prototype, 'restoreFactoryCert');
    stubControlPlane({
      'POST /api/v1/bmc/42/enroll': ok({ device_id: '42', steps: [] }),
      'POST /api/v1/bmc/42/cert/restore': ok({ device_id: '42', steps: [] }),
    });
    const { result } = renderOps();
    await act(async () => {
      await result.current.enroll({ replace_certificate: true, dns_register: false });
      await result.current.restoreFactoryCert();
    });
    expect(enrollSpy).toHaveBeenCalledWith('42', { replaceCertificate: true, dnsRegister: false });
    expect(restoreSpy).toHaveBeenCalledWith('42');
  });
});
