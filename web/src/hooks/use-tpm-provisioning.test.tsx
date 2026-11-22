import { act, cleanup, renderHook } from '@testing-library/react';
import type { ReactNode } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { provisionRequest, tpmKeyRefLabel, useTPMProvisioning } from './use-tpm-provisioning';

// #2068: Provision, Clear, GetCapabilities and GetPlatformAttributes reach
// the control plane through the real SDK client; a refusal comes back as the
// SDK's error response, not a thrown exception.

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function renderProvisioning() {
  return renderHook(() => useTPMProvisioning(), {
    wrapper: ({ children }: { children: ReactNode }) => withControlPlane(children),
  });
}

describe('useTPMProvisioning', () => {
  it('reads the capabilities', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/tpm/capabilities': ok({
        algorithms: ['RSA', 'ECC', 'SHA256'],
        commands: ['TPM2_Quote'],
        eccCurves: ['NIST_P256'],
      }),
    });
    const { result } = renderProvisioning();
    let res: Awaited<ReturnType<typeof result.current.getCapabilities>> | undefined;
    await act(async () => {
      res = await result.current.getCapabilities();
    });
    expect(res?.data?.algorithms).toEqual(['RSA', 'ECC', 'SHA256']);
    expect(sent).toEqual([{ method: 'GET', path: '/api/v1/tpm/capabilities', body: undefined }]);
  });

  it('reads the platform attributes', async () => {
    stubControlPlane({
      'GET /api/v1/tpm/platform': ok({
        device: '/dev/tpmrm0',
        isFips: true,
        manufacturer: 'IBM',
        ek: { handle: 2164260865, algorithm: 'RSA' },
      }),
    });
    const { result } = renderProvisioning();
    let res: Awaited<ReturnType<typeof result.current.getPlatformAttributes>> | undefined;
    await act(async () => {
      res = await result.current.getPlatformAttributes();
    });
    expect(res?.data?.isFips).toBe(true);
    expect(res?.data?.ek?.handle).toBe(2164260865);
  });

  it('provisions with the create flags and no empty password', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/tpm/provision': ok({ status: { success: true, message: 'provisioned' }, ekPublic: 'ZWs=' }),
    });
    const { result } = renderProvisioning();
    let res: Awaited<ReturnType<typeof result.current.provision>> | undefined;
    await act(async () => {
      res = await result.current.provision(
        provisionRequest({
          ownerPassword: '',
          endorsementPassword: 'e',
          createEk: true,
          createSrk: true,
          createAk: false,
        })
      );
    });
    expect(sent[0].body).toEqual({ endorsementPassword: 'e', createEk: true, createSrk: true, createAk: false });
    expect(res?.data?.status?.message).toBe('provisioned');
  });

  it('clears with the lockout password and the confirm flag', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/tpm/clear': ok({ status: { success: true, message: 'TPM cleared successfully' } }),
    });
    const { result } = renderProvisioning();
    await act(async () => {
      await result.current.clear('lockout');
    });
    expect(sent[0]).toEqual({
      method: 'POST',
      path: '/api/v1/tpm/clear',
      body: { ownerPassword: 'lockout', confirm: true },
    });
  });

  it('surfaces a refused clear', async () => {
    stubControlPlane({
      'POST /api/v1/tpm/clear': refused(403, 'tpm: lockout authorization failed'),
    });
    const { result } = renderProvisioning();
    let res: Awaited<ReturnType<typeof result.current.clear>> | undefined;
    await act(async () => {
      res = await result.current.clear('wrong');
    });
    expect(res?.success).toBe(false);
    expect(res?.error?.status).toBe(403);
    expect(res?.error?.message).toContain('lockout authorization failed');
  });

  it('labels key handles', () => {
    expect(tpmKeyRefLabel({ handle: 2164260865, algorithm: 'RSA' })).toBe('0x81000001 (RSA)');
    expect(tpmKeyRefLabel({ handle: 2164326401 })).toBe('0x81010001');
    expect(tpmKeyRefLabel()).toBe('not provisioned');
    expect(tpmKeyRefLabel({ algorithm: 'RSA' })).toBe('not provisioned');
    expect(
      provisionRequest({ ownerPassword: 'o', endorsementPassword: '', createEk: false, createSrk: true, createAk: true })
    ).toEqual({ ownerPassword: 'o', createEk: false, createSrk: true, createAk: true });
  });
});
