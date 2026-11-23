import { act, cleanup, renderHook } from '@testing-library/react';
import type { ReactNode } from 'react';
import { BMCCertService } from 'trusted-platform-sdk';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { bmcPath, failedCeremonySteps, replaceCertProblem, useBMCCertOps } from './use-bmc-cert-ops';

// Placeholder PEM bodies: the hook passes them through unchanged.
const CERT_PEM = 'test-cert-pem';
const KEY_PEM = 'test-key-pem';

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

  it('replaces the web certificate through PUT /bmc/{id}/cert', async () => {
    const sent = stubControlPlane({
      'PUT /api/v1/bmc/42/cert': ok({ status: 'ok' }),
    });
    const { result } = renderOps();
    let res: Awaited<ReturnType<typeof result.current.replaceWebCertificate>> | undefined;
    await act(async () => {
      res = await result.current.replaceWebCertificate({ cert_pem: CERT_PEM, key_pem: KEY_PEM });
    });
    expect(res?.data?.status).toBe('ok');
    expect(sent[0]).toEqual({
      method: 'PUT',
      path: '/api/v1/bmc/42/cert',
      body: { cert_pem: CERT_PEM, key_pem: KEY_PEM },
    });
  });

  it("surfaces the server's missing key refusal", async () => {
    stubControlPlane({
      'PUT /api/v1/bmc/42/cert': refused(400, 'bmc: key_pem is required'),
    });
    const { result } = renderOps();
    let res: Awaited<ReturnType<typeof result.current.replaceWebCertificate>> | undefined;
    await act(async () => {
      res = await result.current.replaceWebCertificate({ cert_pem: CERT_PEM, key_pem: '' });
    });
    expect(res?.success).toBe(false);
    expect(res?.error?.status).toBe(400);
    expect(res?.error?.message).toBe('bmc: key_pem is required');
  });

  it('checks a replace request before sending', () => {
    expect(replaceCertProblem({ cert_pem: ' ', key_pem: 'k' })).toBe('A certificate PEM is required');
    expect(replaceCertProblem({ cert_pem: 'c', key_pem: '' })).toBe('A private key PEM is required');
    expect(replaceCertProblem({ cert_pem: 'c', key_pem: 'k' })).toBeNull();
    expect(failedCeremonySteps(undefined)).toEqual([]);
    expect(bmcPath('a/b', 'cert')).toBe('/v1/bmc/a%2Fb/cert');
  });

  it('goes through the SDK BMCCertService', async () => {
    const enrollSpy = vi.spyOn(BMCCertService.prototype, 'enrollBMC');
    const restoreSpy = vi.spyOn(BMCCertService.prototype, 'restoreFactoryCert');
    const replaceSpy = vi.spyOn(BMCCertService.prototype, 'replaceWebCertificate');
    stubControlPlane({
      'POST /api/v1/bmc/42/enroll': ok({ device_id: '42', steps: [] }),
      'POST /api/v1/bmc/42/cert/restore': ok({ device_id: '42', steps: [] }),
      'PUT /api/v1/bmc/42/cert': ok({ status: 'ok' }),
    });
    const { result } = renderOps();
    await act(async () => {
      await result.current.enroll({ replace_certificate: true, dns_register: false });
      await result.current.restoreFactoryCert();
      await result.current.replaceWebCertificate({ cert_pem: CERT_PEM, key_pem: KEY_PEM });
    });
    expect(enrollSpy).toHaveBeenCalledWith('42', { replaceCertificate: true, dnsRegister: false });
    expect(restoreSpy).toHaveBeenCalledWith('42');
    expect(replaceSpy).toHaveBeenCalledWith('42', { certPem: CERT_PEM, keyPem: KEY_PEM });
  });
});
