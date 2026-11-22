import { act, cleanup, renderHook } from '@testing-library/react';
import type { ReactNode } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { base64ToPem, looksLikePem, pemToBase64, useIDevIDCerts } from './use-idevid-certs';

// #2055: the IDevID certificate hook drives CreateIAKCSR,
// InstallIDevIDCertificate, InstallIAKCertificate, DeleteIAKCertificate and
// ActivateCredential through the real SDK IDevIDService; PEM text travels as
// base64 (proto bytes in protojson).

const PEM = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----';

const wrapper = ({ children }: { children: ReactNode }) => withControlPlane(children);

function renderCerts() {
  return renderHook(() => useIDevIDCerts(), { wrapper });
}

describe('useIDevIDCerts', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('exposes no IAK CSR call while the server cannot produce one', () => {
    stubControlPlane({});
    const { result } = renderCerts();
    expect('createIAKCSR' in result.current).toBe(false);
  });

  it('installs the IDevID certificate as base64', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/idevid/certificate': ok({ status: { success: true, message: 'installed' } }),
    });
    const { result } = renderCerts();
    let res: Awaited<ReturnType<typeof result.current.installIDevIDCertificate>> | undefined;
    await act(async () => {
      res = await result.current.installIDevIDCertificate(PEM + '\n');
    });
    expect(sent[0].body).toEqual({ certificatePem: pemToBase64(PEM) });
    expect(res?.data?.status.success).toBe(true);
  });

  it('installs the IAK certificate and surfaces a refusal', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/idevid/iak/certificate': refused(400, 'certificate does not match the IAK'),
    });
    const { result } = renderCerts();
    let res: Awaited<ReturnType<typeof result.current.installIAKCertificate>> | undefined;
    await act(async () => {
      res = await result.current.installIAKCertificate(PEM);
    });
    expect(sent[0].body).toEqual({ certificatePem: pemToBase64(PEM) });
    expect(res?.success).toBe(false);
    expect(res?.error?.status).toBe(400);
  });

  it('deletes the IAK certificate', async () => {
    const sent = stubControlPlane({
      'DELETE /api/v1/idevid/iak/certificate': ok({ status: { success: true, message: 'deleted' } }),
    });
    const { result } = renderCerts();
    await act(async () => {
      await result.current.deleteIAKCertificate();
    });
    expect(sent[0]).toMatchObject({ method: 'DELETE', path: '/api/v1/idevid/iak/certificate' });
  });

  it('activates a credential', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/idevid/activate-credential': ok({
        status: { success: true, message: 'ok' },
        decryptedSecret: 'c2VjcmV0',
      }),
    });
    const { result } = renderCerts();
    let res: Awaited<ReturnType<typeof result.current.activateCredential>> | undefined;
    await act(async () => {
      res = await result.current.activateCredential(' AAEC ', 'AwQF');
    });
    expect(sent[0].body).toEqual({ credentialBlob: 'AAEC', secret: 'AwQF' });
    expect(res?.data?.decryptedSecret).toBe('c2VjcmV0');
  });

  it('surfaces a missing IAK on activate', async () => {
    stubControlPlane({
      'POST /api/v1/idevid/activate-credential': refused(404, 'IAK not found'),
    });
    const { result } = renderCerts();
    let res: Awaited<ReturnType<typeof result.current.activateCredential>> | undefined;
    await act(async () => {
      res = await result.current.activateCredential('AAEC', 'AwQF');
    });
    expect(res?.error?.status).toBe(404);
  });

  it('round-trips PEM and checks labels', () => {
    expect(base64ToPem(pemToBase64(PEM))).toBe(PEM);
    expect(base64ToPem(undefined)).toBe('');
    expect(looksLikePem(PEM, 'CERTIFICATE')).toBe(true);
    expect(looksLikePem(PEM, 'CERTIFICATE REQUEST')).toBe(false);
    expect(looksLikePem('hello', 'CERTIFICATE')).toBe(false);
  });
});
