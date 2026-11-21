import { act, cleanup, renderHook } from '@testing-library/react';
import type { ReactNode } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { certificateToBase64, useSDNPortAuth } from './use-sdn-port-auth';

// #2064: the SDN port auth hook authenticates a port with a certificate
// (POST /sdn/bridges/{name}/ports/{port}/auth) and revokes it (DELETE on the
// same path) through the SDK SDNService; the certificate is base64 on the wire.

const PEM = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----';
const AUTH_PATH = '/api/v1/sdn/bridges/br0/ports/p1/auth';

const wrapper = ({ children }: { children: ReactNode }) => withControlPlane(children);

describe('useSDNPortAuth', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('authenticates a port with a PEM', async () => {
    const sent = stubControlPlane({
      [`POST ${AUTH_PATH}`]: ok({ status: { success: true, message: 'authenticated' }, auth: { authenticated: true } }),
    });
    const { result } = renderHook(() => useSDNPortAuth('br0', 'p1'), { wrapper });

    let res: Awaited<ReturnType<typeof result.current.authenticatePEM>> | undefined;
    await act(async () => {
      res = await result.current.authenticatePEM(PEM + '\n');
    });

    expect(sent[0].method).toBe('POST');
    expect(sent[0].path).toBe(AUTH_PATH);
    expect(sent[0].body).toEqual({ certificate: certificateToBase64(PEM), format: 'PEM' });
    expect(res?.data?.status.success).toBe(true);
  });

  it('authenticates a port with a DER', async () => {
    const sent = stubControlPlane({
      [`POST ${AUTH_PATH}`]: ok({ status: { success: true, message: 'authenticated' }, auth: { authenticated: true } }),
    });
    const { result } = renderHook(() => useSDNPortAuth('br0', 'p1'), { wrapper });

    await act(async () => {
      await result.current.authenticateDER(' MIIB ');
    });

    expect(sent[0].method).toBe('POST');
    expect(sent[0].body).toEqual({ certificate: 'MIIB', format: 'DER' });
  });

  it('surfaces a rejected certificate', async () => {
    stubControlPlane({ [`POST ${AUTH_PATH}`]: refused(403, 'certificate not trusted') });
    const { result } = renderHook(() => useSDNPortAuth('br0', 'p1'), { wrapper });

    let res: Awaited<ReturnType<typeof result.current.authenticatePEM>> | undefined;
    await act(async () => {
      res = await result.current.authenticatePEM(PEM);
    });

    expect(res?.success).toBe(false);
    expect(res?.error?.status).toBe(403);
  });

  it('revokes the port auth and escapes the ids', async () => {
    const sent = stubControlPlane({
      'DELETE /api/v1/sdn/bridges/br%200/ports/p1/auth': ok({ status: { success: true, message: 'revoked' } }),
    });
    const { result } = renderHook(() => useSDNPortAuth('br 0', 'p1'), { wrapper });

    let res: Awaited<ReturnType<typeof result.current.revoke>> | undefined;
    await act(async () => {
      res = await result.current.revoke();
    });

    expect(sent[0].method).toBe('DELETE');
    expect(sent[0].path).toBe('/api/v1/sdn/bridges/br%200/ports/p1/auth');
    expect(res?.success).toBe(true);
  });

  it('encodes the certificate', () => {
    expect(atob(certificateToBase64(PEM))).toBe(PEM);
    expect(certificateToBase64('')).toBe('');
  });
});
