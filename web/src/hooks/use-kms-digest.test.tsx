import type { ReactNode } from 'react';
import { act, cleanup, renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { useKmsDigest } from './use-kms-digest';

// #2057: useKmsDigest sends Hash, HMAC and Verify HMAC to the KMS routes.

const wrapper = ({ children }: { children: ReactNode }) => withControlPlane(children);

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('useKmsDigest', () => {
  it('hashes the text as base64 with the named algorithm', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/kms/hash': ok({ hash: 'SHA-256', digest: 'ZGlnZXN0' }),
    });
    const { result } = renderHook(() => useKmsDigest(), { wrapper });

    let res: Awaited<ReturnType<typeof result.current.hash>> | undefined;
    await act(async () => {
      res = await result.current.hash('hi', 'SHA-256');
    });

    expect(sent[0].method).toBe('POST');
    expect(sent[0].path).toBe('/api/v1/kms/hash');
    expect(sent[0].body).toEqual({ data: btoa('hi'), hash: 'SHA-256' });
    expect(res?.success).toBe(true);
    expect(res?.data?.digest).toBe('ZGlnZXN0');
  });

  it('computes an HMAC under the escaped key name', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/kms/hmac/team%2Fk%201': ok({ key_id: 'team/k 1', hmac: 'dGFn' }),
    });
    const { result } = renderHook(() => useKmsDigest(), { wrapper });

    let res: Awaited<ReturnType<typeof result.current.hmac>> | undefined;
    await act(async () => {
      res = await result.current.hmac('team/k 1', 'hi', 'SHA-256');
    });

    expect(sent[0].method).toBe('POST');
    expect(sent[0].path).toBe('/api/v1/kms/hmac/team%2Fk%201');
    expect(sent[0].body).toMatchObject({ data: btoa('hi'), hash: 'SHA-256' });
    expect(res?.data?.hmac).toBe('dGFn');
  });

  it('verifies a trimmed tag', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/kms/hmac/k1/verify': ok({ valid: true }),
    });
    const { result } = renderHook(() => useKmsDigest(), { wrapper });

    let res: Awaited<ReturnType<typeof result.current.verifyHmac>> | undefined;
    await act(async () => {
      res = await result.current.verifyHmac('k1', 'hi', ' dGFn ', 'SHA-256');
    });

    expect(sent[0].method).toBe('POST');
    expect(sent[0].path).toBe('/api/v1/kms/hmac/k1/verify');
    expect(sent[0].body).toEqual({ data: btoa('hi'), hmac: 'dGFn', hash: 'SHA-256' });
    expect(res?.data?.valid).toBe(true);
  });

  it('surfaces a refused hash', async () => {
    stubControlPlane({ 'POST /api/v1/kms/hash': refused(400, 'bad hash') });
    const { result } = renderHook(() => useKmsDigest(), { wrapper });

    let res: Awaited<ReturnType<typeof result.current.hash>> | undefined;
    await act(async () => {
      res = await result.current.hash('hi', 'SHA-256');
    });

    expect(res?.success).toBe(false);
    expect(res?.error?.message).toContain('bad hash');
  });
});
