import type { ReactNode } from 'react';
import { act, cleanup, renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { useKmsKeyAdmin } from './use-kms-key-admin';

// #2057: useKmsKeyAdmin sends Update status and Import key to the KMS routes.

const wrapper = ({ children }: { children: ReactNode }) => withControlPlane(children);

type Admin = ReturnType<typeof useKmsKeyAdmin>;

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('useKmsKeyAdmin', () => {
  it('sets a status under the escaped key name', async () => {
    const sent = stubControlPlane({
      'PUT /api/v1/kms/keys/team%2Fk%201/status': ok({ key_id: 'team/k 1', version: 1, status: 'DISABLED' }),
    });
    const { result } = renderHook(() => useKmsKeyAdmin(), { wrapper });

    let res: Awaited<ReturnType<Admin['setStatus']>> | undefined;
    await act(async () => {
      res = await result.current.setStatus('team/k 1', 'DISABLED');
    });

    expect(sent[0].method).toBe('PUT');
    expect(sent[0].path).toBe('/api/v1/kms/keys/team%2Fk%201/status');
    expect(sent[0].body).toEqual({ status: 'DISABLED' });
    expect(res?.success).toBe(true);
    expect(res?.data?.status).toBe('DISABLED');
  });

  it('sends the version when one is named', async () => {
    const sent = stubControlPlane({
      'PUT /api/v1/kms/keys/k1/status': ok({ key_id: 'k1', version: 2, status: 'ENABLED' }),
    });
    const { result } = renderHook(() => useKmsKeyAdmin(), { wrapper });

    await act(async () => {
      await result.current.setStatus('k1', 'ENABLED', 2);
    });

    expect(sent[0].body).toEqual({ status: 'ENABLED', version: 2 });
  });

  it('imports key material', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/kms/keys/import': ok({ key_id: 'k2', version: 1, algorithm: 'AES-256-GCM' }),
    });
    const { result } = renderHook(() => useKmsKeyAdmin(), { wrapper });
    const input: Parameters<Admin['importKey']>[0] = {
      name: 'k2',
      algorithm: 'AES-256-GCM',
      key_material: 'AAAA',
      usage: ['ENCRYPT'],
    };

    let res: Awaited<ReturnType<Admin['importKey']>> | undefined;
    await act(async () => {
      res = await result.current.importKey(input);
    });

    expect(sent[0].method).toBe('POST');
    expect(sent[0].path).toBe('/api/v1/kms/keys/import');
    expect(sent[0].body).toEqual(input);
    expect(res?.data?.key_id).toBe('k2');
  });

  it('surfaces a refused status change', async () => {
    stubControlPlane({ 'PUT /api/v1/kms/keys/k1/status': refused(404, 'no such key') });
    const { result } = renderHook(() => useKmsKeyAdmin(), { wrapper });

    let res: Awaited<ReturnType<Admin['setStatus']>> | undefined;
    await act(async () => {
      res = await result.current.setStatus('k1', 'DISABLED');
    });

    expect(res?.success).toBe(false);
    expect(res?.error?.message).toContain('no such key');
  });
});
