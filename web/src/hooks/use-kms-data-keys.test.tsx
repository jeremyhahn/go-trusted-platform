import type { ReactNode } from 'react';
import { act, cleanup, renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import {
  base64ByteLength,
  encryptionContext,
  useKMSDataKeys,
  type KMSDataKey,
  type KMSWrappedDataKey,
} from './use-kms-data-keys';

const wrapper = ({ children }: { children: ReactNode }) => withControlPlane(children);

type Hook = ReturnType<typeof useKMSDataKeys>;
type DataKeyResult = Awaited<ReturnType<Hook['generateDataKey']>>;
type WrappedResult = Awaited<ReturnType<Hook['generateWrappedDataKey']>>;

describe('useKMSDataKeys', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('generates a data key', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/kms/data-keys': ok({
        key_id: 'kek-1',
        plaintext_key: btoa('k'.repeat(32)),
        encrypted_key: 'ZW5j',
      } satisfies KMSDataKey),
    });
    const { result } = renderHook(() => useKMSDataKeys(), { wrapper });

    let res: DataKeyResult | undefined;
    await act(async () => {
      res = await result.current.generateDataKey(' kek-1 ');
    });

    expect(sent[0].method).toBe('POST');
    expect(sent[0].path).toBe('/api/v1/kms/data-keys');
    expect(sent[0].body).toEqual({ key_id: 'kek-1' });
    expect(res?.success).toBe(true);
    expect(base64ByteLength(res!.data!.plaintext_key)).toBe(32);
    expect(res?.data?.encrypted_key).toBe('ZW5j');
  });

  it('refuses a nonempty encryption context without a request', async () => {
    // #2180 round 9: the pinned backend ignores the context, so a key wrapped
    // "under" one would unwrap without it. Refuse it rather than send it.
    const sent = stubControlPlane({
      'POST /api/v1/kms/data-keys': ok({ key_id: 'kek-1', plaintext_key: btoa('k'.repeat(32)), encrypted_key: 'ZW5j' }),
      'POST /api/v1/kms/data-keys/wrapped': ok({ wrapping_key_id: 'kek-2', wrapped_key: 'd3JhcA==' }),
    });
    const { result } = renderHook(() => useKMSDataKeys(), { wrapper });

    let res: DataKeyResult | undefined;
    let wrapped: WrappedResult | undefined;
    await act(async () => {
      res = await result.current.generateDataKey('kek-1', 'tenant=a');
      wrapped = await result.current.generateWrappedDataKey('kek-2', 'tenant=a');
    });

    expect(sent).toHaveLength(0);
    expect(res?.success).toBe(false);
    expect(res?.error?.message).toContain('context');
    expect(wrapped?.success).toBe(false);
    expect(wrapped?.error?.message).toContain('context');
  });

  it('surfaces a missing key id', async () => {
    stubControlPlane({
      'POST /api/v1/kms/data-keys': refused(400, 'invalid kms request: key_id: is required'),
    });
    const { result } = renderHook(() => useKMSDataKeys(), { wrapper });

    let res: DataKeyResult | undefined;
    await act(async () => {
      res = await result.current.generateDataKey('');
    });

    expect(res?.success).toBe(false);
    expect(res?.error?.status).toBe(400);
    expect(res?.error?.message).toContain('key_id');
  });

  it('generates a wrapped data key', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/kms/data-keys/wrapped': ok({
        wrapping_key_id: 'kek-2',
        wrapped_key: 'd3JhcA==',
      } satisfies KMSWrappedDataKey),
    });
    const { result } = renderHook(() => useKMSDataKeys(), { wrapper });

    let res: WrappedResult | undefined;
    await act(async () => {
      res = await result.current.generateWrappedDataKey('kek-2', ' ');
    });

    expect(sent[0].method).toBe('POST');
    expect(sent[0].path).toBe('/api/v1/kms/data-keys/wrapped');
    expect(sent[0].body).toEqual({ wrapping_key_id: 'kek-2' });
    expect(res?.data?.wrapped_key).toBe('d3JhcA==');
  });

  it('surfaces an unknown wrapping key', async () => {
    stubControlPlane({
      'POST /api/v1/kms/data-keys/wrapped': refused(404, 'key not found: nope'),
    });
    const { result } = renderHook(() => useKMSDataKeys(), { wrapper });

    let res: WrappedResult | undefined;
    await act(async () => {
      res = await result.current.generateWrappedDataKey('nope');
    });

    expect(res?.success).toBe(false);
    expect(res?.error?.status).toBe(404);
  });

  it('encodes contexts and measures keys', () => {
    expect(encryptionContext('a=b')).toBe(btoa('a=b'));
    expect(encryptionContext('  ')).toBeUndefined();
    expect(encryptionContext(undefined)).toBeUndefined();
    expect(base64ByteLength('')).toBe(0);
    expect(base64ByteLength(btoa('abcd'))).toBe(4);
  });
});
