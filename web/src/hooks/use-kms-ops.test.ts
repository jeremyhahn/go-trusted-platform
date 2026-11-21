/**
 * useKmsOps drives PlatformClient.kms, so the SDK's base URL, auth
 * interceptors and transport apply; it never calls fetch (#1675 F27).
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook, act, cleanup } from '@testing-library/react';

const { kms, client } = vi.hoisted(() => {
  const kms = {
    importKey: vi.fn(),
    updateKeyStatus: vi.fn(),
    getKeyVersions: vi.fn(),
    hash: vi.fn(),
    hmac: vi.fn(),
    verifyHMAC: vi.fn(),
    generateRandom: vi.fn(),
    generateDataKey: vi.fn(),
    generateWrappedDataKey: vi.fn(),
    getBackendStatus: vi.fn(),
  };
  return { kms, client: { kms } };
});

vi.mock('trusted-platform-sdk', () => ({ usePlatformClient: () => client }));

import { useKmsOps, textToBase64, base64ToText } from './use-kms-ops';

const ok = (data: unknown) => ({ success: true, data });

beforeEach(() => {
  vi.stubGlobal(
    'fetch',
    vi.fn(() => {
      throw new Error('the KMS hook must not call fetch');
    })
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

describe('base64 helpers', () => {
  it('round-trips UTF-8 text', () => {
    expect(textToBase64('x')).toBe('eA==');
    expect(base64ToText(textToBase64('héllo ✓'))).toBe('héllo ✓');
  });
});

describe('useKmsOps', () => {
  it('passes each operation to its SDK method', async () => {
    for (const fn of Object.values(kms)) {
      fn.mockResolvedValue(ok({}));
    }
    kms.getKeyVersions.mockResolvedValue(ok({ versions: [] }));
    const { result } = renderHook(() => useKmsOps());

    await act(async () => {
      await result.current.updateKeyStatus('a/b', 'DISABLED', 3);
      await result.current.getKeyVersions('k');
      await result.current.hmac('k', 'x', 'SHA256');
      await result.current.verifyHmac('k', 'x', 'bWFj', 'SHA256');
      await result.current.generateDataKey('k', 'AES', 256);
      await result.current.generateWrappedDataKey('k', 'AES', 128);
      await result.current.hash('x', 'SHA256');
      await result.current.generateRandom(16);
      await result.current.getBackendStatus();
      await result.current.importKey({
        name: 'imp',
        algorithm: 'AES_256',
        key_material: 'a2V5',
        wrapping_key_id: 'wrap-1',
        description: 'd',
      });
    });

    expect(kms.importKey).toHaveBeenCalledWith({
      name: 'imp',
      keyMaterial: 'a2V5',
      keySpec: { algorithm: 'AES_256', usage: [] },
      wrappingKeyId: 'wrap-1',
      description: 'd',
    });
    expect(kms.updateKeyStatus).toHaveBeenCalledWith({ keyId: 'a/b', status: 'DISABLED', version: 3 });
    expect(kms.getKeyVersions).toHaveBeenCalledWith({ keyId: 'k' });
    expect(kms.hmac).toHaveBeenCalledWith({ keyId: 'k', message: 'eA==', hashAlgorithm: 'SHA256' });
    expect(kms.verifyHMAC).toHaveBeenCalledWith({
      keyId: 'k',
      message: 'eA==',
      hmac: 'bWFj',
      hashAlgorithm: 'SHA256',
    });
    expect(kms.generateDataKey).toHaveBeenCalledWith({ keyId: 'k', algorithm: 'AES', keySize: 256 });
    expect(kms.generateWrappedDataKey).toHaveBeenCalledWith({
      wrappingKeyId: 'k',
      keyAlgorithm: 'AES',
      keySize: 128,
    });
    expect(kms.hash).toHaveBeenCalledWith({ data: 'eA==', algorithm: 'SHA256' });
    expect(kms.generateRandom).toHaveBeenCalledWith({ numBytes: 16 });
    expect(kms.getBackendStatus).toHaveBeenCalledWith();
    expect(fetch).not.toHaveBeenCalled();
  });

  it('returns the server fields', async () => {
    kms.hmac.mockResolvedValue(ok({ key_id: 'k', hmac: 'bWFj' }));
    kms.verifyHMAC.mockResolvedValue(ok({ valid: true }));
    kms.generateRandom.mockResolvedValue(ok({ bytes: 'AAE=' }));
    kms.hash.mockResolvedValue(ok({ hash: 'SHA256', digest: 'ZGln' }));
    const dk = { key_id: 'k', plaintext_key: 'cA==', encrypted_key: 'ZQ==' };
    kms.generateDataKey.mockResolvedValue(ok(dk));
    const { result } = renderHook(() => useKmsOps());

    let out: unknown[] = [];
    await act(async () => {
      out = [
        await result.current.hmac('k', 'x', 'SHA256'),
        await result.current.verifyHmac('k', 'x', 'bWFj', 'SHA256'),
        await result.current.generateRandom(2),
        await result.current.hash('x', 'SHA256'),
        await result.current.generateDataKey('k', 'AES', 256),
      ];
    });
    expect(out).toEqual(['bWFj', true, 'AAE=', { hash: 'SHA256', digest: 'ZGln' }, dk]);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('a failed SDK response is the hook error', async () => {
    kms.updateKeyStatus.mockResolvedValueOnce({
      success: false,
      error: { code: 'HTTP_403', message: 'forbidden', status: 403 },
    });
    const { result } = renderHook(() => useKmsOps());

    let res: unknown = 'unset';
    await act(async () => {
      res = await result.current.updateKeyStatus('k', 'DISABLED', 1);
    });
    expect(res).toBeNull();
    expect(result.current.error).toBe('forbidden');

    kms.updateKeyStatus.mockResolvedValueOnce(ok({ key_id: 'k', version: 1, status: 'DISABLED' }));
    await act(async () => {
      await result.current.updateKeyStatus('k', 'DISABLED', 1);
    });
    expect(result.current.error).toBeNull();
  });

  it('a rejected SDK call is the hook error', async () => {
    kms.getBackendStatus.mockRejectedValueOnce(new Error('network down'));
    const { result } = renderHook(() => useKmsOps());

    await act(async () => {
      await result.current.getBackendStatus();
    });
    expect(result.current.error).toBe('network down');
  });
});
