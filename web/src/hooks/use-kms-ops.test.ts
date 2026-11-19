import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, renderHook } from '@testing-library/react';
import { base64ToText, textToBase64, useKmsOps } from './use-kms-ops';

interface Seen {
  url: string;
  method: string;
  body: unknown;
}

function stubFetch(reply: (url: string) => { status: number; json: unknown }): Seen[] {
  const seen: Seen[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init?: RequestInit) => {
      seen.push({
        url,
        method: init?.method ?? 'GET',
        body: init?.body ? JSON.parse(String(init.body)) : undefined,
      });
      const r = reply(url);
      return new Response(JSON.stringify(r.json), { status: r.status });
    })
  );
  return seen;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('base64 helpers', () => {
  it('round-trips UTF-8 text', () => {
    expect(textToBase64('hello')).toBe('aGVsbG8=');
    expect(base64ToText(textToBase64('grüße'))).toBe('grüße');
  });
});

describe('useKmsOps', () => {
  it('sends each operation to its REST route', async () => {
    const seen = stubFetch(() => ({ status: 200, json: {} }));
    const { result } = renderHook(() => useKmsOps());
    await act(async () => {
      await result.current.updateKeyStatus('a/b', 'DISABLED', 3);
      await result.current.getKeyVersions('k');
      await result.current.hmac('k', 'x', 'SHA256');
      await result.current.verifyHmac('k', 'x', 'bWFj', 'SHA256');
      await result.current.generateDataKey('k', 'AES', 256);
      await result.current.generateWrappedDataKey('k', 'AES', 128);
      await result.current.getBackendStatus();
    });
    expect(seen.map((s) => `${s.method} ${s.url}`)).toEqual([
      'PUT /api/v1/kms/keys/a%2Fb/status',
      'GET /api/v1/kms/keys/k/versions',
      'POST /api/v1/kms/hmac/k',
      'POST /api/v1/kms/hmac/k/verify',
      'POST /api/v1/kms/data-keys',
      'POST /api/v1/kms/data-keys/wrapped',
      'GET /api/v1/kms/backend/status',
    ]);
    expect(seen[0].body).toEqual({ status: 'DISABLED', version: 3 });
    expect(seen[2].body).toEqual({ data: 'eA==', hash: 'SHA256' });
    expect(seen[3].body).toEqual({ data: 'eA==', hmac: 'bWFj', hash: 'SHA256' });
    expect(seen[4].body).toEqual({ key_id: 'k', algorithm: 'AES', key_size: 256 });
    expect(seen[5].body).toEqual({ wrapping_key_id: 'k', key_algorithm: 'AES', key_size: 128 });
  });

  it('unwraps a payload envelope', async () => {
    stubFetch(() => ({ status: 200, json: { payload: { bytes: 'AAE=' } } }));
    const { result } = renderHook(() => useKmsOps());
    let out: unknown;
    await act(async () => {
      out = await result.current.generateRandom(2);
    });
    expect(out).toBe('AAE=');
  });

  it('reports the server message of a failed call', async () => {
    stubFetch(() => ({ status: 500, json: { message: 'backend unavailable' } }));
    const { result } = renderHook(() => useKmsOps());
    let out: unknown = 'unset';
    await act(async () => {
      out = await result.current.hash('x', 'SHA256');
    });
    expect(out).toBeNull();
    expect(result.current.error).toBe('backend unavailable');
  });
});
