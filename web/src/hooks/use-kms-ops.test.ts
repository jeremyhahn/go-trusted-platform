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

describe('useKmsOps batch and rewrap (#2057)', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('batch encrypt sends one /encrypt/{name} call per item, in order', async () => {
    let n = 0;
    const seen = stubFetch(() => ({ status: 200, json: { key_id: 'k', version: 1, ciphertext: `c${n++}` } }));
    const { result } = renderHook(() => useKmsOps());
    let out: unknown;
    await act(async () => {
      out = await result.current.batchEncrypt('k/1', ['one', 'two']);
    });
    expect(seen.map((s) => `${s.method} ${s.url}`)).toEqual([
      'POST /api/v1/kms/encrypt/k%2F1',
      'POST /api/v1/kms/encrypt/k%2F1',
    ]);
    expect(seen.map((s) => s.body)).toEqual([
      { plaintext: textToBase64('one') },
      { plaintext: textToBase64('two') },
    ]);
    expect(out).toEqual([
      { ciphertext: 'c0', version: 1 },
      { ciphertext: 'c1', version: 1 },
    ]);
  });

  it('batch decrypt returns the decoded plaintext of every item', async () => {
    const seen = stubFetch(() => ({ status: 200, json: { plaintext: textToBase64('hi') } }));
    const { result } = renderHook(() => useKmsOps());
    let out: unknown;
    await act(async () => {
      out = await result.current.batchDecrypt('k', ['AAA=', 'AQE=']);
    });
    expect(seen.map((s) => `${s.method} ${s.url}`)).toEqual([
      'POST /api/v1/kms/decrypt/k',
      'POST /api/v1/kms/decrypt/k',
    ]);
    expect(seen[1].body).toEqual({ ciphertext: 'AQE=' });
    expect(out).toEqual(['hi', 'hi']);
  });

  it('a failed batch item fails the batch with the server message', async () => {
    let n = 0;
    stubFetch(() =>
      n++ === 0
        ? { status: 200, json: { ciphertext: 'c0', version: 1 } }
        : { status: 403, json: { message: 'key disabled' } }
    );
    const { result } = renderHook(() => useKmsOps());
    let out: unknown = 'unset';
    await act(async () => {
      out = await result.current.batchEncrypt('k', ['a', 'b']);
    });
    expect(out).toBeNull();
    expect(result.current.error).toBe('key disabled');
  });

  it('rewrap posts the ciphertext to /keys/{name}/rewrap', async () => {
    const seen = stubFetch(() => ({
      status: 200,
      json: { key_id: 'k/1', old_version: 1, new_version: 2, ciphertext: 'Zm9v' },
    }));
    const { result } = renderHook(() => useKmsOps());
    let out: unknown;
    await act(async () => {
      out = await result.current.rewrap('k/1', 'AAE=');
    });
    expect(seen).toEqual([
      { url: '/api/v1/kms/keys/k%2F1/rewrap', method: 'POST', body: { ciphertext: 'AAE=' } },
    ]);
    expect(out).toEqual({ key_id: 'k/1', old_version: 1, new_version: 2, ciphertext: 'Zm9v' });
  });
});
