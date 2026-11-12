/**
 * Unit tests for the transport abstraction (#1800).
 *
 * transport.ts exports only types: the Transport interface and the
 * TransportKind union. The tests pin both at the type level (with
 * expectTypeOf and @ts-expect-error, checked by `tsc --noEmit`) and
 * exercise the contract at run time through an in-memory transport.
 */

import { describe, it, expect, expectTypeOf } from 'vitest';
import type { Transport, TransportKind } from './transport.js';
import type { ApiResponse, RequestBody } from '../types/api.js';
import { ApiClient, type RequestOptions } from '../client/api-client.js';

interface RecordedCall {
  method: 'get' | 'post' | 'put' | 'patch' | 'delete';
  path: string;
  body?: RequestBody;
  options?: RequestOptions;
}

/** MemoryTransport records every call and answers from a route table. */
class MemoryTransport implements Transport {
  readonly calls: RecordedCall[] = [];

  constructor(private readonly routes: Record<string, unknown> = {}) {}

  private answer<T>(call: RecordedCall): Promise<ApiResponse<T>> {
    this.calls.push(call);
    if (call.path === '') {
      return Promise.reject(new Error('empty path'));
    }
    const key = `${call.method.toUpperCase()} ${call.path}`;
    if (!(key in this.routes)) {
      return Promise.resolve({
        success: false,
        error: { code: 'NOT_FOUND', message: `no route ${key}` },
      } as ApiResponse<T>);
    }
    return Promise.resolve({ success: true, data: this.routes[key] as T });
  }

  get<T>(path: string, options?: RequestOptions): Promise<ApiResponse<T>> {
    return this.answer<T>({ method: 'get', path, options });
  }

  post<T>(path: string, body?: RequestBody, options?: RequestOptions): Promise<ApiResponse<T>> {
    return this.answer<T>({ method: 'post', path, body, options });
  }

  put<T>(path: string, body?: RequestBody, options?: RequestOptions): Promise<ApiResponse<T>> {
    return this.answer<T>({ method: 'put', path, body, options });
  }

  patch<T>(path: string, body?: RequestBody, options?: RequestOptions): Promise<ApiResponse<T>> {
    return this.answer<T>({ method: 'patch', path, body, options });
  }

  delete<T>(path: string, options?: RequestOptions): Promise<ApiResponse<T>> {
    return this.answer<T>({ method: 'delete', path, options });
  }
}

describe('Transport interface', () => {
  it('declares exactly the five request verbs', () => {
    expectTypeOf<keyof Transport>().toEqualTypeOf<'get' | 'post' | 'put' | 'patch' | 'delete'>();
  });

  it('types each verb with a path, an optional body where it carries one, and optional options', () => {
    expectTypeOf<Transport['get']>().parameters.toEqualTypeOf<[string, RequestOptions?]>();
    expectTypeOf<Transport['delete']>().parameters.toEqualTypeOf<[string, RequestOptions?]>();
    expectTypeOf<Transport['post']>().parameters.toEqualTypeOf<[string, RequestBody?, RequestOptions?]>();
    expectTypeOf<Transport['put']>().parameters.toEqualTypeOf<[string, RequestBody?, RequestOptions?]>();
    expectTypeOf<Transport['patch']>().parameters.toEqualTypeOf<[string, RequestBody?, RequestOptions?]>();
  });

  it('returns a promise of ApiResponse carrying the caller type', () => {
    const t: Transport = new MemoryTransport();
    expectTypeOf(t.get<{ id: number }>('/x')).toEqualTypeOf<Promise<ApiResponse<{ id: number }>>>();
    expectTypeOf(t.post<string>('/x')).toEqualTypeOf<Promise<ApiResponse<string>>>();
    expectTypeOf(t.delete<void>('/x')).toEqualTypeOf<Promise<ApiResponse<void>>>();
  });

  it('is satisfied structurally by the REST ApiClient', () => {
    expectTypeOf<ApiClient>().toMatchTypeOf<Transport>();
    const client: Transport = new ApiClient({ baseUrl: 'http://127.0.0.1:1' });
    for (const verb of ['get', 'post', 'put', 'patch', 'delete'] as const) {
      expect(typeof client[verb]).toBe('function');
    }
  });

  it('rejects an object missing a verb or with a wrong path type', () => {
    const partial = {
      get: async () => ({ success: true }),
      post: async () => ({ success: true }),
      put: async () => ({ success: true }),
      patch: async () => ({ success: true }),
    };
    // @ts-expect-error delete is missing
    const missing: Transport = partial;
    expect(missing).toBeDefined();

    const t: Transport = new MemoryTransport();
    // @ts-expect-error the path must be a string
    void t.get(42);
    // @ts-expect-error a number is not a RequestBody
    void t.post('/x', 7);
  });
});

describe('Transport contract through an in-memory transport', () => {
  const routes = {
    'GET /api/v1/tpm/info': { manufacturer: 'IBM' },
    'POST /api/v1/keys': { id: 'k1' },
    'PUT /api/v1/keys/k1': { id: 'k1', label: 'full' },
    'PATCH /api/v1/keys/k1': { id: 'k1', label: 'part' },
    'DELETE /api/v1/keys/k1': null,
  };

  it('routes every verb with its path, body and options', async () => {
    const t: Transport = new MemoryTransport(routes);
    const opts: RequestOptions = { headers: { 'X-Probe': '1' } };

    await expect(t.get('/api/v1/tpm/info', opts)).resolves.toEqual({
      success: true,
      data: { manufacturer: 'IBM' },
    });
    await expect(t.post('/api/v1/keys', { alg: 'ecdsa' })).resolves.toEqual({ success: true, data: { id: 'k1' } });
    await expect(t.put('/api/v1/keys/k1', { label: 'full' })).resolves.toMatchObject({ data: { label: 'full' } });
    await expect(t.patch('/api/v1/keys/k1', { label: 'part' })).resolves.toMatchObject({ data: { label: 'part' } });
    await expect(t.delete('/api/v1/keys/k1')).resolves.toEqual({ success: true, data: null });

    const calls = (t as MemoryTransport).calls;
    expect(calls.map((c) => c.method)).toEqual(['get', 'post', 'put', 'patch', 'delete']);
    expect(calls[0].options).toBe(opts);
    expect(calls[1].body).toEqual({ alg: 'ecdsa' });
  });

  it('allows every RequestBody shape and an absent body', async () => {
    const t = new MemoryTransport();
    const bodies: RequestBody[] = [{}, [1, 2], 'raw', null, new Blob(['x'])];
    for (const body of bodies) {
      await t.post('/b', body);
    }
    await t.post('/b');
    expect(t.calls.map((c) => c.body)).toEqual([...bodies, undefined]);
  });

  it('reports an unknown route as an unsuccessful response, not a throw', async () => {
    const t: Transport = new MemoryTransport(routes);
    const res = await t.get('/api/v1/missing');
    expect(res.success).toBe(false);
    expect(res.data).toBeUndefined();
    expect(res.error?.code).toBe('NOT_FOUND');
  });

  it('propagates a transport failure as a rejected promise', async () => {
    const t: Transport = new MemoryTransport(routes);
    await expect(t.get('')).rejects.toThrow('empty path');
    await expect(t.delete('')).rejects.toThrow('empty path');
  });
});

describe('TransportKind', () => {
  it('is exactly the four supported wire protocols', () => {
    expectTypeOf<TransportKind>().toEqualTypeOf<'rest' | 'grpc-web' | 'wails' | 'unix'>();
    const kinds: TransportKind[] = ['rest', 'grpc-web', 'wails', 'unix'];
    expect(new Set(kinds).size).toBe(4);
  });

  it('rejects an unknown, misspelled or empty kind', () => {
    // @ts-expect-error not a supported kind
    const http: TransportKind = 'http';
    // @ts-expect-error kinds are case-sensitive
    const upper: TransportKind = 'REST';
    // @ts-expect-error the empty string is not a kind
    const empty: TransportKind = '';
    expect([http, upper, empty]).toHaveLength(3);
  });

  it('narrows in an exhaustive switch', () => {
    const hasNetwork = (k: TransportKind): boolean => {
      switch (k) {
        case 'rest':
        case 'grpc-web':
        case 'unix':
          return true;
        case 'wails':
          return false;
        default: {
          const never: never = k;
          return never;
        }
      }
    };
    expect(hasNetwork('rest')).toBe(true);
    expect(hasNetwork('wails')).toBe(false);
  });
});
