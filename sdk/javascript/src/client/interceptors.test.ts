/**
 * Unit tests for the request/response interceptors (#1799).
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  InterceptorManager,
  createAuthInterceptor,
  createLoggingRequestInterceptor,
  createLoggingResponseInterceptor,
  createRequestIdInterceptor,
  createRetryAfterInterceptor,
  type RequestContext,
  type ResponseContext,
} from './interceptors.js';
import type { ApiResponse } from '../types/api.js';

function reqCtx(over: Partial<RequestContext> = {}): RequestContext {
  return {
    url: '/api/v1/kms/keys',
    method: 'GET',
    headers: { Accept: 'application/json' },
    attempt: 0,
    metadata: {},
    ...over,
  };
}

function resCtx<T>(
  response: ApiResponse<T>,
  rawResponse?: Response,
  durationMs = 12
): ResponseContext<T> {
  const ctx: ResponseContext<T> = { request: reqCtx(), response, durationMs };
  if (rawResponse !== undefined) {
    ctx.rawResponse = rawResponse;
  }
  return ctx;
}

function errorResp(): ApiResponse<unknown> {
  return { success: false, error: { code: 'RATE_LIMITED', message: 'slow down', status: 429 } };
}

function retryAfterRaw(value: string | null): Response {
  const headers = new Headers();
  if (value !== null) {
    headers.set('Retry-After', value);
  }
  return new Response(null, { status: 429, headers });
}

describe('InterceptorManager', () => {
  it('starts empty', () => {
    const m = new InterceptorManager<string>();
    expect(m.size).toBe(0);
    expect(m.getAll()).toEqual([]);
  });

  it('adds interceptors in order with increasing ids', () => {
    const m = new InterceptorManager<string>();
    const a = m.add('a');
    const b = m.add('b');
    expect(b.id).toBeGreaterThan(a.id);
    expect(m.getAll()).toEqual(['a', 'b']);
    expect(m.size).toBe(2);
  });

  it('accepts the same interceptor twice as two entries', () => {
    const m = new InterceptorManager<string>();
    m.add('a');
    m.add('a');
    expect(m.getAll()).toEqual(['a', 'a']);
  });

  it('removes through the handle, and a second remove is harmless', () => {
    const m = new InterceptorManager<string>();
    const a = m.add('a');
    m.add('b');
    a.remove();
    a.remove();
    expect(m.getAll()).toEqual(['b']);
  });

  it('removes by id and reports whether it existed', () => {
    const m = new InterceptorManager<string>();
    const a = m.add('a');
    expect(m.remove(a.id)).toBe(true);
    expect(m.remove(a.id)).toBe(false);
    expect(m.remove(-1)).toBe(false);
    expect(m.remove(999)).toBe(false);
  });

  it('never reuses an id after a removal or a clear', () => {
    const m = new InterceptorManager<string>();
    const a = m.add('a');
    a.remove();
    m.clear();
    const b = m.add('b');
    expect(b.id).not.toBe(a.id);
    expect(m.remove(a.id)).toBe(false);
    expect(m.getAll()).toEqual(['b']);
  });

  it('clears every interceptor', () => {
    const m = new InterceptorManager<number>();
    m.add(1);
    m.add(2);
    m.clear();
    expect(m.size).toBe(0);
    expect(m.getAll()).toEqual([]);
  });

  it('getAll returns a copy the caller cannot use to mutate the manager', () => {
    const m = new InterceptorManager<string>();
    m.add('a');
    m.getAll().push('x');
    expect(m.getAll()).toEqual(['a']);
  });
});

describe('createLoggingRequestInterceptor', () => {
  it('logs method, url, headers, body and attempt and returns the config unchanged', () => {
    const logger = vi.fn();
    const config: RequestInit = { method: 'POST' };
    const ctx = reqCtx({ method: 'POST', body: { a: 1 }, attempt: 2 });
    const out = createLoggingRequestInterceptor(logger)(config, ctx);
    expect(out).toBe(config);
    expect(logger).toHaveBeenCalledWith('[API Request] POST /api/v1/kms/keys', {
      headers: ctx.headers,
      body: { a: 1 },
      attempt: 2,
    });
  });

  describe('default logger', () => {
    afterEach(() => {
      vi.restoreAllMocks();
    });

    it('logs to console.log', () => {
      const spy = vi.spyOn(console, 'log').mockImplementation(() => undefined);
      void createLoggingRequestInterceptor()({}, reqCtx());
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy.mock.calls[0]?.[0]).toBe('[API Request] GET /api/v1/kms/keys');
    });
  });
});

describe('createLoggingResponseInterceptor', () => {
  it('logs a success and returns the same response', () => {
    const logger = vi.fn();
    const response: ApiResponse<number> = { success: true, data: 1 };
    const out = createLoggingResponseInterceptor(logger)(response, resCtx(response));
    expect(out).toBe(response);
    expect(logger).toHaveBeenCalledWith('[API Response] SUCCESS GET /api/v1/kms/keys', {
      success: true,
      durationMs: 12,
      error: undefined,
    });
  });

  it('logs an error with its error body', () => {
    const logger = vi.fn();
    const response = errorResp();
    void createLoggingResponseInterceptor(logger)(response, resCtx(response));
    expect(logger).toHaveBeenCalledWith('[API Response] ERROR GET /api/v1/kms/keys', {
      success: false,
      durationMs: 12,
      error: response.error,
    });
  });

  describe('default logger', () => {
    afterEach(() => {
      vi.restoreAllMocks();
    });

    it('logs to console.log', () => {
      const spy = vi.spyOn(console, 'log').mockImplementation(() => undefined);
      const response: ApiResponse<number> = { success: true, data: 1 };
      void createLoggingResponseInterceptor()(response, resCtx(response));
      expect(spy).toHaveBeenCalledTimes(1);
    });
  });
});

describe('createAuthInterceptor', () => {
  it('adds a bearer token from a sync getter, keeping other headers', async () => {
    const out = await createAuthInterceptor(() => 'tok')(
      { method: 'GET', headers: { 'X-A': '1' } },
      reqCtx()
    );
    expect(out.method).toBe('GET');
    expect(out.headers).toEqual({ 'X-A': '1', Authorization: 'Bearer tok' });
  });

  it('awaits an async getter', async () => {
    const out = await createAuthInterceptor(() => Promise.resolve('async-tok'))({}, reqCtx());
    expect(out.headers).toEqual({ Authorization: 'Bearer async-tok' });
  });

  it('reads the token on every request', async () => {
    let n = 0;
    const i = createAuthInterceptor(() => `t${++n}`);
    await i({}, reqCtx());
    const out = await i({}, reqCtx());
    expect(out.headers).toEqual({ Authorization: 'Bearer t2' });
  });

  it('converts a Headers object to a plain record', async () => {
    const out = await createAuthInterceptor(() => 'tok')(
      { headers: new Headers({ 'X-A': '1' }) },
      reqCtx()
    );
    expect(out.headers).toEqual({ 'x-a': '1', Authorization: 'Bearer tok' });
  });

  it('keeps headers given as an array of pairs', async () => {
    const out = await createAuthInterceptor(() => 'tok')(
      { headers: [['X-A', '1']] },
      reqCtx()
    );
    expect(out.headers).toEqual({ 'x-a': '1', Authorization: 'Bearer tok' });
  });

  it('replaces an existing Authorization header', async () => {
    const out = await createAuthInterceptor(() => 'new')(
      { headers: { Authorization: 'Bearer old' } },
      reqCtx()
    );
    expect(out.headers).toEqual({ Authorization: 'Bearer new' });
  });

  it.each<[string, HeadersInit]>([
    ['an array of pairs', [['Authorization', 'Bearer old']]],
    ['a Headers object', new Headers({ Authorization: 'Bearer old' })],
    ['a lower-case record key', { authorization: 'Bearer old' }],
  ])('replaces an existing Authorization header given as %s', async (_name, headers) => {
    const out = await createAuthInterceptor(() => 'new')({ headers }, reqCtx());
    const h = new Headers(out.headers as HeadersInit);
    expect(h.get('authorization')).toBe('Bearer new');
    const keys = Object.keys(out.headers as Record<string, string>).filter(
      (k) => k.toLowerCase() === 'authorization'
    );
    expect(keys).toHaveLength(1);
  });

  it('does not mutate the input config', async () => {
    const config: RequestInit = { headers: { 'X-A': '1' } };
    await createAuthInterceptor(() => 'tok')(config, reqCtx());
    expect(config.headers).toEqual({ 'X-A': '1' });
  });

  it('sends an empty token as a bare "Bearer " header', async () => {
    const out = await createAuthInterceptor(() => '')({}, reqCtx());
    expect(out.headers).toEqual({ Authorization: 'Bearer ' });
  });

  it('rejects when the token getter throws', async () => {
    const i = createAuthInterceptor(() => {
      throw new Error('no session');
    });
    await expect(i({}, reqCtx())).rejects.toThrow('no session');
  });

  it('rejects when the async token getter rejects', async () => {
    const i = createAuthInterceptor(() => Promise.reject(new Error('expired')));
    await expect(i({}, reqCtx())).rejects.toThrow('expired');
  });
});

describe('createRequestIdInterceptor', () => {
  it('sets the X-Request-ID header and records it in the context metadata', async () => {
    const ctx = reqCtx();
    const out = await createRequestIdInterceptor(() => 'id-1')({ headers: { 'X-A': '1' } }, ctx);
    expect(out.headers).toEqual({ 'X-A': '1', 'X-Request-ID': 'id-1' });
    expect(ctx.metadata['requestId']).toBe('id-1');
  });

  it('generates a new id for every request', async () => {
    let n = 0;
    const i = createRequestIdInterceptor(() => `id-${++n}`);
    const a = await i({}, reqCtx());
    const b = await i({}, reqCtx());
    expect(a.headers).toEqual({ 'X-Request-ID': 'id-1' });
    expect(b.headers).toEqual({ 'X-Request-ID': 'id-2' });
  });

  it('defaults to a random UUID', async () => {
    const ctx = reqCtx();
    const out = await createRequestIdInterceptor()({}, ctx);
    const id = (out.headers as Record<string, string>)['X-Request-ID'];
    expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    expect(ctx.metadata['requestId']).toBe(id);
  });

  it('converts a Headers object to a plain record', async () => {
    const out = await createRequestIdInterceptor(() => 'id')(
      { headers: new Headers({ 'X-A': '1' }) },
      reqCtx()
    );
    expect(out.headers).toEqual({ 'x-a': '1', 'X-Request-ID': 'id' });
  });

  it('keeps headers given as an array of pairs', async () => {
    const out = await createRequestIdInterceptor(() => 'id')({ headers: [['X-A', '1']] }, reqCtx());
    expect(out.headers).toEqual({ 'x-a': '1', 'X-Request-ID': 'id' });
  });

  it('replaces an existing x-request-id pair case-insensitively', async () => {
    const out = await createRequestIdInterceptor(() => 'id')(
      { headers: [['x-request-id', 'stale']] },
      reqCtx()
    );
    const h = new Headers(out.headers as HeadersInit);
    expect(h.get('x-request-id')).toBe('id');
    const keys = Object.keys(out.headers as Record<string, string>).filter(
      (k) => k.toLowerCase() === 'x-request-id'
    );
    expect(keys).toHaveLength(1);
  });

  it('throws when the id generator throws', () => {
    const i = createRequestIdInterceptor(() => {
      throw new Error('no entropy');
    });
    expect(() => i({}, reqCtx())).toThrow('no entropy');
  });
});

describe('createRetryAfterInterceptor', () => {
  // The interceptor type allows a promise; this one is synchronous.
  const retryAfter = createRetryAfterInterceptor();
  const i = <T>(r: ApiResponse<T>, ctx: ResponseContext<T>): ApiResponse<T> =>
    retryAfter(r, ctx) as ApiResponse<T>;

  function retryAfterSeconds(r: ApiResponse<unknown>): unknown {
    return r.error?.details?.context?.['retryAfterSeconds'];
  }

  it('records a numeric Retry-After on an error response', () => {
    const r = errorResp();
    const out = i(r, resCtx(r, retryAfterRaw('30')));
    expect(out).toBe(r);
    expect(retryAfterSeconds(out)).toBe(30);
  });

  it('records a zero Retry-After as the number 0', () => {
    const r = errorResp();
    expect(retryAfterSeconds(i(r, resCtx(r, retryAfterRaw('0'))))).toBe(0);
  });

  it('keeps an HTTP-date Retry-After as the raw string', () => {
    const r = errorResp();
    const date = 'Wed, 21 Oct 2015 07:28:00 GMT';
    expect(retryAfterSeconds(i(r, resCtx(r, retryAfterRaw(date))))).toBe(date);
  });

  it('keeps existing details and context fields', () => {
    const r = errorResp();
    if (!r.error) {
      throw new Error('errorResp() carries no error');
    }
    r.error.details = { field: 'name', context: { tenant: 't1' } } as never;
    const out = i(r, resCtx(r, retryAfterRaw('5')));
    expect(out.error?.details).toEqual({
      field: 'name',
      context: { tenant: 't1', retryAfterSeconds: 5 },
    });
  });

  it('leaves the response alone without a Retry-After header', () => {
    const r = errorResp();
    const out = i(r, resCtx(r, retryAfterRaw(null)));
    expect(out.error?.details).toBeUndefined();
  });

  it('leaves the response alone without a raw response', () => {
    const r = errorResp();
    const out = i(r, resCtx(r));
    expect(out.error?.details).toBeUndefined();
  });

  it('leaves a success response alone even with Retry-After', () => {
    const r: ApiResponse<number> = { success: true, data: 1 };
    const out = i(r, resCtx(r, retryAfterRaw('30')));
    expect(out).toEqual({ success: true, data: 1 });
  });
});
