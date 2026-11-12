/**
 * Unit tests for the API client configuration helpers (#1799).
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  DEFAULT_RETRY_CONFIG,
  DEFAULT_TIMEOUT_CONFIG,
  getDefaultBaseUrl,
  getDefaultFetch,
  resolveConfig,
  validateConfig,
  type ResolvedApiClientConfig,
} from './config.js';

const g = globalThis as unknown as Record<string, unknown>;

function clearEnv(): void {
  // stubEnv records the original so unstubAllEnvs restores it; then drop the key.
  vi.stubEnv('NEXT_PUBLIC_API_URL', '');
  vi.stubEnv('API_URL', '');
  delete process.env['NEXT_PUBLIC_API_URL'];
  delete process.env['API_URL'];
}

describe('DEFAULT_RETRY_CONFIG', () => {
  it('holds the documented retry defaults', () => {
    expect(DEFAULT_RETRY_CONFIG).toEqual({
      maxRetries: 3,
      initialDelayMs: 1000,
      maxDelayMs: 30000,
      backoffMultiplier: 2,
      retryableStatuses: [408, 429, 500, 502, 503, 504],
      retryOnNetworkError: true,
    });
  });

  it('never lists a 2xx or a plain 4xx client error as retryable', () => {
    for (const status of [200, 201, 204, 400, 401, 403, 404]) {
      expect(DEFAULT_RETRY_CONFIG.retryableStatuses).not.toContain(status);
    }
  });
});

describe('DEFAULT_TIMEOUT_CONFIG', () => {
  it('holds the documented timeout defaults', () => {
    expect(DEFAULT_TIMEOUT_CONFIG).toEqual({
      requestTimeoutMs: 30000,
      connectionTimeoutMs: 10000,
    });
  });

  it('gives the connection less time than the whole request', () => {
    expect(DEFAULT_TIMEOUT_CONFIG.connectionTimeoutMs).toBeLessThan(
      DEFAULT_TIMEOUT_CONFIG.requestTimeoutMs
    );
  });
});

describe('getDefaultBaseUrl', () => {
  beforeEach(() => {
    clearEnv();
    delete g['import'];
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    delete g['import'];
  });

  it('falls back to the relative /api path when nothing is set', () => {
    expect(getDefaultBaseUrl()).toBe('/api');
  });

  it('uses API_URL when it is set', () => {
    process.env['API_URL'] = '/generic';
    expect(getDefaultBaseUrl()).toBe('/generic');
  });

  it('prefers NEXT_PUBLIC_API_URL over API_URL', () => {
    process.env['API_URL'] = '/generic';
    process.env['NEXT_PUBLIC_API_URL'] = '/next';
    expect(getDefaultBaseUrl()).toBe('/next');
  });

  it('returns an empty NEXT_PUBLIC_API_URL as set, not the fallback', () => {
    process.env['NEXT_PUBLIC_API_URL'] = '';
    process.env['API_URL'] = '/generic';
    expect(getDefaultBaseUrl()).toBe('');
  });

  it('prefers a Vite VITE_API_URL over the process env', () => {
    process.env['NEXT_PUBLIC_API_URL'] = '/next';
    g['import'] = { meta: { env: { VITE_API_URL: '/vite' } } };
    expect(getDefaultBaseUrl()).toBe('/vite');
  });

  it('ignores a Vite env without VITE_API_URL', () => {
    process.env['API_URL'] = '/generic';
    g['import'] = { meta: { env: {} } };
    expect(getDefaultBaseUrl()).toBe('/generic');
  });

  it('ignores a Vite object without meta', () => {
    g['import'] = {};
    expect(getDefaultBaseUrl()).toBe('/api');
  });
});

describe('getDefaultFetch', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('returns a fetch bound to globalThis', async () => {
    const calls: unknown[] = [];
    const fake = vi.fn(function (this: unknown) {
      calls.push(this);
      return Promise.resolve(new Response('ok'));
    });
    vi.stubGlobal('fetch', fake);

    const f = getDefaultFetch();
    expect(f).not.toBe(fake);
    await f('/ping');
    expect(fake).toHaveBeenCalledWith('/ping');
    expect(calls[0]).toBe(globalThis);
  });

  it('throws when no fetch implementation exists', () => {
    vi.stubGlobal('fetch', undefined);
    expect(() => getDefaultFetch()).toThrow(/No fetch implementation available/);
  });
});

describe('resolveConfig', () => {
  beforeEach(() => {
    clearEnv();
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('fills every default when no config is given', () => {
    const r = resolveConfig();
    expect(r.baseUrl).toBe('/api');
    expect(r.headers).toEqual({
      'Content-Type': 'application/json',
      Accept: 'application/json',
    });
    expect(r.credentials).toBe('include');
    expect(r.timeout).toEqual(DEFAULT_TIMEOUT_CONFIG);
    expect(r.retry).toEqual(DEFAULT_RETRY_CONFIG);
    expect(r.throwOnError).toBe(false);
    expect(typeof r.fetch).toBe('function');
  });

  it('fills every default for an empty config object', () => {
    expect(resolveConfig({}).credentials).toBe('include');
  });

  it('keeps every explicit value', () => {
    const fetchImpl = vi.fn() as unknown as typeof fetch;
    const r = resolveConfig({
      baseUrl: '/v2',
      credentials: 'omit',
      throwOnError: true,
      fetch: fetchImpl,
    });
    expect(r.baseUrl).toBe('/v2');
    expect(r.credentials).toBe('omit');
    expect(r.throwOnError).toBe(true);
    expect(r.fetch).toBe(fetchImpl);
  });

  it('keeps an empty baseUrl rather than the default', () => {
    expect(resolveConfig({ baseUrl: '' }).baseUrl).toBe('');
  });

  it('merges headers over the JSON defaults', () => {
    const r = resolveConfig({ headers: { Accept: 'text/plain', 'X-Extra': '1' } });
    expect(r.headers).toEqual({
      'Content-Type': 'application/json',
      Accept: 'text/plain',
      'X-Extra': '1',
    });
  });

  it('merges a partial timeout and retry over the defaults', () => {
    const r = resolveConfig({
      timeout: { requestTimeoutMs: 5 },
      retry: { maxRetries: 0 },
    });
    expect(r.timeout).toEqual({ ...DEFAULT_TIMEOUT_CONFIG, requestTimeoutMs: 5 });
    expect(r.retry).toEqual({ ...DEFAULT_RETRY_CONFIG, maxRetries: 0 });
  });

  it('does not share or mutate the default objects', () => {
    const r = resolveConfig({ timeout: { requestTimeoutMs: 1 } });
    expect(r.timeout).not.toBe(DEFAULT_TIMEOUT_CONFIG);
    expect(r.retry).not.toBe(DEFAULT_RETRY_CONFIG);
    expect(DEFAULT_TIMEOUT_CONFIG.requestTimeoutMs).toBe(30000);
  });

  it('reads the base URL from the environment', () => {
    process.env['API_URL'] = '/env';
    expect(resolveConfig().baseUrl).toBe('/env');
  });
});

describe('validateConfig', () => {
  function valid(): ResolvedApiClientConfig {
    return resolveConfig({ baseUrl: '/api', fetch: vi.fn() as unknown as typeof fetch });
  }

  it('accepts a resolved default config', () => {
    expect(() => validateConfig(valid())).not.toThrow();
  });

  it('accepts zero retries', () => {
    const c = valid();
    c.retry.maxRetries = 0;
    expect(() => validateConfig(c)).not.toThrow();
  });

  it('rejects an empty baseUrl', () => {
    const c = valid();
    c.baseUrl = '';
    expect(() => validateConfig(c)).toThrow('baseUrl cannot be empty');
  });

  it('rejects a zero request timeout', () => {
    const c = valid();
    c.timeout.requestTimeoutMs = 0;
    expect(() => validateConfig(c)).toThrow('requestTimeoutMs must be positive');
  });

  it('rejects a negative request timeout', () => {
    const c = valid();
    c.timeout.requestTimeoutMs = -1;
    expect(() => validateConfig(c)).toThrow('requestTimeoutMs must be positive');
  });

  it('rejects negative retries', () => {
    const c = valid();
    c.retry.maxRetries = -1;
    expect(() => validateConfig(c)).toThrow('maxRetries cannot be negative');
  });

  it('reports the baseUrl first when several fields are invalid', () => {
    const c = valid();
    c.baseUrl = '';
    c.timeout.requestTimeoutMs = 0;
    c.retry.maxRetries = -1;
    expect(() => validateConfig(c)).toThrow('baseUrl cannot be empty');
  });
});
