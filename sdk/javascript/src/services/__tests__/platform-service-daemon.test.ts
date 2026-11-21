/**
 * Unit tests for the daemon status and service lifecycle calls (#1752).
 *
 * Each method must hit the REST route the daemon serves under
 * `/v1/platform` with the right verb, and hand back the wire body.
 */

import { describe, it, expect } from 'vitest';
import { ApiClient } from '../../client/api-client.js';
import { PlatformService } from '../platform-service.js';

interface Call {
  method: string;
  url: string;
}

/** A client whose fetch records each call and answers with one JSON body. */
function clientReturning(body: unknown): { client: ApiClient; calls: Call[] } {
  const calls: Call[] = [];
  const fetchImpl = ((url: RequestInfo | URL, init?: RequestInit) => {
    calls.push({ method: init?.method ?? 'GET', url: String(url) });
    return Promise.resolve(new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));
  }) as unknown as typeof fetch;

  const client = new ApiClient({
    baseUrl: '/api',
    fetch: fetchImpl,
    retry: { maxRetries: 0 },
  });
  return { client, calls };
}

describe('PlatformService daemon operations', () => {
  it('getStatus reads GET /v1/platform/status', async () => {
    const body = { status: 'running', version: '1.2.3', timestamp: 1 };
    const { client, calls } = clientReturning(body);
    const res = await new PlatformService(client).getStatus();
    expect(calls).toHaveLength(1);
    expect(calls[0]?.method).toBe('GET');
    expect(calls[0]?.url).toMatch(/\/v1\/platform\/status$/);
    expect(res.data).toEqual(body);
  });

  it('listServices reads GET /v1/platform/services', async () => {
    const body = { services: [{ name: 'kms', status: 'running', start_count: 1, stop_count: 0 }], count: 1 };
    const { client, calls } = clientReturning(body);
    const res = await new PlatformService(client).listServices();
    expect(calls[0]?.method).toBe('GET');
    expect(calls[0]?.url).toMatch(/\/v1\/platform\/services$/);
    expect(res.data?.services[0]?.name).toBe('kms');
    expect(res.data?.count).toBe(1);
  });

  it('getServiceStatus reads GET /v1/platform/services/{service}, escaping the name', async () => {
    const body = { name: 'a b', status: 'stopped' };
    const { client, calls } = clientReturning(body);
    const res = await new PlatformService(client).getServiceStatus('a b');
    expect(calls[0]?.method).toBe('GET');
    expect(calls[0]?.url).toMatch(/\/v1\/platform\/services\/a%20b$/);
    expect(res.data?.status).toBe('stopped');
  });

  it.each([
    ['startService', 'start'],
    ['stopService', 'stop'],
    ['restartService', 'restart'],
  ] as const)('%s posts to /v1/platform/services/{service}/%s', async (method, action) => {
    const body = { service: 'kms', action, success: true, message: 'ok' };
    const { client, calls } = clientReturning(body);
    const res = await new PlatformService(client)[method]('kms');
    expect(calls).toHaveLength(1);
    expect(calls[0]?.method).toBe('POST');
    expect(calls[0]?.url).toMatch(new RegExp(`/v1/platform/services/kms/${action}$`));
    expect(res.data).toEqual(body);
  });

  // A lifecycle POST whose response is lost after the server acted must not
  // be sent again: the daemon has no idempotency key, so a retried restart
  // would stop and start the service twice.
  it.each([
    ['startService', 'start'],
    ['stopService', 'stop'],
    ['restartService', 'restart'],
  ] as const)('%s is sent once when the response is lost', async (method, action) => {
    const calls: Call[] = [];
    const fetchImpl = ((url: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ method: init?.method ?? 'GET', url: String(url) });
      if (calls.length === 1) {
        return Promise.reject(new TypeError('Failed to fetch'));
      }
      return Promise.resolve(new Response(JSON.stringify({ service: 'kms', action, success: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));
    }) as unknown as typeof fetch;
    const client = new ApiClient({
      baseUrl: '/api',
      fetch: fetchImpl,
      retry: { maxRetries: 3, initialDelayMs: 1, maxDelayMs: 1, retryOnNetworkError: true },
    });
    const res = await new PlatformService(client)[method]('kms');
    expect(calls).toHaveLength(1);
    expect(res.success).toBe(false);
  });
});
