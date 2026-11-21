/**
 * Ruling 1048: the client never auto-retries a mutating verb (POST, PUT,
 * PATCH, DELETE), on a status or a network error, unless the caller passes
 * an `Idempotency-Key` request header or `retry.retryOnMutation: true`.
 * Reads (GET, HEAD) keep the configured retry policy.
 */

import { describe, it, expect, vi } from 'vitest';
import { ApiClient } from '../api-client.js';

type FetchMock = ReturnType<typeof vi.fn>;

function clientWith(fetchImpl: FetchMock, headers?: Record<string, string>): ApiClient {
  return new ApiClient({
    baseUrl: 'https://platform.test/api/v1',
    fetch: fetchImpl as unknown as typeof fetch,
    retry: { maxRetries: 2, initialDelayMs: 1, maxDelayMs: 1 },
    ...(headers !== undefined ? { headers } : {}),
  });
}

function ok(): Response {
  return new Response(JSON.stringify({ success: true, payload: { id: 'x' } }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

function unavailable(): Response {
  return new Response(JSON.stringify({ code: 503, error: 'unavailable', success: false }), {
    status: 503,
    headers: { 'content-type': 'application/json' },
  });
}

function networkError(): TypeError {
  return new TypeError('fetch failed');
}

function alwaysRejects(): FetchMock {
  return vi.fn().mockImplementation(() => Promise.reject(networkError()));
}

function rejectsOnceThenOk(): FetchMock {
  return vi
    .fn()
    .mockRejectedValueOnce(networkError())
    .mockImplementation(() => Promise.resolve(ok()));
}

function unavailableOnceThenOk(): FetchMock {
  return vi
    .fn()
    .mockImplementationOnce(() => Promise.resolve(unavailable()))
    .mockImplementation(() => Promise.resolve(ok()));
}

describe('ApiClient mutation retry policy', () => {
  it('does not resend a POST after a network error', async () => {
    const fetchImpl = alwaysRejects();
    const response = await clientWith(fetchImpl).post('/vms', {});
    expect(response.success).toBe(false);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it.each(['put', 'patch', 'delete'] as const)('does not resend a %s after a network error', async (verb) => {
    const fetchImpl = alwaysRejects();
    const client = clientWith(fetchImpl);
    const response = verb === 'delete' ? await client.delete('/vms/x') : await client[verb]('/vms/x', {});
    expect(response.success).toBe(false);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('does not resend a POST answered 503', async () => {
    const fetchImpl = vi.fn().mockImplementation(() => Promise.resolve(unavailable()));
    const response = await clientWith(fetchImpl).post('/vms', {});
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(response.error?.status).toBe(503);
  });

  it('resends a POST with an Idempotency-Key after a network error', async () => {
    const fetchImpl = rejectsOnceThenOk();
    const response = await clientWith(fetchImpl).post('/vms', {}, { headers: { 'Idempotency-Key': 'k-1' } });
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(response.success).toBe(true);
  });

  it('resends a POST with an Idempotency-Key answered 503', async () => {
    const fetchImpl = unavailableOnceThenOk();
    const response = await clientWith(fetchImpl).post('/vms', {}, { headers: { 'Idempotency-Key': 'k-1' } });
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(response.success).toBe(true);
  });

  it('reads a lower-case idempotency key from the client default headers', async () => {
    const fetchImpl = unavailableOnceThenOk();
    const response = await clientWith(fetchImpl, { 'idempotency-key': 'k-2' }).post('/vms', {});
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(response.success).toBe(true);
  });

  it('does not resend when a blank per-request key replaces a default one', async () => {
    const fetchImpl = vi.fn().mockImplementation(async () => unavailable());
    await clientWith(fetchImpl, { 'Idempotency-Key': 'k' }).post(
      '/vms',
      {},
      { headers: { 'Idempotency-Key': '' } }
    );
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('does not resend when a blank per-request key of another case replaces a default one', async () => {
    const fetchImpl = vi.fn().mockImplementation(async () => unavailable());
    await clientWith(fetchImpl, { 'idempotency-key': 'k' }).post(
      '/vms',
      {},
      { headers: { 'Idempotency-Key': '' } }
    );
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('resends a POST whose Idempotency-Key a request interceptor adds', async () => {
    const fetchImpl = unavailableOnceThenOk();
    const client = clientWith(fetchImpl);
    client.addRequestInterceptor((init) => ({
      ...init,
      headers: { ...(init.headers as Record<string, string>), 'idempotency-key': 'i' },
    }));
    const response = await client.post('/vms', {});
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(response.success).toBe(true);
  });

  it('ignores a blank Idempotency-Key', async () => {
    const fetchImpl = alwaysRejects();
    await clientWith(fetchImpl).post('/vms', {}, { headers: { 'Idempotency-Key': '  ' } });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('resends a POST with retryOnMutation after a network error', async () => {
    const fetchImpl = rejectsOnceThenOk();
    const response = await clientWith(fetchImpl).post('/vms', {}, { retry: { retryOnMutation: true } });
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(response.success).toBe(true);
  });

  it('resends a POST with retryOnMutation answered 503', async () => {
    const fetchImpl = unavailableOnceThenOk();
    const response = await clientWith(fetchImpl).post('/vms', {}, { retry: { retryOnMutation: true } });
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(response.success).toBe(true);
  });

  it('keeps retry.enabled false over an Idempotency-Key', async () => {
    const fetchImpl = alwaysRejects();
    await clientWith(fetchImpl).post(
      '/vms',
      {},
      { headers: { 'Idempotency-Key': 'k-1' }, retry: { enabled: false } }
    );
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('resends a GET after a network error', async () => {
    const fetchImpl = rejectsOnceThenOk();
    const response = await clientWith(fetchImpl).get('/vms');
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(response.success).toBe(true);
  });

  it('resends a GET answered 503', async () => {
    const fetchImpl = unavailableOnceThenOk();
    const response = await clientWith(fetchImpl).get('/vms');
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(response.success).toBe(true);
  });
});
