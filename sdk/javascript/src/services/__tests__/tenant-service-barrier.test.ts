/**
 * TenantService barrier operations (#1673): each method posts to the
 * tenant's barrier route with the request body the REST handler decodes.
 */
import { describe, it, expect } from 'vitest';
import { ApiClient } from '../../client/api-client.js';
import { TenantService } from '../tenant-service.js';

interface Call {
  url: string;
  method: string;
  body: unknown;
}

function recordingClient(): { client: ApiClient; calls: Call[] } {
  const calls: Call[] = [];
  const fetchImpl = ((url: RequestInfo | URL, init?: RequestInit) => {
    calls.push({
      url: String(url),
      method: init?.method ?? 'GET',
      body: typeof init?.body === 'string' ? JSON.parse(init.body) : undefined,
    });
    return Promise.resolve(new Response(JSON.stringify({
      code: 200,
      error: '',
      success: true,
      payload: { status: { success: true, message: 'ok' } },
    }), { status: 200, headers: { 'content-type': 'application/json' } }));
  }) as unknown as typeof fetch;

  const client = new ApiClient({
    baseUrl: '/api',
    fetch: fetchImpl,
    retry: { maxRetries: 0 },
  });
  return { client, calls };
}

describe('TenantService listTenants paging', () => {
  it('sends limit and offset and no page parameter', async () => {
    const { client, calls } = recordingClient();
    await new TenantService(client).listTenants({ limit: 100, offset: 200 });
    expect(calls).toHaveLength(1);
    expect(calls[0]?.method).toBe('GET');
    expect(calls[0]?.url).toContain('limit=100');
    expect(calls[0]?.url).toContain('offset=200');
    expect(calls[0]?.url).not.toContain('page=');
  });

  it('sends offset 0 when it is given', async () => {
    const { client, calls } = recordingClient();
    await new TenantService(client).listTenants({ limit: 100, offset: 0 });
    expect(calls[0]?.url).toContain('offset=0');
  });
});

describe('TenantService barrier operations', () => {
  it('initBarrier posts threshold and shares to barrier/init', async () => {
    const { client, calls } = recordingClient();
    const res = await new TenantService(client).initBarrier({ tenantId: 't 1', threshold: 2, shares: 3 });
    expect(res.success).toBe(true);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.method).toBe('POST');
    expect(calls[0]?.url).toContain('/v1/tenants/t%201/barrier/init');
    expect(calls[0]?.body).toEqual({ threshold: 2, shares: 3 });
  });

  it('unsealBarrier posts the key to barrier/unseal', async () => {
    const { client, calls } = recordingClient();
    const res = await new TenantService(client).unsealBarrier({ tenantId: 't1', key: 'a2V5' });
    expect(res.success).toBe(true);
    expect(calls[0]?.method).toBe('POST');
    expect(calls[0]?.url).toContain('/v1/tenants/t1/barrier/unseal');
    expect(calls[0]?.body).toEqual({ key: 'a2V5' });
  });

  it('sealBarrier posts to barrier/seal', async () => {
    const { client, calls } = recordingClient();
    const res = await new TenantService(client).sealBarrier('t1');
    expect(res.success).toBe(true);
    expect(calls[0]?.method).toBe('POST');
    expect(calls[0]?.url).toContain('/v1/tenants/t1/barrier/seal');
  });
});

describe('TenantService quota-check and DEK routes', () => {
  it('checkQuota posts resource and amount to quota-check', async () => {
    const { client, calls } = recordingClient();
    await new TenantService(client).checkQuota({ tenantId: 't1', resource: 'vcpus', amount: 8 });
    expect(calls[0]?.method).toBe('POST');
    expect(calls[0]?.url).toMatch(/\/v1\/tenants\/t1\/quota-check$/);
    expect(calls[0]?.body).toEqual({ resource: 'vcpus', amount: 8 });
  });

  it('getDEKStatus gets the dek route', async () => {
    const { client, calls } = recordingClient();
    await new TenantService(client).getDEKStatus('t1');
    expect(calls[0]?.method).toBe('GET');
    expect(calls[0]?.url).toMatch(/\/v1\/tenants\/t1\/dek$/);
  });
});
