/**
 * TenantService barrier operations against the daemon REST handlers
 * (pkg/api/rest/tenant_handlers.go, Codex review of PR #2022):
 * - handleInitTenantBarrier discards threshold and shares, so the SDK
 *   refuses them before any request is sent;
 * - the handlers answer with a flat TenantBarrierActionResponse
 *   ({tenant_id, success, message, timestamp}), which the SDK normalises
 *   into the declared { status } shape.
 */
import { describe, it, expect } from 'vitest';
import { ApiClient } from '../../client/api-client.js';
import { TenantService } from '../tenant-service.js';

function daemonClient(body: unknown): { client: ApiClient; calls: string[] } {
  const calls: string[] = [];
  const fetchImpl = ((url: RequestInfo | URL) => {
    calls.push(String(url));
    return Promise.resolve(new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));
  }) as unknown as typeof fetch;
  const client = new ApiClient({ baseUrl: '/api', fetch: fetchImpl, retry: { maxRetries: 0 } });
  return { client, calls };
}

describe('TenantService.initBarrier Shamir settings', () => {
  it.each([
    { threshold: 2, shares: 3 },
    { threshold: 2 },
    { shares: 3 },
  ])('refuses %o before any request is sent', async (settings) => {
    const { client, calls } = daemonClient({ tenant_id: 't1', success: true });
    await expect(new TenantService(client).initBarrier({ tenantId: 't1', ...settings })).rejects.toThrow(RangeError);
    expect(calls).toHaveLength(0);
  });
});

// TenantBarrierActionResponse as handleInitTenantBarrier, handleUnsealTenantBarrier
// and handleSealTenantBarrier write it.
const daemonBody = {
  tenant_id: 't1',
  success: true,
  message: 'tenant barrier initialized',
  timestamp: '2026-11-20T05:00:00Z',
};

describe('TenantService barrier responses from the daemon', () => {
  it.each([
    ['initBarrier', (s: TenantService) => s.initBarrier({ tenantId: 't1' })],
    ['unsealBarrier', (s: TenantService) => s.unsealBarrier({ tenantId: 't1', key: 'a2V5' })],
    ['sealBarrier', (s: TenantService) => s.sealBarrier('t1')],
  ] as const)('%s normalises the flat body into status', async (_name, call) => {
    const { client } = daemonClient(daemonBody);
    const res = await call(new TenantService(client));
    expect(res.success).toBe(true);
    expect(res.data?.status).toEqual({ success: true, message: 'tenant barrier initialized' });
  });

  it('reports a daemon failure in status', async () => {
    const { client } = daemonClient({ ...daemonBody, success: false, message: 'sealed' });
    const res = await new TenantService(client).sealBarrier('t1');
    expect(res.data?.status).toEqual({ success: false, message: 'sealed' });
  });

  it('keeps the webservice status shape', async () => {
    const { client } = daemonClient({ status: { success: true, message: 'ok' } });
    const res = await new TenantService(client).sealBarrier('t1');
    expect(res.data?.status).toEqual({ success: true, message: 'ok' });
  });
});
