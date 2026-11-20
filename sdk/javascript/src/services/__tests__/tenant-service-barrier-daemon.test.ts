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
