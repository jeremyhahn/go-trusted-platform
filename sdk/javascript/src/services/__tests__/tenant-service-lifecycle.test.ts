/**
 * TenantService lifecycle, quota, sync and DEK routes (#1758).
 *
 * Each case pins the method and path the server registers under
 * /api/v1/tenants (pkg/webservice/v1/rest/tenant/router.go).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { TenantService } from '../tenant-service.js';
import type { ApiClient } from '../../client/api-client.js';

function createMockApiClient(): ApiClient {
  return {
    get: vi.fn().mockResolvedValue({ success: true, data: {} }),
    post: vi.fn().mockResolvedValue({ success: true, data: {} }),
    put: vi.fn().mockResolvedValue({ success: true, data: {} }),
    patch: vi.fn(),
    delete: vi.fn().mockResolvedValue({ success: true, data: {} }),
    head: vi.fn(),
    options: vi.fn(),
    fetch: vi.fn(),
    baseUrl: 'http://localhost',
  } as unknown as ApiClient;
}

describe('TenantService lifecycle routes', () => {
  let service: TenantService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new TenantService(mockClient);
  });

  it('getTenantByName GETs /by-name/{name}, encoding the name', async () => {
    await service.getTenantByName('acme corp');
    expect(mockClient.get).toHaveBeenCalledWith('/v1/tenants/by-name/acme%20corp');
  });

  it('updateTenant PUTs /{id}', async () => {
    await service.updateTenant({ tenantId: 't-1', displayName: 'Acme' });
    expect(mockClient.put).toHaveBeenCalledWith('/v1/tenants/t-1', {
      tenantId: 't-1',
      displayName: 'Acme',
    });
  });

  it('deleteTenant DELETEs /{id}', async () => {
    await service.deleteTenant('t-1');
    expect(mockClient.delete).toHaveBeenCalledWith('/v1/tenants/t-1');
  });

  it('suspendTenant POSTs /{id}/suspend', async () => {
    await service.suspendTenant('t-1');
    expect(mockClient.post).toHaveBeenCalledWith('/v1/tenants/t-1/suspend', {});
  });

  it('resumeTenant POSTs /{id}/resume', async () => {
    await service.resumeTenant('t-1');
    expect(mockClient.post).toHaveBeenCalledWith('/v1/tenants/t-1/resume', {});
  });

  it('updateQuotas PUTs /{id}/quotas without the tenant id in the body', async () => {
    await service.updateQuotas({ tenantId: 't-1', compute: { maxVms: 4 } });
    expect(mockClient.put).toHaveBeenCalledWith('/v1/tenants/t-1/quotas', {
      compute: { maxVms: 4 },
      network: undefined,
      storage: undefined,
    });
  });

  it('checkQuota POSTs the served /{id}/quota-check path, not /quotas/check', async () => {
    await service.checkQuota({ tenantId: 't-1', resource: 'vms', amount: 2 });
    expect(mockClient.post).toHaveBeenCalledWith('/v1/tenants/t-1/quota-check', {
      resource: 'vms',
      amount: 2,
    });
    expect(vi.mocked(mockClient.post).mock.calls[0]?.[0]).not.toContain('/quotas/check');
  });

  it('syncTenants POSTs /sync', async () => {
    await service.syncTenants();
    expect(mockClient.post).toHaveBeenCalledWith('/v1/tenants/sync', {});
  });

  it('rotateDEK POSTs /{id}/dek/rotate', async () => {
    await service.rotateDEK({ tenantId: 't-1', background: true });
    expect(mockClient.post).toHaveBeenCalledWith('/v1/tenants/t-1/dek/rotate', {
      background: true,
    });
  });

  it('getDEKStatus GETs the served /{id}/dek path, not /dek/status', async () => {
    await service.getDEKStatus('t-1');
    expect(mockClient.get).toHaveBeenCalledWith('/v1/tenants/t-1/dek');
  });

  it('propagates a transport error unchanged', async () => {
    const failure = new Error('404 Not Found');
    vi.mocked(mockClient.delete).mockRejectedValue(failure);
    await expect(service.deleteTenant('t-1')).rejects.toBe(failure);
  });
});
