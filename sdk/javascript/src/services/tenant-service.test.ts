/**
 * Unit tests for TenantService: each public method is driven through a
 * mocked ApiClient and asserted on HTTP method, path, query and body, plus
 * one error case that must reach the caller unchanged.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { TenantService } from './tenant-service.js';
import type { ApiClient } from '../client/api-client.js';
import type { ComputeQuota, NetworkQuota, StorageQuota } from '../types/tenant.js';

function createMockApiClient(): ApiClient {
  return {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
    head: vi.fn(),
    options: vi.fn(),
    fetch: vi.fn(),
  } as unknown as ApiClient;
}

describe('TenantService', () => {
  let mockClient: ApiClient;
  let service: TenantService;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new TenantService(mockClient);
  });

  describe('createTenant', () => {
    it('POSTs the request to /v1/tenants', async () => {
      vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: { tenant: {} } });
      const request = { name: 'acme', displayName: 'Acme', labels: { env: 'prod' } };

      const result = await service.createTenant(request);

      expect(mockClient.post).toHaveBeenCalledTimes(1);
      expect(mockClient.post).toHaveBeenCalledWith('/v1/tenants', request);
      expect(result).toEqual({ success: true, data: { tenant: {} } });
    });

    it('propagates a transport error', async () => {
      const failure = new Error('409 Conflict: tenant already exists');
      vi.mocked(mockClient.post).mockRejectedValue(failure);

      await expect(service.createTenant({ name: 'acme' })).rejects.toBe(failure);
    });
  });

  describe('getTenant', () => {
    it('GETs /v1/tenants/{id} with no query', async () => {
      vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: { tenant: {} } });

      await service.getTenant('t-1');

      expect(mockClient.get).toHaveBeenCalledWith('/v1/tenants/t-1');
    });

    it('encodes the tenant id as one path segment', async () => {
      vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: { tenant: {} } });

      await service.getTenant('a/b');

      expect(mockClient.get).toHaveBeenCalledWith('/v1/tenants/a%2Fb');
    });

    it('propagates a transport error', async () => {
      const failure = new Error('404 Not Found: tenant not found');
      vi.mocked(mockClient.get).mockRejectedValue(failure);

      await expect(service.getTenant('missing')).rejects.toBe(failure);
    });
  });

  describe('getTenantByName', () => {
    it('GETs /v1/tenants/by-name/{name} with the name encoded', async () => {
      vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: { tenant: {} } });

      await service.getTenantByName('acme corp');

      expect(mockClient.get).toHaveBeenCalledWith('/v1/tenants/by-name/acme%20corp');
    });

    it('propagates a transport error', async () => {
      const failure = new Error('404 Not Found: tenant not found');
      vi.mocked(mockClient.get).mockRejectedValue(failure);

      await expect(service.getTenantByName('missing')).rejects.toBe(failure);
    });
  });

  describe('listTenants', () => {
    it('GETs /v1/tenants with no query when called without a request', async () => {
      vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: { tenants: [] } });

      await service.listTenants();

      expect(mockClient.get).toHaveBeenCalledWith('/v1/tenants');
    });

    it('turns offset and limit into page and limit, and labels into label_ filters', async () => {
      vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: { tenants: [] } });

      await service.listTenants({
        offset: 20,
        limit: 10,
        selector: { matchLabels: { env: 'prod' } },
      });

      expect(mockClient.get).toHaveBeenCalledWith('/v1/tenants?page=3&limit=10&label_env=prod');
    });

    it('sends limit without page when no offset is given', async () => {
      vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: { tenants: [] } });

      await service.listTenants({ limit: 5 });

      expect(mockClient.get).toHaveBeenCalledWith('/v1/tenants?limit=5');
    });

    it('propagates a transport error', async () => {
      const failure = new Error('503 Service Unavailable');
      vi.mocked(mockClient.get).mockRejectedValue(failure);

      await expect(service.listTenants()).rejects.toBe(failure);
    });
  });

  describe('updateTenant', () => {
    it('PUTs the request to /v1/tenants/{id}', async () => {
      vi.mocked(mockClient.put).mockResolvedValue({ success: true, data: { tenant: {} } });
      const request = { tenantId: 't-1', displayName: 'Acme 2', labels: { env: 'dev' } };

      await service.updateTenant(request);

      expect(mockClient.put).toHaveBeenCalledWith('/v1/tenants/t-1', request);
    });

    it('propagates a transport error', async () => {
      const failure = new Error('400 Bad Request: invalid display name');
      vi.mocked(mockClient.put).mockRejectedValue(failure);

      await expect(service.updateTenant({ tenantId: 't-1' })).rejects.toBe(failure);
    });
  });

  describe('deleteTenant', () => {
    it('DELETEs /v1/tenants/{id}', async () => {
      vi.mocked(mockClient.delete).mockResolvedValue({ success: true, data: {} });

      await service.deleteTenant('t-1');

      expect(mockClient.delete).toHaveBeenCalledWith('/v1/tenants/t-1');
    });

    it('propagates a transport error', async () => {
      const failure = new Error('404 Not Found: tenant not found');
      vi.mocked(mockClient.delete).mockRejectedValue(failure);

      await expect(service.deleteTenant('missing')).rejects.toBe(failure);
    });
  });

  describe('suspendTenant', () => {
    it('POSTs an empty body to /v1/tenants/{id}/suspend', async () => {
      vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: {} });

      await service.suspendTenant('t-1');

      expect(mockClient.post).toHaveBeenCalledWith('/v1/tenants/t-1/suspend', {});
    });

    it('propagates a transport error', async () => {
      const failure = new Error('409 Conflict: tenant already suspended');
      vi.mocked(mockClient.post).mockRejectedValue(failure);

      await expect(service.suspendTenant('t-1')).rejects.toBe(failure);
    });
  });

  describe('resumeTenant', () => {
    it('POSTs an empty body to /v1/tenants/{id}/resume', async () => {
      vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: {} });

      await service.resumeTenant('t-1');

      expect(mockClient.post).toHaveBeenCalledWith('/v1/tenants/t-1/resume', {});
    });

    it('propagates a transport error', async () => {
      const failure = new Error('409 Conflict: tenant is not suspended');
      vi.mocked(mockClient.post).mockRejectedValue(failure);

      await expect(service.resumeTenant('t-1')).rejects.toBe(failure);
    });
  });

  describe('getQuotas', () => {
    it('GETs /v1/tenants/{id}/quotas', async () => {
      vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: {} });

      await service.getQuotas('t-1');

      expect(mockClient.get).toHaveBeenCalledWith('/v1/tenants/t-1/quotas');
    });

    it('propagates a transport error', async () => {
      const failure = new Error('404 Not Found: tenant not found');
      vi.mocked(mockClient.get).mockRejectedValue(failure);

      await expect(service.getQuotas('missing')).rejects.toBe(failure);
    });
  });

  describe('updateQuotas', () => {
    it('PUTs only the quota sections to /v1/tenants/{id}/quotas', async () => {
      vi.mocked(mockClient.put).mockResolvedValue({ success: true, data: {} });
      const compute = { maxInstances: 4 } as unknown as ComputeQuota;
      const network = { maxNetworks: 2 } as unknown as NetworkQuota;
      const storage = { maxVolumes: 8 } as unknown as StorageQuota;

      await service.updateQuotas({ tenantId: 't-1', compute, network, storage });

      expect(mockClient.put).toHaveBeenCalledWith('/v1/tenants/t-1/quotas', {
        compute,
        network,
        storage,
      });
    });

    it('propagates a transport error', async () => {
      const failure = new Error('400 Bad Request: quota below current usage');
      vi.mocked(mockClient.put).mockRejectedValue(failure);

      await expect(service.updateQuotas({ tenantId: 't-1' })).rejects.toBe(failure);
    });
  });

  describe('getUsage', () => {
    it('GETs /v1/tenants/{id}/usage', async () => {
      vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: {} });

      await service.getUsage('t-1');

      expect(mockClient.get).toHaveBeenCalledWith('/v1/tenants/t-1/usage');
    });

    it('propagates a transport error', async () => {
      const failure = new Error('404 Not Found: tenant not found');
      vi.mocked(mockClient.get).mockRejectedValue(failure);

      await expect(service.getUsage('missing')).rejects.toBe(failure);
    });
  });

  describe('checkQuota', () => {
    it('POSTs resource and amount to /v1/tenants/{id}/quotas/check', async () => {
      vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: { allowed: true } });

      await service.checkQuota({ tenantId: 't-1', resource: 'vcpu', amount: 2 });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/tenants/t-1/quotas/check', {
        resource: 'vcpu',
        amount: 2,
      });
    });

    it('propagates a transport error', async () => {
      const failure = new Error('400 Bad Request: unknown resource');
      vi.mocked(mockClient.post).mockRejectedValue(failure);

      await expect(
        service.checkQuota({ tenantId: 't-1', resource: 'bogus', amount: 1 })
      ).rejects.toBe(failure);
    });
  });

  describe('rotateDEK', () => {
    it('POSTs the background flag to /v1/tenants/{id}/dek/rotate', async () => {
      vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: {} });

      await service.rotateDEK({ tenantId: 't-1', background: true });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/tenants/t-1/dek/rotate', {
        background: true,
      });
    });

    it('propagates a transport error', async () => {
      const failure = new Error('409 Conflict: rotation in progress');
      vi.mocked(mockClient.post).mockRejectedValue(failure);

      await expect(service.rotateDEK({ tenantId: 't-1' })).rejects.toBe(failure);
    });
  });

  describe('getDEKStatus', () => {
    it('GETs /v1/tenants/{id}/dek/status', async () => {
      vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: {} });

      await service.getDEKStatus('t-1');

      expect(mockClient.get).toHaveBeenCalledWith('/v1/tenants/t-1/dek/status');
    });

    it('propagates a transport error', async () => {
      const failure = new Error('404 Not Found: tenant not found');
      vi.mocked(mockClient.get).mockRejectedValue(failure);

      await expect(service.getDEKStatus('missing')).rejects.toBe(failure);
    });
  });

  describe('syncTenants', () => {
    it('POSTs an empty body to /v1/tenants/sync', async () => {
      vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: {} });

      await service.syncTenants();

      expect(mockClient.post).toHaveBeenCalledWith('/v1/tenants/sync', {});
    });

    it('propagates a transport error', async () => {
      const failure = new Error('403 Forbidden: admin only');
      vi.mocked(mockClient.post).mockRejectedValue(failure);

      await expect(service.syncTenants()).rejects.toBe(failure);
    });
  });
});
