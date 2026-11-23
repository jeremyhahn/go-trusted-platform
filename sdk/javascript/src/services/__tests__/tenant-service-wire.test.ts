/**
 * TenantService wire paths: the quota check and DEK status calls reach the
 * routes the server serves (POST /api/v1/tenants/{id}/quota-check and
 * GET /api/v1/tenants/{id}/dek), #2067.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { TenantService } from '../tenant-service.js';
import type { ApiClient } from '../../client/api-client.js';

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
    baseUrl: 'https://api.example.com',
  } as unknown as ApiClient;
}

function pathOf(url: unknown): string {
  return new URL(String(url), 'https://api.example.com').pathname;
}

describe('TenantService wire paths', () => {
  let mockClient: ApiClient;
  let service: TenantService;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new TenantService(mockClient);
  });

  it('checkQuota posts to /tenants/{id}/quota-check with resource and amount', async () => {
    await service.checkQuota({ tenantId: 't1', resource: 'vms', amount: 2 });

    const call = vi.mocked(mockClient.post).mock.calls[0];
    expect(pathOf(call?.[0]).endsWith('/tenants/t1/quota-check')).toBe(true);
    expect(call?.[1]).toEqual({ resource: 'vms', amount: 2 });
  });

  it('getDEKStatus reads /tenants/{id}/dek', async () => {
    await service.getDEKStatus('t1');

    const path = pathOf(vi.mocked(mockClient.get).mock.calls[0]?.[0]);
    expect(path.endsWith('/tenants/t1/dek')).toBe(true);
    expect(path.endsWith('/dek/status')).toBe(false);
  });
});
