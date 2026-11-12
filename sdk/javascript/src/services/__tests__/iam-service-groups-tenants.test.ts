/**
 * IAMService group, member, permission check and tenant routes (#1744).
 *
 * The paths are the ones pkg/webservice/v1/rest/iam/router.go registers:
 * the member is a path segment of /groups/{id}/members/{user}, and the
 * permission check is /tenants/{tenant}/permissions/check.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { IAMService } from '../iam-service.js';
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

function calledPath(fn: unknown): string {
  return String(vi.mocked(fn as (...a: unknown[]) => unknown).mock.calls[0]?.[0]);
}

describe('IAMService groups, members, permission check and tenants', () => {
  let service: IAMService;
  let mockClient: ApiClient;
  const ok = { success: true, data: {} };

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new IAMService(mockClient);
    vi.mocked(mockClient.get).mockResolvedValue(ok);
    vi.mocked(mockClient.post).mockResolvedValue(ok);
    vi.mocked(mockClient.put).mockResolvedValue(ok);
    vi.mocked(mockClient.delete).mockResolvedValue(ok);
  });

  it('createGroup POSTs /tenants/{tenant}/groups', async () => {
    await service.createGroup({ tenantId: 't1', name: 'ops' } as never);
    expect(calledPath(mockClient.post)).toMatch(/\/tenants\/t1\/groups$/);
  });

  it('getGroup GETs /tenants/{tenant}/groups/{id}', async () => {
    await service.getGroup('t1', 'g1');
    expect(calledPath(mockClient.get)).toMatch(/\/tenants\/t1\/groups\/g1$/);
  });

  it('updateGroup PUTs /tenants/{tenant}/groups/{id}', async () => {
    await service.updateGroup({ tenantId: 't1', groupId: 'g1', name: 'ops2' });
    expect(calledPath(mockClient.put)).toMatch(/\/tenants\/t1\/groups\/g1$/);
  });

  it('addGroupMember POSTs the user as a path segment, as the server routes it', async () => {
    await service.addGroupMember({ tenantId: 't1', groupId: 'g1', userId: 'u/1' });
    expect(mockClient.post).toHaveBeenCalledTimes(1);
    expect(calledPath(mockClient.post)).toMatch(/\/tenants\/t1\/groups\/g1\/members\/u%2F1$/);
  });

  it('removeGroupMember DELETEs /tenants/{tenant}/groups/{id}/members/{user}', async () => {
    await service.removeGroupMember({ tenantId: 't1', groupId: 'g1', userId: 'u1' });
    expect(calledPath(mockClient.delete)).toMatch(/\/tenants\/t1\/groups\/g1\/members\/u1$/);
  });

  it('checkPermission POSTs /tenants/{tenant}/permissions/check, not /auth/check', async () => {
    const request = { tenantId: 't1', subjectId: 'u1', action: 'read', resource: 'devices' };
    await service.checkPermission(request);
    expect(calledPath(mockClient.post)).toMatch(/\/tenants\/t1\/permissions\/check$/);
    expect(calledPath(mockClient.post)).not.toContain('/auth/check');
    expect(vi.mocked(mockClient.post).mock.calls[0]?.[1]).toEqual(request);
  });

  it('tenant CRUD uses /tenants and /tenants/{tenant}', async () => {
    await service.createTenant({ name: 'acme' });
    expect(calledPath(mockClient.post)).toMatch(/\/tenants$/);
    await service.getTenant('acme');
    expect(calledPath(mockClient.get)).toMatch(/\/tenants\/acme$/);
    await service.updateTenant({ tenantId: 'acme', name: 'Acme' });
    expect(calledPath(mockClient.put)).toMatch(/\/tenants\/acme$/);
    await service.deleteTenant('acme');
    expect(calledPath(mockClient.delete)).toMatch(/\/tenants\/acme$/);
  });

  it('listTenants GETs /tenants', async () => {
    await service.listTenants();
    expect(calledPath(mockClient.get)).toMatch(/\/tenants(\?.*)?$/);
  });
});
