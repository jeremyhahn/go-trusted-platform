/**
 * IAMService group calls: the URL and method of each call (#2053).
 *
 * The control plane routes group membership only as
 * /groups/{id}/members/{user} (POST to add, DELETE to remove), so the
 * user ID travels in the path, never in the body.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { IAMService } from '../iam-service.js';
import type { ApiClient } from '../../client/api-client.js';

function createMockClient(): ApiClient {
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

describe('IAMService group calls', () => {
  let mockClient: ApiClient;
  let service: IAMService;

  beforeEach(() => {
    mockClient = createMockClient();
    service = new IAMService(mockClient);
    for (const m of ['get', 'post', 'put', 'delete'] as const) {
      vi.mocked(mockClient[m]).mockResolvedValue({ success: true });
    }
  });

  it('createGroup posts /v1/iam/tenants/{tenant}/groups', async () => {
    await service.createGroup({ tenantId: 't-1', id: 'g-1', name: 'Eng' });
    expect(vi.mocked(mockClient.post).mock.calls[0]?.[0]).toBe('/v1/iam/tenants/t-1/groups');
    expect(vi.mocked(mockClient.post).mock.calls[0]?.[1]).toMatchObject({ tenantId: 't-1', id: 'g-1', name: 'Eng' });
  });

  it('getGroup gets /v1/iam/tenants/{tenant}/groups/{id}', async () => {
    await service.getGroup('t-1', 'g-1');
    expect(vi.mocked(mockClient.get).mock.calls[0]?.[0]).toBe('/v1/iam/tenants/t-1/groups/g-1');
  });

  it('updateGroup puts /v1/iam/tenants/{tenant}/groups/{id}', async () => {
    await service.updateGroup({ tenantId: 't-1', groupId: 'g-1', name: 'Eng 2', description: 'd' });
    expect(vi.mocked(mockClient.put).mock.calls[0]?.[0]).toBe('/v1/iam/tenants/t-1/groups/g-1');
    expect(vi.mocked(mockClient.put).mock.calls[0]?.[1]).toMatchObject({ name: 'Eng 2', description: 'd' });
  });

  it('addGroupMember posts /v1/iam/tenants/{tenant}/groups/{id}/members/{user}', async () => {
    await service.addGroupMember({ tenantId: 't-1', groupId: 'g-1', userId: 'u/1' });
    expect(vi.mocked(mockClient.post).mock.calls[0]?.[0]).toBe('/v1/iam/tenants/t-1/groups/g-1/members/u%2F1');
  });

  it('addGroupMember sends no body field naming the user', async () => {
    await service.addGroupMember({ tenantId: 't-1', groupId: 'g-1', userId: 'u/1' });
    expect(vi.mocked(mockClient.post).mock.calls[0]?.[1]).toEqual({});
  });

  it('removeGroupMember deletes /v1/iam/tenants/{tenant}/groups/{id}/members/{user}', async () => {
    await service.removeGroupMember({ tenantId: 't-1', groupId: 'g-1', userId: 'u/1' });
    expect(vi.mocked(mockClient.delete).mock.calls[0]?.[0]).toBe('/v1/iam/tenants/t-1/groups/g-1/members/u%2F1');
  });
});
