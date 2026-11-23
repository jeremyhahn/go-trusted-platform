/**
 * Unit tests for TenantService.createInitialAdminInvitation
 * (POST /api/v1/tenants/{id}/initial-admin-invitation, system tenant only).
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

describe('TenantService.createInitialAdminInvitation', () => {
  let service: TenantService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new TenantService(mockClient);
  });

  it('posts the owner email to the tenant initial-admin-invitation route', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: {} });

    await service.createInitialAdminInvitation('t 1', 'owner@example.com');

    expect(mockClient.post).toHaveBeenCalledTimes(1);
    const [url, body] = vi.mocked(mockClient.post).mock.calls[0]!;
    expect(String(url).endsWith('/v1/tenants/t%201/initial-admin-invitation')).toBe(true);
    expect(body).toEqual({ email: 'owner@example.com' });
  });

  it('adds expiresInSeconds when it is given', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: {} });

    await service.createInitialAdminInvitation('t1', 'owner@example.com', 3600);

    const [, body] = vi.mocked(mockClient.post).mock.calls[0]!;
    expect(body).toEqual({ email: 'owner@example.com', expiresInSeconds: 3600 });
  });

  it('returns what the client resolved', async () => {
    const resolved = {
      success: true,
      data: { invitation: { id: 'inv-1', email: 'owner@example.com' } },
    };
    vi.mocked(mockClient.post).mockResolvedValue(resolved);

    const result = await service.createInitialAdminInvitation('t1', 'owner@example.com');

    expect(result).toBe(resolved);
  });
});
