/**
 * TenantService.rotateDEK (#2189 Codex): a rotation is not idempotent (each
 * success advances the key version), so it is posted with network retries
 * disabled and a lost response is never sent again.
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

describe('TenantService.rotateDEK', () => {
  let service: TenantService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: {} });
    service = new TenantService(mockClient);
  });

  it('posts the rotation with network retries disabled', async () => {
    await service.rotateDEK({ tenantId: 't-1', background: false });

    expect(mockClient.post).toHaveBeenCalledWith(
      expect.stringContaining('/t-1/dek/rotate'),
      { background: false },
      { retry: { enabled: false } }
    );
  });
});
