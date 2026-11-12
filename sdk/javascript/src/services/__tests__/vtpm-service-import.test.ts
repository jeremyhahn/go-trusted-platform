/**
 * VTPMService.importBundle (#1674): POST /api/v1/vtpm/bundles/import reads
 * the raw request body as the bundle archive, so the Blob must reach the
 * client unchanged.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { VTPMService } from '../vtpm-service.js';
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

describe('VTPMService.importBundle', () => {
  let mockClient: ApiClient;
  let service: VTPMService;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new VTPMService(mockClient);
  });

  it('posts the archive Blob unchanged to /bundles/import', async () => {
    const payload = { id: 'bundle-1', mode: 'TEMPLATE' };
    vi.mocked(mockClient.post).mockResolvedValue({ data: payload } as never);
    const archive = new Blob([new Uint8Array([0x1f, 0x8b, 0x08, 0x00])], {
      type: 'application/gzip',
    });

    const result = await service.importBundle(archive);

    expect(mockClient.post).toHaveBeenCalledTimes(1);
    const [path, body] = vi.mocked(mockClient.post).mock.calls[0];
    expect(path).toMatch(/\/v1\/vtpm\/bundles\/import$/);
    expect(body).toBe(archive);
    expect(result.data).toEqual(payload);
  });
});
