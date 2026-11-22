/**
 * VTPMService.listBundles paging: the REST handler pages by limit and
 * offset, so the SDK sends offset as it is (#2071, UI epic #1665 slice 34).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { VTPMService } from '../vtpm-service.js';
import { ApiClient } from '../../client/api-client.js';

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

const ok = { success: true, data: {} };

describe('VTPMService.listBundles paging', () => {
  let service: VTPMService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new VTPMService(mockClient);
  });

  it('sends offset and limit as they are, and mode, labels and deviceProfileId to filters', async () => {
    vi.mocked(mockClient.get).mockResolvedValue(ok);

    await service.listBundles({
      options: {
        mode: 'TEMPLATE',
        labels: { env: 'prod', tier: 'a b' },
        limit: 10,
        offset: 20,
        deviceProfileId: '42',
      },
    });

    expect(mockClient.get).toHaveBeenCalledWith(
      '/v1/vtpm/bundles?limit=10&mode=TEMPLATE&label_env=prod&label_tier=a+b&device_profile_id=42&offset=20'
    );
  });

  it('sends only the offset when no limit is given', async () => {
    vi.mocked(mockClient.get).mockResolvedValue(ok);

    await service.listBundles({ options: { offset: 25 } });

    expect(mockClient.get).toHaveBeenCalledWith('/v1/vtpm/bundles?offset=25');
  });

  it('sends only the limit when no offset is given', async () => {
    vi.mocked(mockClient.get).mockResolvedValue(ok);

    await service.listBundles({ options: { limit: 5 } });

    expect(mockClient.get).toHaveBeenCalledWith('/v1/vtpm/bundles?limit=5');
  });
});
