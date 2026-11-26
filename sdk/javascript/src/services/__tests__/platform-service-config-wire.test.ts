/**
 * PlatformService config wire tests: getConfig sends the redact and section
 * query parameters the REST handler reads, and the config and reload
 * responses carry the shapes the handlers write (#2047).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { PlatformService } from '../platform-service.js';
import type { ApiClient } from '../../client/api-client.js';
import type { ApiResponse } from '../../types/api.js';
import type { GetConfigResponse, ReloadConfigResponse } from '../../types/platform.js';

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

describe('PlatformService config wire', () => {
  let mockClient: ApiClient;
  let service: PlatformService;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new PlatformService(mockClient);
  });

  it('sends redact=false and section when asked for sensitive values of one section', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: undefined });

    await service.getConfig({ includeSensitive: true, section: 'logging' });

    expect(mockClient.get).toHaveBeenCalledTimes(1);
    expect(mockClient.get).toHaveBeenCalledWith('/v1/platform/config?redact=false&section=logging');
  });

  it('sends no query when no sensitive values or section are asked for', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: undefined });

    await service.getConfig();
    await service.getConfig({ includeSensitive: false });

    expect(mockClient.get).toHaveBeenNthCalledWith(1, '/v1/platform/config');
    expect(mockClient.get).toHaveBeenNthCalledWith(2, '/v1/platform/config');
  });

  it('reads the config tree the server answers', async () => {
    const reply: ApiResponse<GetConfigResponse> = {
      success: true,
      data: {
        sources: [{ path: '/etc/platform.yaml', format: 'yaml' }],
        tree: { logging: { level: 'info' } },
        generated_at: '2026-11-21T00:00:00Z',
        redacted_keys: ['tls.key_password'],
        secrets_hidden: true,
      },
    };
    vi.mocked(mockClient.get).mockResolvedValue(reply);

    const result = await service.getConfig();

    expect(result.data?.tree).toEqual({ logging: { level: 'info' } });
    expect(result.data?.sources[0]?.path).toBe('/etc/platform.yaml');
    expect(result.data?.secrets_hidden).toBe(true);
  });

  it('reloadConfig posts to the reload route and reads the reload body', async () => {
    const reply: ApiResponse<ReloadConfigResponse> = {
      success: true,
      data: { reloaded: true, sections: ['logging'], pre_reload_snapshot: 'snap-1' },
    };
    vi.mocked(mockClient.post).mockResolvedValue(reply);

    const result = await service.reloadConfig();

    expect(mockClient.post).toHaveBeenCalledWith('/v1/platform/config/reload', {});
    expect(result.data?.pre_reload_snapshot).toBe('snap-1');
  });
});
