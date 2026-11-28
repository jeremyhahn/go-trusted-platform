/**
 * RegistryService.inspect: GET /v1/compute/images/{repository}:{tag} (#2063).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { RegistryService } from '../registry-service.js';
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

describe('RegistryService.inspect', () => {
  let mockClient: ApiClient;
  let service: RegistryService;

  beforeEach(() => {
    mockClient = createMockClient();
    service = new RegistryService(mockClient);
  });

  it('inspect gets the image by repository and tag', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: { Tags: ['v1'] } });

    const res = await service.inspect('team/app', 'v1');

    expect(mockClient.get).toHaveBeenCalledWith('/v1/compute/images/team/app:v1');
    expect(res.data).toEqual({ Tags: ['v1'] });
  });

  it('inspect encodes each segment and keeps a host port', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({ success: true });

    await service.inspect('registry.example:5000/my app', 'v 1');

    expect(mockClient.get).toHaveBeenCalledWith(
      '/v1/compute/images/registry.example%3A5000/my%20app:v%201'
    );
  });

  it('inspect never writes', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({ success: true });

    await service.inspect('team/app', 'v1');

    expect(mockClient.post).not.toHaveBeenCalled();
    expect(mockClient.put).not.toHaveBeenCalled();
    expect(mockClient.patch).not.toHaveBeenCalled();
    expect(mockClient.delete).not.toHaveBeenCalled();
  });
});
