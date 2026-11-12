/**
 * RegistryService: the URL and method of each call.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { RegistryService, RegistryHealth } from '../registry-service.js';
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

describe('RegistryService', () => {
  let mockClient: ApiClient;
  let service: RegistryService;

  beforeEach(() => {
    mockClient = createMockClient();
    service = new RegistryService(mockClient);
  });

  it('listTags gets the OCI tag list and keeps slashes in the name', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({
      success: true,
      data: { name: 'team/app', tags: ['v1', 'latest'] },
    });

    const res = await service.listTags('team/app');

    expect(mockClient.get).toHaveBeenCalledWith('/v2/team/app/tags/list');
    expect(res.data?.tags).toEqual(['v1', 'latest']);
  });

  it('listTags encodes each name segment', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({ success: true });

    await service.listTags('a b/c');

    expect(mockClient.get).toHaveBeenCalledWith('/v2/a%20b/c/tags/list');
  });

  it('deleteManifest deletes by tag', async () => {
    vi.mocked(mockClient.delete).mockResolvedValue({ success: true });

    await service.deleteManifest('team/app', 'v1');

    expect(mockClient.delete).toHaveBeenCalledWith('/v2/team/app/manifests/v1');
  });

  it('deleteManifest encodes a digest reference', async () => {
    vi.mocked(mockClient.delete).mockResolvedValue({ success: true });

    await service.deleteManifest('app', 'sha256:abc');

    expect(mockClient.delete).toHaveBeenCalledWith('/v2/app/manifests/sha256%3Aabc');
  });

  it('getStatus gets the registry status', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({
      success: true,
      data: { Health: RegistryHealth.Healthy, Version: '1.0.0', ReadOnly: false },
    });

    const res = await service.getStatus();

    expect(mockClient.get).toHaveBeenCalledWith('/v1/compute/images/status');
    expect(res.data?.Health).toBe(RegistryHealth.Healthy);
  });
});
