/**
 * RegistryService: the URL and method of each call.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { RegistryService, RegistryHealth } from '../registry-service.js';
import { ApiClient } from '../../client/api-client.js';
import * as sdk from '../../index.js';

describe('RegistryService package entry point', () => {
  it('is exported from the package entry point', () => {
    expect(sdk.RegistryService).toBe(RegistryService);
    expect(sdk.RegistryHealth).toBeDefined();
    expect(sdk.RegistryHealth).toBe(RegistryHealth);
  });
});

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

    expect(mockClient.get).toHaveBeenCalledWith('/v2/team/app/tags/list', { rootRelative: true });
    expect(res.data?.tags).toEqual(['v1', 'latest']);
  });

  it('listTags encodes each name segment', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({ success: true });

    await service.listTags('a b/c');

    expect(mockClient.get).toHaveBeenCalledWith('/v2/a%20b/c/tags/list', { rootRelative: true });
  });

  it('deleteManifest deletes by tag', async () => {
    vi.mocked(mockClient.delete).mockResolvedValue({ success: true });

    await service.deleteManifest('team/app', 'v1');

    expect(mockClient.delete).toHaveBeenCalledWith('/v2/team/app/manifests/v1', { rootRelative: true });
  });

  it('deleteManifest encodes a digest reference', async () => {
    vi.mocked(mockClient.delete).mockResolvedValue({ success: true });

    await service.deleteManifest('app', 'sha256:abc');

    expect(mockClient.delete).toHaveBeenCalledWith('/v2/app/manifests/sha256%3Aabc', { rootRelative: true });
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

describe('RegistryService with a real ApiClient', () => {
  /** Builds a service over a real ApiClient whose fetch records each call. */
  function serviceWith(baseUrl: string) {
    const calls: Array<{ url: string; method: string }> = [];
    const fetchImpl = ((input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(input), method: init?.method ?? 'GET' });
      return Promise.resolve(
        new Response(JSON.stringify({ name: 'team/app', tags: [] }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        })
      );
    }) as unknown as typeof fetch;
    const client = new ApiClient({ baseUrl, fetch: fetchImpl, retry: { maxRetries: 0 } });
    return { service: new RegistryService(client), calls };
  }

  it('listTags requests the host-root /v2 route, not under /api', async () => {
    const { service, calls } = serviceWith('/api');

    await service.listTags('team/app');

    expect(calls).toEqual([{ url: '/v2/team/app/tags/list', method: 'GET' }]);
  });

  it('deleteManifest sends DELETE to the host-root /v2 route', async () => {
    const { service, calls } = serviceWith('/api');

    await service.deleteManifest('team/app', 'v1');

    expect(calls).toEqual([{ url: '/v2/team/app/manifests/v1', method: 'DELETE' }]);
  });

  it('getStatus keeps the API prefix', async () => {
    const { service, calls } = serviceWith('/api');

    await service.getStatus();

    expect(calls).toEqual([{ url: '/api/v1/compute/images/status', method: 'GET' }]);
  });

  it('listTags resolves against the host root of an absolute baseUrl', async () => {
    const { service, calls } = serviceWith('https://platform.test/api');

    await service.listTags('team/app');

    expect(calls).toEqual([
      { url: 'https://platform.test/v2/team/app/tags/list', method: 'GET' },
    ]);
  });
});
