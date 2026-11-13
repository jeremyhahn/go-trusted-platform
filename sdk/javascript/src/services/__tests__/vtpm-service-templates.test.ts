/**
 * VTPMService.createTemplate (#1674): POST /api/v1/vtpm/templates decodes
 * the body with DisallowUnknownFields into the REST CreateTemplateRequest
 * (id, description, ek_algorithm, secure_boot_enabled), so the SDK must send
 * that flat body and never the request's `options` wrapper.
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

describe('VTPMService.createTemplate', () => {
  let mockClient: ApiClient;
  let service: VTPMService;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new VTPMService(mockClient);
    vi.mocked(mockClient.post).mockResolvedValue({ data: {} } as never);
  });

  it('posts every field in the handler shape', async () => {
    await service.createTemplate({
      options: { id: 't1', description: 'd', ekAlgorithm: 'ECC', secureBootEnabled: true },
    });

    expect(mockClient.post).toHaveBeenCalledTimes(1);
    const [path, body] = vi.mocked(mockClient.post).mock.calls[0]!;
    expect(path).toMatch(/\/v1\/vtpm\/templates$/);
    expect(body).toEqual({
      id: 't1',
      description: 'd',
      ek_algorithm: 'ECC',
      secure_boot_enabled: true,
    });
    expect(body).not.toHaveProperty('options');
  });

  it('posts only id and secure_boot_enabled when the options are bare', async () => {
    await service.createTemplate({ options: { id: 't2' } });

    const [path, body] = vi.mocked(mockClient.post).mock.calls[0]!;
    expect(path).toMatch(/\/v1\/vtpm\/templates$/);
    expect(body).toEqual({ id: 't2', secure_boot_enabled: false });
    expect(body).not.toHaveProperty('options');
  });
});

// The REST ListBundles handler pages by `limit` and `offset`; it has no
// `page` parameter.
describe('VTPMService.listBundles', () => {
  let mockClient: ApiClient;
  let service: VTPMService;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new VTPMService(mockClient);
    vi.mocked(mockClient.get).mockResolvedValue({ data: { bundles: [] } } as never);
  });

  it('sends limit and offset, never page', async () => {
    await service.listBundles({ options: { limit: 100, offset: 200 } });

    expect(mockClient.get).toHaveBeenCalledTimes(1);
    const [path] = vi.mocked(mockClient.get).mock.calls[0]!;
    expect(path).toContain('limit=100');
    expect(path).toContain('offset=200');
    expect(path).not.toContain('page=');
  });
});
