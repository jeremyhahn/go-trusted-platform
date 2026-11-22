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
    const payload = {
      id: 'bundle-1',
      mode: 'template',
      manifest: { version: '1', id: 'bundle-1', mode: 'template', ek_algorithm: 'RSA', ek_handle: 1, secure_boot_enabled: false },
      tpm_state: { state_dir: 's', permall_file: 'p', volatile_file: 'v' },
      ovmf_state: { nvram_file: 'n' },
      created_at: 't',
    };
    vi.mocked(mockClient.post).mockResolvedValue({ data: payload } as never);
    const archive = new Blob([new Uint8Array([0x1f, 0x8b, 0x08, 0x00])], {
      type: 'application/gzip',
    });

    const result = await service.importBundle(archive);

    expect(mockClient.post).toHaveBeenCalledTimes(1);
    const path = vi.mocked(mockClient.post).mock.calls[0]?.[0];
    const body = vi.mocked(mockClient.post).mock.calls[0]?.[1];
    expect(path).toMatch(/\/v1\/vtpm\/bundles\/import$/);
    expect(body).toBe(archive);
    expect(result.data?.id).toBe('bundle-1');
    expect(result.data?.mode).toBe('TEMPLATE');
    expect(result.data?.tpmState.stateDir).toBe('s');
  });
});
