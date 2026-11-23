/**
 * KMSService.rewrap (#2057): asserted against the route the server mounts
 * (pkg/webservice/v1/rest/kms/router.go: POST /api/v1/kms/rewrap) and the
 * body it decodes (pkg/webservice/v1/rest/kms/handlers_rewrap.go:
 * { source_key_id, ciphertext, source_context?, source_nonce? }), with the
 * key id in the body, not the path.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { KMSService } from '../kms-service.js';
import type { ApiClient } from '../../client/api-client.js';
import type { ApiResponse } from '../../types/api.js';
import type { RewrapResponse } from '../../types/kms.js';

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

describe('KMSService rewrap route (#2057)', () => {
  let client: ApiClient;
  let service: KMSService;

  beforeEach(() => {
    client = createMockApiClient();
    service = new KMSService(client);
  });

  it('rewrap posts /v1/kms/rewrap with { source_key_id, ciphertext } only', async () => {
    vi.mocked(client.post).mockResolvedValue({ success: true, data: {} } as ApiResponse<RewrapResponse>);

    await service.rewrap({ sourceKeyId: 'k 1', ciphertext: 'Y3Q=' });

    expect(client.post).toHaveBeenCalledTimes(1);
    const url = vi.mocked(client.post).mock.calls[0]?.[0];
    const body = vi.mocked(client.post).mock.calls[0]?.[1];
    expect(url).toBe('/v1/kms/rewrap');
    expect(body).toEqual({ source_key_id: 'k 1', ciphertext: 'Y3Q=' });
  });

  it('rewrap sends source_context and source_nonce when given', async () => {
    vi.mocked(client.post).mockResolvedValue({ success: true, data: {} } as ApiResponse<RewrapResponse>);

    await service.rewrap({
      sourceKeyId: 'k 1',
      ciphertext: 'Y3Q=',
      sourceContext: 'Y3R4',
      sourceNonce: 'bm9uY2U=',
    });

    expect(client.post).toHaveBeenCalledTimes(1);
    const body = vi.mocked(client.post).mock.calls[0]?.[1];
    expect(body).toEqual({
      source_key_id: 'k 1',
      ciphertext: 'Y3Q=',
      source_context: 'Y3R4',
      source_nonce: 'bm9uY2U=',
    });
  });

  it('rewrap returns the served response unchanged', async () => {
    const served = {
      success: true,
      data: {
        source_key_id: 'k 1',
        destination_key_id: 'k 1',
        source_key_version: 1,
        dest_key_version: 2,
        ciphertext: 'bmV3',
        nonce: 'bg==',
      },
    } as ApiResponse<RewrapResponse>;
    vi.mocked(client.post).mockResolvedValue(served);

    const result = await service.rewrap({ sourceKeyId: 'k 1', ciphertext: 'Y3Q=' });

    expect(result).toEqual(served);
  });
});
