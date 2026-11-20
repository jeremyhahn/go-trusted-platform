/**
 * PollDeviceVerdicts over REST (#2038): GET /v1/attestation/verdicts with the
 * cursor and wait_ms query the server's VerdictsRouter reads.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AttestationService } from '../attestation-service.js';
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

describe('AttestationService.pollDeviceVerdicts', () => {
  let client: ApiClient;
  let service: AttestationService;

  beforeEach(() => {
    client = createMockApiClient();
    service = new AttestationService(client);
    vi.mocked(client.get).mockResolvedValue({ success: true, data: { cursor: 'c2', verdicts: [] } });
  });

  it('polls the verdicts route with no query on the first poll', async () => {
    const response = await service.pollDeviceVerdicts();
    expect(client.get).toHaveBeenCalledWith('/v1/attestation/verdicts');
    expect(response.data?.cursor).toBe('c2');
  });

  it('carries the cursor and wait_ms the server reads', async () => {
    await service.pollDeviceVerdicts({ cursor: 'c 1', waitMs: 500 });
    expect(client.get).toHaveBeenCalledWith('/v1/attestation/verdicts?cursor=c+1&wait_ms=500');
  });
});
