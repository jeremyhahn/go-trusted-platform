/**
 * The verdicts feed route (#2038): AttestationService.pollDeviceVerdicts is
 * asserted against the path and query the server mounts
 * (pkg/webservice/v1/rest/attestation/verdicts_router.go).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AttestationService } from '../attestation-service.js';
import type { ApiClient } from '../../client/api-client.js';
import type { ApiResponse } from '../../types/api.js';
import type { PollDeviceVerdictsResponse } from '../../types/attestation.js';

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

describe('AttestationService device verdicts', () => {
  let service: AttestationService;
  let client: ApiClient;

  beforeEach(() => {
    client = createMockApiClient();
    service = new AttestationService(client);
  });

  it('polls /v1/attestation/verdicts with no query and keeps the uint64 device id a string', async () => {
    const page: PollDeviceVerdictsResponse = {
      cursor: 'c2',
      verdicts: [
        {
          eventId: 'e1',
          deviceId: '9007199254740993',
          tenantId: 't1',
          hostId: 'h1',
          serial: 's1',
          passed: false,
          cryptographic: true,
          reason: 'pcr mismatch',
        },
      ],
    };
    vi.mocked(client.get).mockResolvedValue({ success: true, data: page });
    const result = await service.pollDeviceVerdicts();
    expect(client.get).toHaveBeenCalledWith('/v1/attestation/verdicts');
    expect(result.data?.cursor).toBe('c2');
    expect(result.data?.verdicts[0]?.deviceId).toBe('9007199254740993');
  });

  it('encodes the cursor and floors wait_ms', async () => {
    vi.mocked(client.get).mockResolvedValue({ success: true, data: { cursor: '', verdicts: [] } });
    await service.pollDeviceVerdicts({ cursor: 'c 1/x', waitMs: 1500.7 });
    expect(client.get).toHaveBeenCalledWith('/v1/attestation/verdicts?cursor=c+1%2Fx&wait_ms=1500');
  });

  it('leaves out an empty cursor and a negative wait', async () => {
    vi.mocked(client.get).mockResolvedValue({ success: true, data: { cursor: '', verdicts: [] } });
    await service.pollDeviceVerdicts({ cursor: '', waitMs: -1 });
    expect(client.get).toHaveBeenCalledWith('/v1/attestation/verdicts');
  });

  it('leaves out a non-finite wait', async () => {
    vi.mocked(client.get).mockResolvedValue({ success: true, data: { cursor: '', verdicts: [] } });
    await service.pollDeviceVerdicts({ waitMs: Number.POSITIVE_INFINITY });
    expect(client.get).toHaveBeenCalledWith('/v1/attestation/verdicts');
  });

  it('passes a 403 for a session with no tenant through unchanged', async () => {
    const forbidden: ApiResponse<PollDeviceVerdictsResponse> = {
      success: false,
      error: { code: 'FORBIDDEN', message: 'no tenant', status: 403 },
    };
    vi.mocked(client.get).mockResolvedValue(forbidden);
    const result = await service.pollDeviceVerdicts();
    expect(result).toEqual(forbidden);
  });
});
