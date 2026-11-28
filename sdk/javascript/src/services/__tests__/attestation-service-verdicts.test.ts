/**
 * The device verdicts poll (#2038): GET /v1/attestation/verdicts with an
 * optional cursor and a wait the server caps at 20000 ms
 * (pkg/webservice/v1/rest/attestation/verdicts_router.go).
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

describe('AttestationService device verdicts', () => {
  let service: AttestationService;
  let client: ApiClient;

  beforeEach(() => {
    client = createMockApiClient();
    service = new AttestationService(client);
  });

  it('polls /v1/attestation/verdicts with no cursor', async () => {
    vi.mocked(client.get).mockResolvedValue({ success: true, data: { cursor: '', verdicts: [] } });

    await service.pollDeviceVerdicts();

    expect(client.get).toHaveBeenCalledWith('/v1/attestation/verdicts');
  });

  it('sends the cursor and wait_ms', async () => {
    vi.mocked(client.get).mockResolvedValue({ success: true, data: { cursor: '', verdicts: [] } });

    await service.pollDeviceVerdicts({ cursor: 'c 1/2', waitMs: 5000 });

    expect(client.get).toHaveBeenCalledWith('/v1/attestation/verdicts?cursor=c+1%2F2&wait_ms=5000');
  });

  it('caps waitMs at the server limit of 20000', async () => {
    vi.mocked(client.get).mockResolvedValue({ success: true, data: { cursor: '', verdicts: [] } });

    await service.pollDeviceVerdicts({ waitMs: 60000 });
    expect(client.get).toHaveBeenLastCalledWith('/v1/attestation/verdicts?wait_ms=20000');

    await service.pollDeviceVerdicts({ waitMs: 0 });
    expect(client.get).toHaveBeenLastCalledWith('/v1/attestation/verdicts?wait_ms=0');
  });

  it('returns the cursor and the verdicts the server answers', async () => {
    vi.mocked(client.get).mockResolvedValue({
      success: true,
      data: {
        cursor: 'c2',
        verdicts: [
          {
            eventId: 'e1',
            recordedAt: '2026-11-01T00:00:00Z',
            deviceId: '18446744073709551615',
            tenantId: 't1',
            hostId: 'h1',
            serial: 'SN-1',
            passed: false,
            cryptographic: true,
            reason: 'pcr mismatch',
          },
        ],
      },
    });

    const result = await service.pollDeviceVerdicts();

    expect(result.data?.cursor).toBe('c2');
    expect(result.data?.verdicts[0]?.deviceId).toBe('18446744073709551615');
  });
});
