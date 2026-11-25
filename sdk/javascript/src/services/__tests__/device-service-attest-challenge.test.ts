/**
 * DeviceService attestation challenge: issueAttestationChallenge reaches the
 * served POST /api/v1/devices/{id}/attest/challenge, and attestDevice sends the
 * challenge_id with the quote evidence (#2048).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { DeviceService } from '../device-service.js';
import type { ApiClient } from '../../client/api-client.js';
import type { ApiResponse } from '../../types/api.js';
import type { DeviceAttestChallengeResponse } from '../../types/device.js';

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

describe('DeviceService attestation challenge', () => {
  let service: DeviceService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new DeviceService(mockClient);
  });

  it('issues a challenge on POST /v1/devices/{id}/attest/challenge', async () => {
    const response: ApiResponse<DeviceAttestChallengeResponse> = {
      success: true,
      data: {
        challenge_id: 'ch-1',
        nonce: 'bm9uY2U=',
        expires_at: '2026-11-23T12:05:00Z',
      },
    };
    vi.mocked(mockClient.post).mockResolvedValue(response);

    const result = await service.issueAttestationChallenge('9007199254740993');

    expect(mockClient.post).toHaveBeenCalledWith(
      '/v1/devices/9007199254740993/attest/challenge',
      {}
    );
    expect(result.data?.challenge_id).toBe('ch-1');
  });

  it('hands a refused challenge back unchanged', async () => {
    const refused = {
      success: false,
      error: { status: 409, message: 'attestation challenge is unknown or already used' },
    } as ApiResponse<DeviceAttestChallengeResponse>;
    vi.mocked(mockClient.post).mockResolvedValue(refused);

    const result = await service.issueAttestationChallenge(7);

    expect(result).toBe(refused);
  });

  it('attestDevice sends the challenge_id with the evidence', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({ success: true });

    await service.attestDevice(7, { evidence: 'ZQ==', challenge_id: 'ch-1' });

    expect(mockClient.post).toHaveBeenCalledWith(
      '/v1/devices/7/attest',
      { evidence: 'ZQ==', challenge_id: 'ch-1' },
      { retry: { enabled: false } }
    );
  });

  it('attestDevice never retries, with or without a challenge', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({ success: true });

    await service.attestDevice(7, { evidence: 'ZQ==' });

    expect(vi.mocked(mockClient.post).mock.calls[0]?.[2]).toEqual({ retry: { enabled: false } });
  });
});
