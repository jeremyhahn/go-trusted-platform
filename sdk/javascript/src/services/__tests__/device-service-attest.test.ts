/**
 * DeviceService.attestDevice posts quote evidence to the one verifier route
 * and hands the per-check result back unchanged (docs/device/api.md §4.4).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { DeviceService } from '../device-service.js';
import type { ApiClient } from '../../client/api-client.js';
import type { ApiResponse } from '../../types/api.js';
import type { DeviceAttestResponse } from '../../types/device.js';

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

describe('DeviceService.attestDevice', () => {
  let service: DeviceService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new DeviceService(mockClient);
  });

  it('posts the evidence to /v1/devices/{id}/attest', async () => {
    const verdict: DeviceAttestResponse = {
      device_id: '9007199254740993',
      verified: false,
      signature_valid: true,
      nonce_valid: true,
      pcrs_valid: false,
      attestation_status: 'registered',
      attested_at: '2026-09-01T12:00:00Z',
      ak_certificate_verified: false,
      pcr_baseline_source: 'tofu',
      pcr_baseline_recorded_at: '2026-08-30T00:00:00Z',
      pcr_baseline_captured: false,
    };
    const response: ApiResponse<DeviceAttestResponse> = { success: true, data: verdict };
    vi.mocked(mockClient.post).mockResolvedValue(response);

    const result = await service.attestDevice('9007199254740993', { evidence: 'ZXZpZGVuY2U=' });

    expect(mockClient.post).toHaveBeenCalledWith('/v1/devices/9007199254740993/attest', {
      evidence: 'ZXZpZGVuY2U=',
    });
    expect(result.data?.ak_certificate_verified).toBe(false);
    expect(result.data?.pcr_baseline_source).toBe('tofu');
  });

  it('surfaces a transport failure rather than inventing a verdict', async () => {
    vi.mocked(mockClient.post).mockRejectedValue(new Error('connection refused'));
    await expect(service.attestDevice(1, { evidence: '' })).rejects.toThrow('connection refused');
  });
});
