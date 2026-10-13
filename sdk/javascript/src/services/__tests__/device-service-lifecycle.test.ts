/**
 * DeviceService.disableDevice / enableDevice post to the dedicated
 * transition routes, never the generic PUT, and hand the server's verdict
 * back unchanged (docs/device/api.md, #250).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { DeviceService } from '../device-service.js';
import type { ApiClient } from '../../client/api-client.js';
import type { ApiResponse } from '../../types/api.js';
import type { DeviceLifecycleResponse } from '../../types/device.js';

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

describe('DeviceService lifecycle transitions', () => {
  let service: DeviceService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new DeviceService(mockClient);
  });

  it('disables through POST /v1/devices/{id}/disable with the reason', async () => {
    const reply: ApiResponse<DeviceLifecycleResponse> = {
      success: true,
      data: {
        device_id: '9007199254740993',
        state: 'suspended',
        previous_state: 'attested',
        state_reason: 'operator: rma pending',
        reattestation_requested: false,
      },
    };
    vi.mocked(mockClient.post).mockResolvedValue(reply);

    const result = await service.disableDevice('9007199254740993', { reason: 'rma pending' });

    expect(mockClient.post).toHaveBeenCalledWith('/v1/devices/9007199254740993/disable', {
      reason: 'rma pending',
    });
    expect(mockClient.put).not.toHaveBeenCalled();
    expect(result.data?.state).toBe('suspended');
  });

  it('disables without a reason', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({ success: true });

    await service.disableDevice(7);

    expect(mockClient.post).toHaveBeenCalledWith('/v1/devices/7/disable', {});
  });

  it('enables through POST /v1/devices/{id}/enable', async () => {
    const reply: ApiResponse<DeviceLifecycleResponse> = {
      success: true,
      data: {
        device_id: '7',
        state: 'quarantined',
        previous_state: 'suspended',
        reattestation_requested: true,
      },
    };
    vi.mocked(mockClient.post).mockResolvedValue(reply);

    const result = await service.enableDevice(7);

    expect(mockClient.post).toHaveBeenCalledWith('/v1/devices/7/enable', {});
    expect(mockClient.put).not.toHaveBeenCalled();
    expect(result.data?.reattestation_requested).toBe(true);
  });

  it('hands a server refusal back to the caller', async () => {
    const refusal: ApiResponse<DeviceLifecycleResponse> = {
      success: false,
      error: { code: 'BAD_REQUEST', message: 'device 7 has no network port on record' },
    };
    vi.mocked(mockClient.post).mockResolvedValue(refusal);

    const result = await service.disableDevice(7);

    expect(result.success).toBe(false);
    expect(result.error?.message).toContain('no network port');
  });

  it('surfaces a transport failure', async () => {
    vi.mocked(mockClient.post).mockRejectedValue(new Error('connection refused'));
    await expect(service.enableDevice(7)).rejects.toThrow('connection refused');
  });
});
