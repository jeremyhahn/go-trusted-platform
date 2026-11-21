/**
 * Unit tests for the BMC power and boot-device routes
 * (pkg/webservice/v1/bmc/handler.go, /api/v1/bmc/{profileID}/...).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { BMCService } from '../bmc-service.js';
import { BMCService as IndexedBMCService } from '../index.js';
import { BMCService as RootBMCService } from '../../index.js';
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

const noRetry = { retry: { enabled: false } };

describe('BMCService', () => {
  let service: BMCService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new BMCService(mockClient);
  });

  it('is exported from the services index and the package root', () => {
    expect(IndexedBMCService).toBe(BMCService);
    expect(RootBMCService).toBe(BMCService);
  });

  it('powerAction posts the action to /v1/bmc/{id}/power with retries off', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: { status: 'ok', action: 'cycle' } });

    const result = await service.powerAction(7, 'cycle');

    expect(result.success).toBe(true);
    expect(mockClient.post).toHaveBeenCalledTimes(1);
    expect(mockClient.post).toHaveBeenCalledWith('/v1/bmc/7/power', { action: 'cycle' }, noRetry);
  });

  it('powerOn, powerOff and powerReset post their action to the power route', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: { status: 'ok', action: 'x' } });

    await service.powerOn(7);
    await service.powerOff(7);
    await service.powerReset(7);

    const calls = vi.mocked(mockClient.post).mock.calls;
    expect(calls).toEqual([
      ['/v1/bmc/7/power', { action: 'on' }, noRetry],
      ['/v1/bmc/7/power', { action: 'off' }, noRetry],
      ['/v1/bmc/7/power', { action: 'reset' }, noRetry],
    ]);
  });

  it('getPowerStatus gets /v1/bmc/{id}/power', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: { state: 'On' } });

    await service.getPowerStatus(7);

    expect(mockClient.get).toHaveBeenCalledTimes(1);
    expect(vi.mocked(mockClient.get).mock.calls[0]?.[0]).toBe('/v1/bmc/7/power');
  });

  it('getBootDevice gets /v1/bmc/{id}/boot-device', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: { device: 'pxe' } });

    await service.getBootDevice(7);

    expect(mockClient.get).toHaveBeenCalledTimes(1);
    expect(vi.mocked(mockClient.get).mock.calls[0]?.[0]).toBe('/v1/bmc/7/boot-device');
  });

  it('setBootDevice posts the request to /v1/bmc/{id}/boot-device with retries off', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: { status: 'ok', device: 'pxe' } });

    await service.setBootDevice(7, { device: 'pxe', persistent: true });

    expect(mockClient.post).toHaveBeenCalledWith(
      '/v1/bmc/7/boot-device',
      { device: 'pxe', persistent: true },
      noRetry,
    );
  });
});
