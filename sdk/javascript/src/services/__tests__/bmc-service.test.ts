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

  it('getVirtualMediaStatus gets /v1/bmc/{id}/virtual-media', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: { mounted: false } });

    await service.getVirtualMediaStatus(7);

    expect(mockClient.get).toHaveBeenCalledTimes(1);
    expect(vi.mocked(mockClient.get).mock.calls[0]?.[0]).toBe('/v1/bmc/7/virtual-media');
  });

  it('mountISO posts the ISO URL to /v1/bmc/{id}/virtual-media with retries off', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({
      success: true,
      data: { status: 'mounted', iso_url: 'https://example.com/a.iso' },
    });

    await service.mountISO(7, 'https://example.com/a.iso');

    expect(mockClient.post).toHaveBeenCalledTimes(1);
    expect(mockClient.post).toHaveBeenCalledWith(
      '/v1/bmc/7/virtual-media',
      { iso_url: 'https://example.com/a.iso' },
      noRetry,
    );
  });

  it('unmountISO deletes /v1/bmc/{id}/virtual-media with retries off', async () => {
    vi.mocked(mockClient.delete).mockResolvedValue({ success: true, data: { status: 'unmounted' } });

    await service.unmountISO(7);

    expect(mockClient.delete).toHaveBeenCalledTimes(1);
    expect(mockClient.delete).toHaveBeenCalledWith('/v1/bmc/7/virtual-media', noRetry);
  });

  it('getSensors, getSystemInfo, getWebCertificate and getProvisionStatus get their routes', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: {} });

    await service.getSensors(7);
    await service.getSystemInfo(7);
    await service.getWebCertificate(7);
    await service.getProvisionStatus(7);

    const paths = vi.mocked(mockClient.get).mock.calls.map((call) => call[0]);
    expect(paths).toEqual([
      '/v1/bmc/7/sensors',
      '/v1/bmc/7/system-info',
      '/v1/bmc/7/cert',
      '/v1/bmc/7/provision',
    ]);
  });

  it('provision posts the request, or an empty body, to /v1/bmc/{id}/provision with retries off', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: { status: 'pending' } });

    await service.provision(7, { iso_url: 'https://example.com/a.iso' });
    await service.provision(7);

    const calls = vi.mocked(mockClient.post).mock.calls;
    expect(calls).toEqual([
      ['/v1/bmc/7/provision', { iso_url: 'https://example.com/a.iso' }, noRetry],
      ['/v1/bmc/7/provision', {}, noRetry],
    ]);
  });

  it('escapes a string profile id in the path', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: { status: 'ok', action: 'on' } });

    await service.powerOn('a/b');

    expect(mockClient.post).toHaveBeenCalledWith('/v1/bmc/a%2Fb/power', { action: 'on' }, noRetry);
  });
});
