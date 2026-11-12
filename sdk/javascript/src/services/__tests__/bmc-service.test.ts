/**
 * Unit tests for the BMC service routes (#1736): each method hits
 * `/v1/bmc/{profileID}/...` with the verb the server registers.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { BMCService } from '../bmc-service.js';
import type { ApiClient } from '../../client/api-client.js';

function createMockApiClient(): ApiClient {
  return {
    get: vi.fn().mockResolvedValue({ success: true, data: {} }),
    post: vi.fn().mockResolvedValue({ success: true, data: {} }),
    put: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn().mockResolvedValue({ success: true, data: {} }),
    head: vi.fn(),
    options: vi.fn(),
    fetch: vi.fn(),
    baseUrl: 'https://api.example.com',
  } as unknown as ApiClient;
}

describe('BMCService', () => {
  let service: BMCService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new BMCService(mockClient);
  });

  const gets: Array<[string, (s: BMCService) => Promise<unknown>, string]> = [
    ['getPowerStatus', (s) => s.getPowerStatus('1'), '/v1/bmc/1/power'],
    ['getBootDevice', (s) => s.getBootDevice('1'), '/v1/bmc/1/boot-device'],
    ['getVirtualMediaStatus', (s) => s.getVirtualMediaStatus('1'), '/v1/bmc/1/virtual-media'],
    ['getSensors', (s) => s.getSensors('1'), '/v1/bmc/1/sensors'],
    ['getSystemInfo', (s) => s.getSystemInfo('1'), '/v1/bmc/1/system-info'],
    ['getProvisionStatus', (s) => s.getProvisionStatus('1'), '/v1/bmc/1/provision'],
    ['getWebCertificate', (s) => s.getWebCertificate('1'), '/v1/bmc/1/cert'],
  ];

  it.each(gets)('%s GETs its route', async (_name, call, url) => {
    await call(service);
    expect(mockClient.get).toHaveBeenCalledTimes(1);
    expect(mockClient.get).toHaveBeenCalledWith(url);
    expect(mockClient.post).not.toHaveBeenCalled();
  });

  it('setBootDevice POSTs the device to boot-device', async () => {
    await service.setBootDevice('1', { device: 'pxe', persistent: false });
    expect(mockClient.post).toHaveBeenCalledWith('/v1/bmc/1/boot-device', { device: 'pxe', persistent: false });
  });

  it('mountISO POSTs the iso_url to virtual-media', async () => {
    await service.mountISO('1', { iso_url: 'installer.iso' });
    expect(mockClient.post).toHaveBeenCalledWith('/v1/bmc/1/virtual-media', { iso_url: 'installer.iso' });
  });

  it('getSensors returns the plain sensor array the server sends', async () => {
    const readings = [{ name: 'CPU1 Temp', value: 54, units: 'C', status: 'OK' }];
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: readings });
    const res = await service.getSensors('1');
    expect(Array.isArray(res.data)).toBe(true);
    expect(res.data?.[0].value).toBe(54);
  });

  it('unmountISO DELETEs virtual-media', async () => {
    await service.unmountISO('1');
    expect(mockClient.delete).toHaveBeenCalledWith('/v1/bmc/1/virtual-media');
    expect(mockClient.post).not.toHaveBeenCalled();
  });

  it('provision POSTs to provision', async () => {
    await service.provision('1');
    expect(mockClient.post).toHaveBeenCalledWith('/v1/bmc/1/provision', {});
  });

  it('encodes the profile ID as one path segment', async () => {
    await service.getPowerStatus('rack 1/node');
    expect(mockClient.get).toHaveBeenCalledWith('/v1/bmc/rack%201%2Fnode/power');
  });

  it('propagates a transport error unchanged', async () => {
    const failure = new Error('404 Not Found: bmc: no profile 9');
    vi.mocked(mockClient.get).mockRejectedValue(failure);
    await expect(service.getSensors('9')).rejects.toBe(failure);
  });
});
