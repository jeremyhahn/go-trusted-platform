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
    ['getPowerStatus', (s) => s.getPowerStatus('r640-01'), '/v1/bmc/r640-01/power'],
    ['getBootDevice', (s) => s.getBootDevice('r640-01'), '/v1/bmc/r640-01/boot-device'],
    ['getVirtualMediaStatus', (s) => s.getVirtualMediaStatus('r640-01'), '/v1/bmc/r640-01/virtual-media'],
    ['getSensors', (s) => s.getSensors('r640-01'), '/v1/bmc/r640-01/sensors'],
    ['getSystemInfo', (s) => s.getSystemInfo('r640-01'), '/v1/bmc/r640-01/system-info'],
    ['getProvisionStatus', (s) => s.getProvisionStatus('r640-01'), '/v1/bmc/r640-01/provision'],
    ['getWebCertificate', (s) => s.getWebCertificate('r640-01'), '/v1/bmc/r640-01/cert'],
  ];

  it.each(gets)('%s GETs its route', async (_name, call, url) => {
    await call(service);
    expect(mockClient.get).toHaveBeenCalledTimes(1);
    expect(mockClient.get).toHaveBeenCalledWith(url);
    expect(mockClient.post).not.toHaveBeenCalled();
  });

  it('setBootDevice POSTs the device to boot-device', async () => {
    await service.setBootDevice('r640-01', { device: 'pxe', persistent: false });
    expect(mockClient.post).toHaveBeenCalledWith('/v1/bmc/r640-01/boot-device', { device: 'pxe', persistent: false });
  });

  it('mountISO POSTs the iso_url to virtual-media', async () => {
    await service.mountISO('r640-01', { iso_url: 'installer.iso' });
    expect(mockClient.post).toHaveBeenCalledWith('/v1/bmc/r640-01/virtual-media', { iso_url: 'installer.iso' });
  });

  it('getSensors returns the plain sensor array the server sends', async () => {
    const readings = [{ name: 'CPU1 Temp', value: 54, units: 'C', status: 'OK' }];
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: readings });
    const res = await service.getSensors('r640-01');
    expect(Array.isArray(res.data)).toBe(true);
    expect(res.data?.[0].value).toBe(54);
  });

  it('unmountISO DELETEs virtual-media', async () => {
    await service.unmountISO('r640-01');
    expect(mockClient.delete).toHaveBeenCalledWith('/v1/bmc/r640-01/virtual-media');
    expect(mockClient.post).not.toHaveBeenCalled();
  });

  it('provision POSTs to provision', async () => {
    await service.provision('r640-01');
    expect(mockClient.post).toHaveBeenCalledWith('/v1/bmc/r640-01/provision', {});
  });

  it('encodes the profile ID as one path segment', async () => {
    await service.getPowerStatus('rack 1/node');
    expect(mockClient.get).toHaveBeenCalledWith('/v1/bmc/rack%201%2Fnode/power');
  });

  it('propagates a transport error unchanged', async () => {
    const failure = new Error('404 Not Found: bmc: no profile r640-09');
    vi.mocked(mockClient.get).mockRejectedValue(failure);
    await expect(service.getSensors('r640-09')).rejects.toBe(failure);
  });
});
