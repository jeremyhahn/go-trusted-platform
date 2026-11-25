/**
 * Unit tests for the two PXE device routes whose client and server had drifted.
 *
 * `pkg/webservice/v1/rest/pxe/router.go` serves `GET /pxe/devices/mac/{mac}`
 * and `PUT /pxe/devices/{id}/state`; the client used to request
 * `/devices/by-mac/{mac}` and to POST the state update, so both calls 404'd.
 * A wrong verb and a missing route are indistinguishable from the outside —
 * mux answers a POST to a PUT-only path with 404, not 405 — so these tests
 * pin the verb as tightly as the path (docs/ipxe/api.md §Device routes).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { PXEService } from '../pxe-service.js';
import type { ApiClient } from '../../client/api-client.js';
import type { UpdatePXEStateRequest } from '../../types/pxe.js';
import { InvalidEnumValueError } from '../../errors/index.js';

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

describe('PXEService device routes', () => {
  let service: PXEService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new PXEService(mockClient);
  });

  describe('getDeviceByMAC', () => {
    it('gets the served /devices/mac/{mac} path, not the /devices/by-mac alias', async () => {
      vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: { device: { id: '7' } } });

      const result = await service.getDeviceByMAC('aa:bb:cc:dd:ee:ff');

      expect(result.success).toBe(true);
      expect(mockClient.get).toHaveBeenCalledTimes(1);
      expect(mockClient.get).toHaveBeenCalledWith('/v1/pxe/devices/mac/aa%3Abb%3Acc%3Add%3Aee%3Aff');
      expect(vi.mocked(mockClient.get).mock.calls[0]?.[0]).not.toContain('/by-mac/');
    });

    it('propagates a transport error unchanged', async () => {
      const failure = new Error('404 Not Found: pxe: no device with that MAC');
      vi.mocked(mockClient.get).mockRejectedValue(failure);

      await expect(service.getDeviceByMAC('aa:bb:cc:dd:ee:ff')).rejects.toBe(failure);
      expect(mockClient.get).toHaveBeenCalledWith('/v1/pxe/devices/mac/aa%3Abb%3Acc%3Add%3Aee%3Aff');
    });
  });

  describe('updateState', () => {
    const request: UpdatePXEStateRequest = {
      deviceId: 'node-3',
      state: 'INSTALLING',
      reason: 'operator retry',
    };

    it('PUTs the state update — the server registers PUT, and a POST would 404', async () => {
      vi.mocked(mockClient.put).mockResolvedValue({ success: true, data: { device: { id: 'node-3' } } });

      const result = await service.updateState(request);

      expect(result.success).toBe(true);
      expect(mockClient.put).toHaveBeenCalledTimes(1);
      expect(mockClient.put).toHaveBeenCalledWith('/v1/pxe/devices/node-3/state', {
        state: 'PROVISIONING_STATE_INSTALLING',
        reason: 'operator retry',
      });
      expect(mockClient.post).not.toHaveBeenCalled();
    });

    it('propagates a transport error unchanged', async () => {
      const failure = new Error('409 Conflict: pxe: illegal state transition');
      vi.mocked(mockClient.put).mockRejectedValue(failure);

      await expect(service.updateState(request)).rejects.toBe(failure);
      expect(mockClient.post).not.toHaveBeenCalled();
    });

    it('passes a protobuf enum name through unchanged', async () => {
      vi.mocked(mockClient.put).mockResolvedValue({ success: true, data: { device: { id: 'node-3' } } });

      await service.updateState({
        deviceId: 'node-3',
        state: 'PROVISIONING_STATE_FAILED' as UpdatePXEStateRequest['state'],
        reason: 'disk',
      });

      expect(mockClient.put).toHaveBeenCalledWith('/v1/pxe/devices/node-3/state', {
        state: 'PROVISIONING_STATE_FAILED',
        reason: 'disk',
      });
    });

    it('refuses a state that is not a provisioning state', async () => {
      await expect(
        service.updateState({
          deviceId: 'node-3',
          state: 'BOGUS' as UpdatePXEStateRequest['state'],
          reason: 'disk',
        }),
      ).rejects.toBeInstanceOf(InvalidEnumValueError);
      expect(mockClient.put).not.toHaveBeenCalled();
    });
  });

  // pkg/webservice/v1/rest/pxe/filter.go:27-33 reads state, mac_address,
  // vlan, limit and offset; macAddress and page are ignored, so a filtered
  // or second-page list would silently come back unfiltered from the start.
  describe('listDevices', () => {
    function sentUrl(): { path: string; params: URLSearchParams } {
      const url = String(vi.mocked(mockClient.get).mock.calls[0]?.[0]);
      return { path: url.split('?')[0] ?? '', params: new URLSearchParams(url.split('?')[1] ?? '') };
    }

    beforeEach(() => {
      vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: { devices: [] } });
    });

    it('sends the filter under the names the server reads', async () => {
      await service.listDevices({
        filter: { state: 'QUARANTINED', macAddress: '02:00:00', vlan: 20, limit: 10, offset: 20 },
      });

      expect(mockClient.get).toHaveBeenCalledTimes(1);
      const { path, params } = sentUrl();
      expect(path).toBe('/v1/pxe/devices');
      expect(params.get('state')).toBe('QUARANTINED');
      expect(params.get('mac_address')).toBe('02:00:00');
      expect(params.get('vlan')).toBe('20');
      expect(params.get('limit')).toBe('10');
      expect(params.get('offset')).toBe('20');
      expect(params.has('macAddress')).toBe(false);
      expect(params.has('page')).toBe(false);
    });

    it('sends an offset without a limit', async () => {
      await service.listDevices({ filter: { offset: 5 } });

      const { params } = sentUrl();
      expect(params.get('offset')).toBe('5');
      expect(params.has('page')).toBe(false);
    });

    it('sends no query without a filter', async () => {
      await service.listDevices();

      expect(mockClient.get).toHaveBeenCalledWith('/v1/pxe/devices');
    });
  });
});
