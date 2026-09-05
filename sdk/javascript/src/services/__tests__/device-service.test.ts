/**
 * Unit tests for DeviceService template routes.
 *
 * Template creation is the one device operation that does not live under
 * the service's plural base path: `POST /v1/devices/templates` is the
 * bootstrap seeder's route (docs/device/api.md §4.1), so createTemplate
 * must post to the singular `/v1/device/templates` while the other template
 * operations keep the plural aliases.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { DeviceService } from '../device-service.js';
import type { ApiClient } from '../../client/api-client.js';
import type { ApiResponse } from '../../types/api.js';
import type { DeviceTemplate, CreateDeviceTemplateRequest, DeviceProfile } from '../../types/device.js';

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

describe('DeviceService templates', () => {
  let service: DeviceService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new DeviceService(mockClient);
  });

  describe('createTemplate', () => {
    const request: CreateDeviceTemplateRequest = {
      name: 'gw-default',
      description: 'gateway default',
      role: 'GATEWAY',
      config: { domain: 'example.com' },
    };

    it('posts the unchanged request to the singular CRUD path, not the seeder route', async () => {
      const mockResponse: ApiResponse<DeviceTemplate> = {
        success: true,
        data: { id: '42', name: 'gw-default', role: 'GATEWAY' } as unknown as DeviceTemplate,
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.createTemplate(request);

      expect(result.success).toBe(true);
      expect(result.data?.name).toBe('gw-default');
      expect(mockClient.post).toHaveBeenCalledTimes(1);
      expect(mockClient.post).toHaveBeenCalledWith('/v1/device/templates', request);
      const [path] = vi.mocked(mockClient.post).mock.calls[0];
      expect(path).not.toBe('/v1/devices/templates');
    });

    it('propagates a transport error unchanged', async () => {
      const failure = new Error('400 Bad Request: device: unknown role "compute"');
      vi.mocked(mockClient.post).mockRejectedValue(failure);

      await expect(service.createTemplate(request)).rejects.toBe(failure);
      expect(mockClient.post).toHaveBeenCalledWith('/v1/device/templates', request);
    });
  });

  describe('plural aliases that are still CRUD routes', () => {
    it('lists templates from the plural path', async () => {
      vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: [] });

      await service.listTemplates();

      expect(mockClient.get).toHaveBeenCalledWith('/v1/devices/templates');
    });

    it('gets a template by id from the plural path', async () => {
      vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: {} });

      await service.getTemplate('42');

      expect(mockClient.get).toHaveBeenCalledWith('/v1/devices/templates/42');
    });
  });
});

/**
 * updateDevice is the route the WebUI's Enable / Disable Device control
 * will use once the device lifecycle transition flow lands (#250). Until
 * then the control is disabled rather than faked: the mutation behind it
 * used to `return { data: {}, error: undefined, success: true }` without
 * sending anything and then toast "Device disabled successfully" (#229).
 *
 * These tests hold updateDevice to the opposite standard — it must reach
 * the wire, and a server rejection must reach the caller. Both would fail
 * against a client-side fake.
 */
describe('DeviceService updateDevice', () => {
  let service: DeviceService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new DeviceService(mockClient);
  });

  const request = {
    device: { id: 1, serial: 'SN001' },
  } as unknown as Parameters<DeviceService['updateDevice']>[0];

  it('issues a real PUT to the device it was asked to update', async () => {
    vi.mocked(mockClient.put).mockResolvedValue({ success: true, data: {} });

    const result = await service.updateDevice(request);

    expect(mockClient.put).toHaveBeenCalledTimes(1);
    expect(mockClient.put).toHaveBeenCalledWith('/v1/devices/1', request);
    expect(result.success).toBe(true);
  });

  it('surfaces a server rejection instead of reporting success', async () => {
    const failure = new Error('403 Forbidden: device: state transition not permitted');
    vi.mocked(mockClient.put).mockRejectedValue(failure);

    await expect(service.updateDevice(request)).rejects.toBe(failure);
    expect(mockClient.put).toHaveBeenCalledWith('/v1/devices/1', request);
  });

  it('reports an unsuccessful response as unsuccessful', async () => {
    vi.mocked(mockClient.put).mockResolvedValue({
      success: false,
      error: { code: 'not_found', message: 'device 1 not found' },
    } as never);

    const result = await service.updateDevice(request);

    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
  });
});

/**
 * findConfigForDevice used to POST a JSON body to `/v1/devices/profiles/config`,
 * a route the server has never served. The capability is
 * `GET /api/v1/device/profiles/find-config`, which reads QUERY PARAMETERS whose
 * names differ from this request type's fields (#265).
 *
 * These assert the URL that goes OUT, not the object that goes in. The rename
 * from `macAddress` to `mac` is invisible to the type system: a version that
 * sent `?macAddress=...` type-checks, compiles, and returns 400 forever.
 */
/**
 * firstGetPath returns the URL of the first client.get call, failing loudly if
 * there wasn't one. Indexing mock.calls directly is `possibly undefined` under
 * strict mode, and a non-null assertion would hide a test that asserted
 * nothing because the call never happened.
 */
function firstGetPath(client: ApiClient): string {
  const first = vi.mocked(client.get).mock.calls[0];
  if (first === undefined) {
    throw new Error('expected client.get to have been called, but it was not');
  }
  // No cast: ApiClient.get is typed `(path: string, ...)`, so the recorded
  // first argument is already a string. Asserting it would be noise —
  // @typescript-eslint/no-unnecessary-type-assertion catches exactly this.
  return first[0];
}

describe('DeviceService findConfigForDevice', () => {
  let service: DeviceService;
  let mockClient: ApiClient;

  const found: ApiResponse<DeviceProfile | null> = {
    success: true,
    data: { id: 7, name: 'x10-worker' } as unknown as DeviceProfile,
  };

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new DeviceService(mockClient);
    vi.mocked(mockClient.get).mockResolvedValue(found);
  });

  it('GETs the singular find-config route, and never the old POST path', async () => {
    await service.findConfigForDevice({ ekSerial: 'EK123' });

    expect(mockClient.get).toHaveBeenCalledTimes(1);
    expect(mockClient.post).not.toHaveBeenCalled();

    const path = firstGetPath(mockClient);
    expect(path.startsWith('/v1/device/profiles/find-config')).toBe(true);
    // The controls: the two paths this must never go back to.
    expect(path).not.toContain('/v1/devices/');
    expect(path).not.toContain('/profiles/config');
  });

  it('sends ekSerial as ek_serial', async () => {
    await service.findConfigForDevice({ ekSerial: 'EK123' });

    const path = firstGetPath(mockClient);
    expect(path).toBe('/v1/device/profiles/find-config?ek_serial=EK123');
  });

  it('sends macAddress as mac — the rename no type checker catches', async () => {
    await service.findConfigForDevice({ macAddress: 'aa:bb:cc:dd:ee:ff' });

    const query = new URLSearchParams(firstGetPath(mockClient).split('?')[1] ?? '');
    expect(query.get('mac')).toBe('aa:bb:cc:dd:ee:ff');
    expect(query.get('macAddress')).toBeNull();
  });

  it('sends both identifiers when both are given', async () => {
    await service.findConfigForDevice({ ekSerial: 'EK123', macAddress: 'aa:bb:cc:dd:ee:ff' });

    const query = new URLSearchParams(firstGetPath(mockClient).split('?')[1] ?? '');
    expect(query.get('ek_serial')).toBe('EK123');
    expect(query.get('mac')).toBe('aa:bb:cc:dd:ee:ff');
  });

  it('omits empty identifiers rather than sending blank parameters', async () => {
    // The server 400s when BOTH are absent, and treats an empty string as
    // absent. Sending `?ek_serial=` would look like an identifier and is not.
    await service.findConfigForDevice({ ekSerial: '', macAddress: 'aa:bb:cc:dd:ee:ff' });

    const path = firstGetPath(mockClient);
    expect(path).toBe('/v1/device/profiles/find-config?mac=aa%3Abb%3Acc%3Add%3Aee%3Aff');
  });

  it('sends no query string at all when neither identifier is given', async () => {
    await service.findConfigForDevice({});

    const path = firstGetPath(mockClient);
    expect(path).toBe('/v1/device/profiles/find-config');
  });

  it('passes a null body through as null rather than coercing it', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: null });

    const result = await service.findConfigForDevice({ ekSerial: 'EK123' });

    expect(result.success).toBe(true);
    expect(result.data).toBeNull();
  });
});

describe('DeviceService getDeviceProfile', () => {
  let service: DeviceService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new DeviceService(mockClient);
    vi.mocked(mockClient.get).mockResolvedValue({
      success: true,
      data: { serialNumber: 'SRV-1', trustedNetwork: { vlan: 200, useDHCP: true } },
    });
  });

  it('GETs the singular mTLS route with no parameters — identity is the client certificate', async () => {
    const result = await service.getDeviceProfile();

    expect(mockClient.get).toHaveBeenCalledTimes(1);
    expect(mockClient.post).not.toHaveBeenCalled();
    expect(firstGetPath(mockClient)).toBe('/v1/device/profile');
    expect(result.data?.trustedNetwork.vlan).toBe(200);
  });

  it('never routes through the plural operator prefix', async () => {
    await service.getDeviceProfile();

    const path = firstGetPath(mockClient);
    // The controls: the operator surface this must not be confused with.
    expect(path).not.toContain('/v1/devices/');
    expect(path).not.toContain('/profiles');
  });
});

describe('DeviceService fulfillProvisioningSession', () => {
  let service: DeviceService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new DeviceService(mockClient);
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: undefined });
  });

  it('posts profile_id as a string under the wire name the server decodes', async () => {
    // Above 2^53: the only encoding that survives is a string, and the server
    // accepts it since #418. The old body carried `profileId: number`, a key the
    // server never read, so it fulfilled with id 0 and 404ed.
    await service.fulfillProvisioningSession({ sessionId: 'sess-1', profile_id: '9007199254740993' });

    expect(mockClient.post).toHaveBeenCalledTimes(1);
    const [path, body] = vi.mocked(mockClient.post).mock.calls[0] as [string, Record<string, unknown>];
    expect(path).toBe('/v1/provisioning/sessions/sess-1/fulfill');
    expect(body).toEqual({ session_id: 'sess-1', profile_id: '9007199254740993' });
    expect(body).not.toHaveProperty('profileId');
    expect(typeof body.profile_id).toBe('string');
  });

  it('encodes the session id in the path and never posts under the plural device prefix', async () => {
    await service.fulfillProvisioningSession({ sessionId: 'a/b c', profile_id: '7' });

    const [path] = vi.mocked(mockClient.post).mock.calls[0] as [string, unknown];
    expect(path).toBe('/v1/provisioning/sessions/a%2Fb%20c/fulfill');
    expect(path).not.toContain('/v1/devices/');
  });
});
