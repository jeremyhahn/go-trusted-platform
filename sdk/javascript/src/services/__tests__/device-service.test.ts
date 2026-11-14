/**
 * Unit tests for DeviceService routes.
 *
 * The server serves each device resource under exactly one name (#266,
 * docs/device/api.md §3.1): device RECORDS under the plural `/v1/devices`,
 * and profiles, templates and the machine-facing routes under the singular
 * `/v1/device`. The plural profile and template aliases are gone, so a client
 * that still calls one gets a 404. mux also answers a wrong verb with 404, not
 * 405, which makes it look exactly like a missing route. The route table below
 * therefore pins the verb as tightly as the path for every method (#228).
 *
 * Template creation must not use the plural `POST /v1/devices/templates`
 * either: that is the bootstrap seeder's route, and it takes a different body
 * (docs/device/api.md §4.1).
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
      role: 'gateway',
      config: { domain: 'example.com' },
    };

    it('posts the unchanged request to the singular CRUD path, not the seeder route', async () => {
      const mockResponse: ApiResponse<DeviceTemplate> = {
        success: true,
        data: { id: '42', name: 'gw-default', role: 'gateway' } as unknown as DeviceTemplate,
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.createTemplate(request);

      expect(result.success).toBe(true);
      expect(result.data?.name).toBe('gw-default');
      expect(mockClient.post).toHaveBeenCalledTimes(1);
      expect(mockClient.post).toHaveBeenCalledWith('/v1/device/templates', request);
      expect(vi.mocked(mockClient.post).mock.calls[0]?.[0]).not.toBe('/v1/devices/templates');
    });

    it('propagates a transport error unchanged', async () => {
      const failure = new Error('400 Bad Request: device: unknown role "compute"');
      vi.mocked(mockClient.post).mockRejectedValue(failure);

      await expect(service.createTemplate(request)).rejects.toBe(failure);
      expect(mockClient.post).toHaveBeenCalledWith('/v1/device/templates', request);
    });
  });

});

type Verb = 'get' | 'post' | 'put' | 'delete';

interface RouteCase {
  method: string;
  verb: Verb;
  path: string;
  call: (service: DeviceService) => Promise<unknown>;
}

/**
 * Every DeviceService method whose route sits under the device prefixes, with
 * the verb and path the server registers for it (pkg/webservice/v1/router/device.go).
 * Inputs are cast because the tests care about the URL that goes out, not the
 * shape of the object that goes in.
 */
const routes: RouteCase[] = [
  // Device records: plural.
  { method: 'createDevice', verb: 'post', path: '/v1/devices', call: (s) => s.createDevice({} as never) },
  { method: 'getDevice', verb: 'get', path: '/v1/devices/5', call: (s) => s.getDevice('5') },
  { method: 'deleteDevice', verb: 'delete', path: '/v1/devices/5', call: (s) => s.deleteDevice('5') },
  { method: 'listDevices', verb: 'get', path: '/v1/devices', call: (s) => s.listDevices() },
  { method: 'countDevices', verb: 'get', path: '/v1/devices/count', call: (s) => s.countDevices() },
  {
    method: 'findDeviceBySerial',
    verb: 'get',
    path: '/v1/devices/serial/SN%2F1',
    call: (s) => s.findDeviceBySerial('SN/1'),
  },
  // Operator activation: the singular JSON-body route, not the mTLS one.
  {
    method: 'activateDevice',
    verb: 'post',
    path: '/v1/device/activate-json',
    call: (s) => s.activateDevice({} as never),
  },
  // Profiles: singular.
  { method: 'createProfile', verb: 'post', path: '/v1/device/profiles', call: (s) => s.createProfile({ profile: {} }) },
  { method: 'getProfile', verb: 'get', path: '/v1/device/profiles/7', call: (s) => s.getProfile('7') },
  {
    method: 'updateProfile',
    verb: 'put',
    path: '/v1/device/profiles/7',
    call: (s) => s.updateProfile({ profile: { id: 7 } } as never),
  },
  { method: 'deleteProfile', verb: 'delete', path: '/v1/device/profiles/7', call: (s) => s.deleteProfile('7') },
  { method: 'listProfiles', verb: 'get', path: '/v1/device/profiles', call: (s) => s.listProfiles() },
  {
    method: 'findProfileByMACAddress',
    verb: 'get',
    path: '/v1/device/profiles/mac/aa%3Abb%3Acc%3Add%3Aee%3Aff',
    call: (s) => s.findProfileByMACAddress('aa:bb:cc:dd:ee:ff'),
  },
  {
    method: 'findProfileBySerial',
    verb: 'get',
    path: '/v1/device/profiles/serial/SN1',
    call: (s) => s.findProfileBySerial('SN1'),
  },
  {
    method: 'findMatchingProfile',
    verb: 'post',
    path: '/v1/device/profiles/match',
    call: (s) => s.findMatchingProfile({} as never),
  },
  { method: 'countProfiles', verb: 'get', path: '/v1/device/profiles/count', call: (s) => s.countProfiles() },
  {
    method: 'assignProfileToDevice',
    verb: 'post',
    path: '/v1/device/profiles/7/assign',
    call: (s) => s.assignProfileToDevice({ profileId: '7' } as never),
  },
  {
    method: 'unassignProfileFromDevice',
    verb: 'post',
    path: '/v1/device/profiles/7/unassign',
    call: (s) => s.unassignProfileFromDevice(7),
  },
  // Templates: singular.
  { method: 'createTemplate', verb: 'post', path: '/v1/device/templates', call: (s) => s.createTemplate({} as never) },
  { method: 'getTemplate', verb: 'get', path: '/v1/device/templates/42', call: (s) => s.getTemplate('42') },
  {
    method: 'updateTemplate',
    verb: 'put',
    path: '/v1/device/templates/42',
    call: (s) => s.updateTemplate({ id: 42 } as never),
  },
  { method: 'deleteTemplate', verb: 'delete', path: '/v1/device/templates/42', call: (s) => s.deleteTemplate('42') },
  { method: 'listTemplates', verb: 'get', path: '/v1/device/templates', call: (s) => s.listTemplates() },
  {
    method: 'createProfileFromTemplate',
    verb: 'post',
    path: '/v1/device/templates/42/create-profile',
    call: (s) => s.createProfileFromTemplate({ templateId: 42 } as never),
  },
];

const verbs: Verb[] = ['get', 'post', 'put', 'delete'];

describe('DeviceService route table', () => {
  let service: DeviceService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new DeviceService(mockClient);
  });

  it.each(routes)('$method sends $verb $path and no other request', async ({ verb, path, call }) => {
    vi.mocked(mockClient[verb]).mockResolvedValue({ success: true, data: {} });

    const result = await call(service);

    expect(result).toEqual({ success: true, data: {} });
    expect(mockClient[verb]).toHaveBeenCalledTimes(1);
    expect(vi.mocked(mockClient[verb]).mock.calls[0]?.[0]).toBe(path);
    for (const other of verbs.filter((v) => v !== verb)) {
      expect(mockClient[other]).not.toHaveBeenCalled();
    }
  });

  it.each(routes)('$method propagates a transport error unchanged', async ({ verb, path, call }) => {
    const failure = new Error('404 Not Found');
    vi.mocked(mockClient[verb]).mockRejectedValue(failure);

    await expect(call(service)).rejects.toBe(failure);
    expect(vi.mocked(mockClient[verb]).mock.calls[0]?.[0]).toBe(path);
  });

  it('never calls a removed plural profile or template alias', async () => {
    for (const verb of verbs) {
      vi.mocked(mockClient[verb]).mockResolvedValue({ success: true, data: {} });
    }

    for (const route of routes) {
      await route.call(service);
    }

    const sent = verbs.flatMap((verb) => vi.mocked(mockClient[verb]).mock.calls.map((c) => String(c[0])));
    expect(sent).toHaveLength(routes.length);
    for (const path of sent) {
      expect(path.startsWith('/v1/devices/profiles')).toBe(false);
      expect(path.startsWith('/v1/devices/templates')).toBe(false);
    }
  });

  it('passes list pagination through as query parameters on the singular prefix', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: [] });

    await service.listProfiles({ page: 2, pageSize: 10 } as never);
    await service.listTemplates({ page: 3, pageSize: 5 } as never);

    expect(vi.mocked(mockClient.get).mock.calls.map((c) => c[0])).toEqual([
      '/v1/device/profiles?page=2&limit=10',
      '/v1/device/templates?page=3&limit=5',
    ]);
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
      data: { serialNumber: 'SRV-1', admittedNetwork: { vlan: 200, useDHCP: true } },
    });
  });

  it('GETs the singular mTLS route with no parameters — identity is the client certificate', async () => {
    const result = await service.getDeviceProfile();

    expect(mockClient.get).toHaveBeenCalledTimes(1);
    expect(mockClient.post).not.toHaveBeenCalled();
    expect(firstGetPath(mockClient)).toBe('/v1/device/profile');
    expect(result.data?.admittedNetwork.vlan).toBe(200);
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
    await service.fulfillProvisioningSession({ session_id: 'sess-1', profile_id: '9007199254740993' });

    expect(mockClient.post).toHaveBeenCalledTimes(1);
    const [path, body] = vi.mocked(mockClient.post).mock.calls[0] as [string, Record<string, unknown>];
    expect(path).toBe('/v1/provisioning/sessions/sess-1/fulfill');
    expect(body).toEqual({ session_id: 'sess-1', profile_id: '9007199254740993' });
    expect(body).not.toHaveProperty('profileId');
    expect(typeof body.profile_id).toBe('string');
  });

  it('encodes the session id in the path and never posts under the plural device prefix', async () => {
    await service.fulfillProvisioningSession({ session_id: 'a/b c', profile_id: '7' });

    const [path] = vi.mocked(mockClient.post).mock.calls[0] as [string, unknown];
    expect(path).toBe('/v1/provisioning/sessions/a%2Fb%20c/fulfill');
    expect(path).not.toContain('/v1/devices/');
  });
});

describe('DeviceService assignProfileToDevice and updateTemplate wire bodies', () => {
  let service: DeviceService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new DeviceService(mockClient);
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: undefined });
    vi.mocked(mockClient.put).mockResolvedValue({ success: true, data: undefined });
  });

  it('assign keeps a large profile id exact in the path and posts snake_case identity only', async () => {
    await service.assignProfileToDevice({ profileId: '9007199254740993', ekSerial: 'EK1', macAddress: '' });

    expect(mockClient.post).toHaveBeenCalledTimes(1);
    const [path, body] = vi.mocked(mockClient.post).mock.calls[0] as [string, Record<string, unknown>];
    expect(path).toMatch(/\/profiles\/9007199254740993\/assign$/);
    expect(body).toEqual({ ek_serial: 'EK1' });
    expect(body).not.toHaveProperty('profile_id');
    expect(body).not.toHaveProperty('profileId');
    expect(body).not.toHaveProperty('ekSerial');
    expect(body).not.toHaveProperty('mac_address');
  });

  it('assign posts mac_address when a MAC is given', async () => {
    await service.assignProfileToDevice({ profileId: '7', macAddress: 'aa:bb:cc:dd:ee:ff' });

    const [, body] = vi.mocked(mockClient.post).mock.calls[0] as [string, Record<string, unknown>];
    expect(body).toEqual({ mac_address: 'aa:bb:cc:dd:ee:ff' });
  });

  it('updateTemplate carries tenant_id, config and match_rules in the flat PUT body', async () => {
    const config = 'Y2Zn' as unknown as Record<string, unknown>;
    await service.updateTemplate({
      id: '1',
      name: 'n',
      tenant_id: 't',
      config,
      match_rules: { mac_prefix: 'aa:bb' },
    });

    expect(mockClient.put).toHaveBeenCalledTimes(1);
    const [, body] = vi.mocked(mockClient.put).mock.calls[0] as [string, Record<string, unknown>];
    expect(body).toMatchObject({ tenant_id: 't', config: 'Y2Zn', match_rules: { mac_prefix: 'aa:bb' } });
    expect(body).not.toHaveProperty('matchRules');
  });
});

describe('DeviceService wire bodies for the lookup page (#1756)', () => {
  let service: DeviceService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new DeviceService(mockClient);
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: undefined });
    vi.mocked(mockClient.put).mockResolvedValue({ success: true, data: undefined });
  });

  it('updateProfile PUTs the flat profile, not the request envelope', async () => {
    await service.updateProfile({ profile: { id: '9007199254740993', name: 'n', zone: 'z' } as never });

    const [path, body] = vi.mocked(mockClient.put).mock.calls[0] as [string, Record<string, unknown>];
    expect(path.endsWith('/profiles/9007199254740993')).toBe(true);
    expect(body).toHaveProperty('name', 'n');
    expect(body).toHaveProperty('zone', 'z');
    expect(body).not.toHaveProperty('profile');
  });

  it('findMatchingProfile sends mac_address and omits empty criteria', async () => {
    await service.findMatchingProfile({ macAddress: 'aa:bb', model: '' });

    const [, body] = vi.mocked(mockClient.post).mock.calls[0] as [string, Record<string, unknown>];
    expect(body).toEqual({ mac_address: 'aa:bb' });
  });

  it('activateDevice sends serial and mac_address', async () => {
    await service.activateDevice({ serial: 'S1', macAddress: 'aa:bb' });

    const [, body] = vi.mocked(mockClient.post).mock.calls[0] as [string, Record<string, unknown>];
    expect(body).toEqual({ serial: 'S1', mac_address: 'aa:bb' });
  });
});
