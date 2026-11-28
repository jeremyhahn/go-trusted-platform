/**
 * Unit tests for the switch port routes (docs/switch/api.md):
 * GET /v1/switches/{switch}/ports, GET /v1/switches/{switch}/ports/{port},
 * POST .../vlan, .../enable and .../disable.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { SwitchService } from '../switch-service.js';
import { SwitchService as IndexedSwitchService } from '../index.js';
import { SwitchService as RootSwitchService } from '../../index.js';
import type {
  SwitchPortStatus,
  SwitchPortActionResponse,
  SetSwitchPortVLANResponse,
} from '../../index.js';
import { PlatformClient } from '../../client/platform-client.js';
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

describe('SwitchService', () => {
  let service: SwitchService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new SwitchService(mockClient);
  });

  it('is exported from the services index', () => {
    expect(IndexedSwitchService).toBe(SwitchService);
  });

  it('is exported from the package root with its response types', () => {
    expect(RootSwitchService).toBe(SwitchService);
    const rooted = new RootSwitchService(mockClient);
    expect(rooted).toBeInstanceOf(SwitchService);
    const status: SwitchPortStatus | undefined = undefined;
    const action: SwitchPortActionResponse | undefined = undefined;
    const vlan: SetSwitchPortVLANResponse | undefined = undefined;
    expect([status, action, vlan]).toEqual([undefined, undefined, undefined]);
  });

  it('listPorts gets /v1/switches/{switch}/ports', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: [] });

    const result = await service.listPorts('core-1');

    expect(result.success).toBe(true);
    expect(mockClient.get).toHaveBeenCalledTimes(1);
    expect(mockClient.get).toHaveBeenCalledWith('/v1/switches/core-1/ports');
  });

  it('getPortStatus encodes the slash in the port name', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: { port: 'Eth1/1' } });

    await service.getPortStatus('core-1', 'Eth1/1');

    expect(mockClient.get).toHaveBeenCalledWith('/v1/switches/core-1/ports/Eth1%2F1');
  });

  it('setPortVLAN posts vlan_id', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: { status: 'ok' } });

    await service.setPortVLAN('core-1', 'Eth1/1', 20);

    expect(mockClient.post).toHaveBeenCalledTimes(1);
    expect(mockClient.post).toHaveBeenCalledWith('/v1/switches/core-1/ports/Eth1%2F1/vlan', {
      vlan_id: 20,
    });
  });

  it('setPortVLAN refuses a VLAN outside 1..4094 without a request', async () => {
    for (const vlan of [0, 4095, 1.5]) {
      await expect(service.setPortVLAN('core-1', 'Eth1/1', vlan)).rejects.toThrow(RangeError);
    }
    expect(mockClient.post).not.toHaveBeenCalled();
  });

  it('enablePort and disablePort post with an empty body', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: { status: 'ok' } });

    await service.enablePort('core-1', 'Eth1/1');
    await service.disablePort('core-1', 'Eth1/1');

    expect(mockClient.post).toHaveBeenNthCalledWith(1, '/v1/switches/core-1/ports/Eth1%2F1/enable', {});
    expect(mockClient.post).toHaveBeenNthCalledWith(2, '/v1/switches/core-1/ports/Eth1%2F1/disable', {});
  });

  it('encodes the switch name too', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: [] });

    await service.listPorts('rack a/1');

    expect(mockClient.get).toHaveBeenCalledWith('/v1/switches/rack%20a%2F1/ports');
  });

  it('PlatformClient exposes the service as client.switches', () => {
    const client = new PlatformClient({
      baseUrl: 'https://api.example.com',
    });

    expect(client.switches).toBeInstanceOf(SwitchService);
  });
});
