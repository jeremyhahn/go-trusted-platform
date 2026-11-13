/**
 * Unit tests for the switch port routes (docs/switch/api.md §3, §5.1).
 *
 * Port names contain slashes, so the tests pin the escaped path as well as
 * the verb and the body.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { SwitchService } from '../switch-service.js';
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

  it('listPorts GETs /v1/switches/{switch}/ports', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: [] });

    const result = await service.listPorts('core-1');

    expect(result.success).toBe(true);
    expect(mockClient.get).toHaveBeenCalledWith('/v1/switches/core-1/ports');
  });

  it('getPortStatus escapes the slash in a port name', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: { port: 'Eth1/3' } });

    await service.getPortStatus('core-1', 'Eth1/3');

    expect(mockClient.get).toHaveBeenCalledWith('/v1/switches/core-1/ports/Eth1%2F3');
  });

  it('enablePort POSTs to .../enable with no body', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: { status: 'ok' } });

    await service.enablePort('core-1', 'Eth1/3');

    expect(mockClient.post).toHaveBeenCalledWith('/v1/switches/core-1/ports/Eth1%2F3/enable');
  });

  it('disablePort POSTs to .../disable with no body', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: { status: 'ok' } });

    await service.disablePort('core-1', 'Eth1/3');

    expect(mockClient.post).toHaveBeenCalledWith('/v1/switches/core-1/ports/Eth1%2F3/disable');
  });

  it('setPortVLAN POSTs vlan_id only', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: { status: 'ok' } });

    await service.setPortVLAN('core-1', 'Eth1/3', 200);

    expect(mockClient.post).toHaveBeenCalledWith('/v1/switches/core-1/ports/Eth1%2F3/vlan', {
      vlan_id: 200,
    });
  });

  it.each([0, 4095, 1.5])('setPortVLAN refuses vlan_id %s before sending', async (vlan) => {
    await expect(service.setPortVLAN('core-1', 'Eth1/3', vlan)).rejects.toBeInstanceOf(RangeError);
    expect(mockClient.post).not.toHaveBeenCalled();
  });
});
