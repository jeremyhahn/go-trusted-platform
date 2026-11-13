/**
 * ComputeService VM operations added for the web UI (#1727): suspend,
 * resume, get snapshot, prepare and finalize migration.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { ApiClient } from '../../client/api-client.js';
import { ComputeService } from '../compute-service.js';

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

describe('ComputeService VM operations', () => {
  let service: ComputeService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: {} });
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: {} });
    service = new ComputeService(mockClient);
  });

  it('suspends a VM by POST to /vms/{id}/suspend', async () => {
    await service.suspendVM('vm 1');
    const [url, body] = vi.mocked(mockClient.post).mock.calls[0]!;
    expect(url).toMatch(/\/compute\/vms\/vm%201\/suspend$/);
    expect(body).toEqual({});
  });

  it('resumes a VM by POST to /vms/{id}/resume', async () => {
    await service.resumeVM('vm-1');
    const [url, body] = vi.mocked(mockClient.post).mock.calls[0]!;
    expect(url).toMatch(/\/compute\/vms\/vm-1\/resume$/);
    expect(body).toEqual({});
  });

  it('gets one snapshot by GET /vms/{id}/snapshots/{snapshotId}', async () => {
    await service.getSnapshot('vm-1', 'snap/2');
    const [url] = vi.mocked(mockClient.get).mock.calls[0]!;
    expect(url).toMatch(/\/compute\/vms\/vm-1\/snapshots\/snap%2F2$/);
  });

  it('prepares a migration by POST /migrations/prepare with name, mode and spec', async () => {
    const spec = { memoryMb: 2048, cpus: 2, diskSize: '20G', bootMode: 'uefi', arch: 'x86_64', tpmEnabled: true };
    await service.prepareMigration({ vmId: 'vm-1', vmName: 'web', mode: 'live', spec });
    const [url, body] = vi.mocked(mockClient.post).mock.calls[0]!;
    expect(url).toMatch(/\/compute\/migrations\/prepare$/);
    expect(body).toEqual({ vmId: 'vm-1', vmName: 'web', mode: 'live', spec });
  });

  it('finalizes a migration by POST /migrations/{receiverId}/finalize with commit', async () => {
    await service.finalizeMigration({ receiverId: 'rx-9', commit: false });
    const [url, body] = vi.mocked(mockClient.post).mock.calls[0]!;
    expect(url).toMatch(/\/compute\/migrations\/rx-9\/finalize$/);
    expect(body).toEqual({ commit: false });
  });

  it('migrateVM forwards a per-request timeout to the client', async () => {
    await service.migrateVM(
      { vmId: 'vm-1', destinationHost: 'dest', liveMigration: true },
      { timeoutMs: 3600000 }
    );
    const call = vi.mocked(mockClient.post).mock.calls[0]!;
    expect(call[0]).toMatch(/\/compute\/vms\/vm-1\/migrate$/);
    expect(call[1]).toEqual({ destinationHost: 'dest', liveMigration: true, bandwidthLimitMbps: undefined });
    expect(call[2]).toEqual({ timeout: 3600000 });
  });

  it('migrateVM without options passes no request options', async () => {
    await service.migrateVM({ vmId: 'vm-1', destinationHost: 'dest', liveMigration: false });
    expect(vi.mocked(mockClient.post).mock.calls[0]![2]).toBeUndefined();
  });
});
