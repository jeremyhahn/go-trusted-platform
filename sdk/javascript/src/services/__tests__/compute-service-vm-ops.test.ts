/**
 * ComputeService VM operations added for the web UI (#1727): suspend,
 * resume, get snapshot, prepare and finalize migration.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ApiClient } from '../../client/api-client.js';
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

  it('finalizes a migration relying on the api-client retry default', async () => {
    await service.finalizeMigration({ receiverId: 'rx-9', commit: true });
    expect(vi.mocked(mockClient.post).mock.calls[0]?.[2]).toBeUndefined();
  });

  it('surfaces a lost finalize response without resending the commit', async () => {
    // The daemon removes the receiver token before it commits, so a resent
    // finalize would answer 404 for a migration that has already resumed.
    const lost = new TypeError('network error: response lost after commit');
    vi.mocked(mockClient.post).mockRejectedValueOnce(lost);
    await expect(service.finalizeMigration({ receiverId: 'rx-9', commit: true })).rejects.toBe(lost);
    expect(mockClient.post).toHaveBeenCalledTimes(1);
    expect(vi.mocked(mockClient.post).mock.calls[0]?.[2]).toBeUndefined();
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

/** A real ApiClient whose transport loses the first response after the server acted. */
function lossyClient(): { client: ApiClient; fetchImpl: ReturnType<typeof vi.fn> } {
  const fetchImpl = vi
    .fn()
    .mockRejectedValueOnce(new TypeError('network error: response lost after the server acted'))
    .mockResolvedValue(
      new Response(JSON.stringify({ success: true, payload: { id: 'vm-1' } }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    );
  const client = new ApiClient({
    baseUrl: 'https://platform.test/api/v1',
    fetch: fetchImpl as unknown as typeof fetch,
    retry: { maxRetries: 3, initialDelayMs: 1, maxDelayMs: 1 },
  });
  return { client, fetchImpl };
}

describe('ComputeService suspend/resume send one request', () => {
  it('suspendVM does not resend when the first response is lost', async () => {
    const { client, fetchImpl } = lossyClient();
    const response = await new ComputeService(client).suspendVM('vm-1');
    expect(response.success).toBe(false);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('resumeVM does not resend when the first response is lost', async () => {
    const { client, fetchImpl } = lossyClient();
    const response = await new ComputeService(client).resumeVM('vm-1');
    expect(response.success).toBe(false);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });
});
