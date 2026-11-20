/**
 * createLDevID and prepareMigration act on the server before they answer:
 * the daemon creates and saves a fresh LDevID key on each call, and each
 * prepare launches a QEMU receiver. A client resend after a lost response
 * would replace the just-issued identity (or report a false failure) and
 * leak a receiver whose token the caller never saw, so both calls must go
 * out with client retries disabled, as finalizeMigration does.
 */

import { describe, it, expect, vi } from 'vitest';
import { ApiClient } from '../../client/api-client.js';
import { CAService } from '../ca-service.js';
import { ComputeService } from '../compute-service.js';
import { IDevIDService } from '../idevid-service.js';

function createMockApiClient(): ApiClient {
  return {
    get: vi.fn(),
    post: vi.fn().mockResolvedValue({ success: true, data: {} }),
    put: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
    head: vi.fn(),
    options: vi.fn(),
    fetch: vi.fn(),
    baseUrl: 'https://api.example.com',
  } as unknown as ApiClient;
}

/** A real ApiClient whose transport loses the first response. */
function lossyClient(): { client: ApiClient; fetchImpl: ReturnType<typeof vi.fn> } {
  const fetchImpl = vi
    .fn()
    .mockRejectedValueOnce(new TypeError('network error: response lost after the server acted'))
    .mockResolvedValue(
      new Response(JSON.stringify({ success: true, payload: { id: 'second' } }), {
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

const spec = { memoryMb: 2048, cpus: 2, diskSize: '20G', bootMode: 'uefi', arch: 'x86_64', tpmEnabled: true };

describe('create calls go out without client retries: they rely on the api-client default', () => {
  it('createLDevID passes no per-call options and relies on the api-client default', async () => {
    const mockClient = createMockApiClient();
    await new IDevIDService(mockClient).createLDevID({ overwrite: true });
    expect(vi.mocked(mockClient.post).mock.calls[0]?.[2]).toBeUndefined();
  });

  it('signCSR passes no per-call options and relies on the api-client default', async () => {
    const mockClient = createMockApiClient();
    await new CAService(mockClient).signCSR({ csrPem: 'CSR' });
    expect(vi.mocked(mockClient.post).mock.calls[0]?.[2]).toBeUndefined();
  });

  it('prepareMigration passes no per-call options and relies on the api-client default', async () => {
    const mockClient = createMockApiClient();
    await new ComputeService(mockClient).prepareMigration({ vmId: 'vm-1', vmName: 'web', mode: 'live', spec });
    expect(vi.mocked(mockClient.post).mock.calls[0]?.[2]).toBeUndefined();
  });

  it('createLDevID surfaces a lost response with exactly one request', async () => {
    const { client, fetchImpl } = lossyClient();
    const result = await new IDevIDService(client).createLDevID({ overwrite: true });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(result.success).toBe(false);
    expect(result.error?.message).toMatch(/network error/);
  });

  it('prepareMigration surfaces a lost response with exactly one request', async () => {
    const { client, fetchImpl } = lossyClient();
    const result = await new ComputeService(client).prepareMigration({
      vmId: 'vm-1',
      vmName: 'web',
      mode: 'live',
      spec,
    });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(result.success).toBe(false);
    expect(result.error?.message).toMatch(/network error/);
  });
});
