/**
 * KMSService.updateKeyStatus reaches the served PUT /v1/kms/keys/{name}/status route.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { KMSService } from '../kms-service.js';
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

describe('KMSService.updateKeyStatus', () => {
  let client: ApiClient;
  let service: KMSService;
  const ok = { success: true, data: { key_id: 'k1', version: 2, status: 'DISABLED' } };

  beforeEach(() => {
    client = createMockApiClient();
    service = new KMSService(client);
    vi.mocked(client.put).mockResolvedValue(ok as never);
  });

  it('sends PUT to /v1/kms/keys/{name}/status with status and version', async () => {
    await service.updateKeyStatus({ keyId: 'k1', status: 'DISABLED', version: 2 });

    expect(client.put).toHaveBeenCalledTimes(1);
    const [url, body] = vi.mocked(client.put).mock.calls[0] as unknown[];
    expect(url).toMatch(/\/v1\/kms\/keys\/k1\/status$/);
    expect(body).toEqual({ status: 'DISABLED', version: 2 });
    expect(client.patch).not.toHaveBeenCalled();
  });

  it('encodes the key name and omits version when the caller sets none', async () => {
    await service.updateKeyStatus({ keyId: 'team/key 1', status: 'ENABLED' });

    expect(client.put).toHaveBeenCalledTimes(1);
    const [url, body] = vi.mocked(client.put).mock.calls[0] as unknown[];
    expect(String(url).endsWith('/v1/kms/keys/team%2Fkey%201/status')).toBe(true);
    expect(Object.keys(body as object)).toEqual(['status']);
    expect(client.patch).not.toHaveBeenCalled();
  });

  it('returns the PUT response unchanged', async () => {
    const result = await service.updateKeyStatus({ keyId: 'k1', status: 'DISABLED', version: 2 });
    expect(result).toBe(ok);
  });

  it('returns a PUT error response unchanged', async () => {
    const notFound = { success: false, error: { code: 'NOT_FOUND', message: 'key not found', status: 404 } };
    vi.mocked(client.put).mockResolvedValue(notFound as never);

    const result = await service.updateKeyStatus({ keyId: 'k1', status: 'DISABLED' });
    expect(result).toBe(notFound);
  });
});
