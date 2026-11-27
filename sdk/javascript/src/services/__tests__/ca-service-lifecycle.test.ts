/**
 * CAService lifecycle: InitCA and the CA trust install/uninstall go to
 * their REST routes with the protojson camelCase request body.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CAService } from '../ca-service.js';
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
  } as unknown as ApiClient;
}

describe('CAService lifecycle', () => {
  let service: CAService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new CAService(mockClient);
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: { status: { success: true } } });
  });

  it('initCA POSTs force to /v1/ca/init', async () => {
    const result = await service.initCA();
    expect(result.success).toBe(true);
    expect(mockClient.post).toHaveBeenLastCalledWith('/v1/ca/init', { force: false });

    await service.initCA({ force: true });
    expect(mockClient.post).toHaveBeenLastCalledWith('/v1/ca/init', { force: true });
    expect(mockClient.post).toHaveBeenCalledTimes(2);
  });

  it('installCACertificates POSTs includeIntermediates to /v1/ca/trust/install', async () => {
    await service.installCACertificates();
    expect(mockClient.post).toHaveBeenLastCalledWith('/v1/ca/trust/install', { includeIntermediates: false });

    await service.installCACertificates({ includeIntermediates: true });
    expect(mockClient.post).toHaveBeenLastCalledWith('/v1/ca/trust/install', { includeIntermediates: true });
  });

  it('uninstallCACertificates POSTs includeIntermediates to /v1/ca/trust/uninstall', async () => {
    await service.uninstallCACertificates();
    expect(mockClient.post).toHaveBeenLastCalledWith('/v1/ca/trust/uninstall', { includeIntermediates: false });

    await service.uninstallCACertificates({ includeIntermediates: true });
    expect(mockClient.post).toHaveBeenLastCalledWith('/v1/ca/trust/uninstall', { includeIntermediates: true });
  });

  it('propagates a refusal unchanged', async () => {
    const failure = new Error('403 Forbidden: token lacks scope');
    vi.mocked(mockClient.post).mockRejectedValue(failure);

    await expect(service.initCA()).rejects.toBe(failure);
    await expect(service.installCACertificates()).rejects.toBe(failure);
    await expect(service.uninstallCACertificates()).rejects.toBe(failure);
  });
});
