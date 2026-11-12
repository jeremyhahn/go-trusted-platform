/**
 * Unit tests for the TPM capability, platform and certify calls (#1735).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { TPMService } from '../tpm-service.js';
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

describe('TPMService capabilities, platform and certify', () => {
  let service: TPMService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: {} });
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: {} });
    service = new TPMService(mockClient);
  });

  it('getCapabilities GETs /tpm/capabilities', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({
      success: true,
      data: { algorithms: ['RSA'], commands: ['TPM2_Quote'], eccCurves: ['NIST_P256'] },
    });

    const res = await service.getCapabilities();

    const url = vi.mocked(mockClient.get).mock.calls[0]?.[0] as string;
    expect(url).toMatch(/\/tpm\/capabilities$/);
    expect(res.data?.algorithms).toEqual(['RSA']);
  });

  it('getPlatformAttributes GETs /tpm/platform', async () => {
    await service.getPlatformAttributes();

    const url = vi.mocked(mockClient.get).mock.calls[0]?.[0] as string;
    expect(url).toMatch(/\/tpm\/platform$/);
  });

  it('certify POSTs the request body to /tpm/certify', async () => {
    const request = { keyHandle: 0x81000001, nonce: 'AAEC' };

    await service.certify(request);

    const call = vi.mocked(mockClient.post).mock.calls[0];
    expect(call?.[0] as string).toMatch(/\/tpm\/certify$/);
    expect(call?.[1]).toEqual(request);
  });
});
