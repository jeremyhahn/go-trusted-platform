/**
 * TPMService capabilities and platform attributes (#2068): each getter reads
 * its own served route and returns the protojson response unchanged.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { TPMService } from '../tpm-service.js';
import { ApiClient } from '../../client/api-client.js';
import type {
  TPMCapabilitiesResponse,
  TPMPlatformAttributesResponse,
  TPMKeyRef,
} from '../../index.js';

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

describe('TPMService capabilities and platform attributes', () => {
  let service: TPMService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new TPMService(mockClient);
  });

  it('getCapabilities reads /v1/tpm/capabilities', async () => {
    const response = {
      success: true,
      data: { algorithms: ['RSA'], commands: ['TPM2_Quote'], eccCurves: ['NIST_P256'] },
    };
    vi.mocked(mockClient.get).mockResolvedValue(response);

    const result = await service.getCapabilities();

    expect(mockClient.get).toHaveBeenCalledTimes(1);
    expect(mockClient.get).toHaveBeenCalledWith('/v1/tpm/capabilities');
    expect(result).toEqual(response);
  });

  it('getPlatformAttributes reads /v1/tpm/platform', async () => {
    const response = {
      success: true,
      data: { device: '/dev/tpmrm0', isFips: false, ek: { handle: 2164260865, algorithm: 'RSA' } },
    };
    vi.mocked(mockClient.get).mockResolvedValue(response);

    const result = await service.getPlatformAttributes();

    expect(mockClient.get).toHaveBeenCalledTimes(1);
    expect(mockClient.get).toHaveBeenCalledWith('/v1/tpm/platform');
    expect(result).toEqual(response);
  });

  it('exports the response types from the package root', () => {
    const capabilities: TPMCapabilitiesResponse | undefined = undefined;
    const platform: TPMPlatformAttributesResponse | undefined = undefined;
    const keyRef: TPMKeyRef | undefined = undefined;
    expect([capabilities, platform, keyRef]).toEqual([undefined, undefined, undefined]);
  });
});
