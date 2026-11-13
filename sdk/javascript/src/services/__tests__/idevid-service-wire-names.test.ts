/**
 * Unit tests for the IDevID request enum names.
 *
 * `pkg/webservice/v1/rest/idevid/handlers.go` decodes request bodies with
 * protojson, which discards a short key algorithm such as 'ECDSA_P256' and
 * reads it as UNSPECIFIED. These tests pin the proto names on the wire for
 * every request that carries one.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { IDevIDService } from '../idevid-service.js';
import type { ApiClient } from '../../client/api-client.js';
import type { CertStorageType, DeviceKeyAlgorithm } from '../../types/idevid.js';

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

const algorithms: Array<[DeviceKeyAlgorithm, string]> = [
  ['UNSPECIFIED', 'DEVICE_KEY_ALGORITHM_UNSPECIFIED'],
  ['ECDSA_P256', 'DEVICE_KEY_ALGORITHM_ECDSA_P256'],
  ['ECDSA_P384', 'DEVICE_KEY_ALGORITHM_ECDSA_P384'],
  ['RSA_2048', 'DEVICE_KEY_ALGORITHM_RSA_2048'],
  ['RSA_3072', 'DEVICE_KEY_ALGORITHM_RSA_3072'],
];

const storageTypes: Array<[CertStorageType, string]> = [
  ['UNSPECIFIED', 'CERT_STORAGE_TYPE_UNSPECIFIED'],
  ['NVRAM', 'CERT_STORAGE_TYPE_NVRAM'],
  ['FILESYSTEM', 'CERT_STORAGE_TYPE_FILESYSTEM'],
];

describe('IDevIDService request enum names', () => {
  let service: IDevIDService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new IDevIDService(mockClient);
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: {} });
  });

  it.each(algorithms)('generateIDevID sends algorithm %s as %s', async (algorithm, protoName) => {
    await service.generateIDevID({ config: { algorithm, handle: 1 } });

    expect(mockClient.post).toHaveBeenCalledWith('/v1/idevid/generate', {
      config: { algorithm: protoName, handle: 1 },
    });
  });

  it.each(storageTypes)('generateIDevID sends storage %s as %s', async (storage, protoName) => {
    await service.generateIDevID({ config: { storage, storagePath: '/var/idevid' } });

    expect(mockClient.post).toHaveBeenCalledWith('/v1/idevid/generate', {
      config: { storage: protoName, storagePath: '/var/idevid' },
    });
  });

  it.each(algorithms)('generateIAK sends algorithm %s as %s', async (algorithm, protoName) => {
    await service.generateIAK({ config: { algorithm, overwrite: true } });

    expect(mockClient.post).toHaveBeenCalledWith('/v1/idevid/iak/generate', {
      config: { algorithm: protoName, overwrite: true },
    });
  });

  it.each(storageTypes)('generateIAK sends storage %s as %s', async (storage, protoName) => {
    await service.generateIAK({ config: { storage, nvIndex: 5 } });

    expect(mockClient.post).toHaveBeenCalledWith('/v1/idevid/iak/generate', {
      config: { storage: protoName, nvIndex: 5 },
    });
  });

  it('sends an empty body when the caller passes no config', async () => {
    await service.generateIDevID();
    await service.generateIAK({});

    expect(mockClient.post).toHaveBeenNthCalledWith(1, '/v1/idevid/generate', {});
    expect(mockClient.post).toHaveBeenNthCalledWith(2, '/v1/idevid/iak/generate', {});
  });

  it('leaves out the enums the caller did not set', async () => {
    await service.generateIDevID({ config: { handle: 7 } });

    expect(mockClient.post).toHaveBeenCalledWith('/v1/idevid/generate', { config: { handle: 7 } });
  });
});
