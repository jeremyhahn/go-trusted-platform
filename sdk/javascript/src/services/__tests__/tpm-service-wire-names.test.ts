/**
 * Unit tests for the TPM request enum names.
 *
 * `pkg/webservice/v1/rest/tpm/handlers.go` decodes request bodies with
 * protojson, which discards a short enum name such as 'SHA256' and reads the
 * field as UNSPECIFIED. These tests pin the proto name on the wire for the
 * key algorithm and the PCR bank.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { TPMService } from '../tpm-service.js';
import type { ApiClient } from '../../client/api-client.js';
import { InvalidEnumValueError } from '../../errors/index.js';
import type { KeyAlgorithm } from '../../types/ca.js';
import type { PCRBank } from '../../types/tpm.js';

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

const keyAlgorithms: Array<[KeyAlgorithm, string]> = [
  ['UNSPECIFIED', 'KEY_ALGORITHM_UNSPECIFIED'],
  ['RSA_2048', 'KEY_ALGORITHM_RSA_2048'],
  ['RSA_3072', 'KEY_ALGORITHM_RSA_3072'],
  ['RSA_4096', 'KEY_ALGORITHM_RSA_4096'],
  ['ECDSA_P256', 'KEY_ALGORITHM_ECDSA_P256'],
  ['ECDSA_P384', 'KEY_ALGORITHM_ECDSA_P384'],
  ['ECDSA_P521', 'KEY_ALGORITHM_ECDSA_P521'],
  ['ED25519', 'KEY_ALGORITHM_ED25519'],
  ['DILITHIUM2', 'KEY_ALGORITHM_DILITHIUM2'],
  ['DILITHIUM3', 'KEY_ALGORITHM_DILITHIUM3'],
  ['DILITHIUM5', 'KEY_ALGORITHM_DILITHIUM5'],
];

const pcrBanks: Array<[PCRBank, string]> = [
  ['UNSPECIFIED', 'PCR_BANK_UNSPECIFIED'],
  ['SHA1', 'PCR_BANK_SHA1'],
  ['SHA256', 'PCR_BANK_SHA256'],
  ['SHA384', 'PCR_BANK_SHA384'],
  ['SHA512', 'PCR_BANK_SHA512'],
  ['SM3_256', 'PCR_BANK_SM3_256'],
];

describe('TPMService request enum names', () => {
  let service: TPMService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new TPMService(mockClient);
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: {} });
  });

  describe('key creation', () => {
    it.each(keyAlgorithms)('createEK sends algorithm %s as %s', async (algorithm, protoName) => {
      await service.createEK({ attributes: { cn: 'ek', algorithm }, persistent: true });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/tpm/ek', {
        attributes: { cn: 'ek', algorithm: protoName },
        persistent: true,
      });
    });

    it.each(keyAlgorithms)('createSRK sends algorithm %s as %s', async (algorithm, protoName) => {
      await service.createSRK({ attributes: { cn: 'srk', algorithm } });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/tpm/srk', {
        attributes: { cn: 'srk', algorithm: protoName },
      });
    });

    it.each(keyAlgorithms)('createAK sends algorithm %s as %s', async (algorithm, protoName) => {
      await service.createAK({ attributes: { cn: 'ak', algorithm }, parentHandle: 1 });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/tpm/ak', {
        attributes: { cn: 'ak', algorithm: protoName },
        parentHandle: 1,
      });
    });

    it('sends an empty body when no request is given', async () => {
      await service.createEK();

      expect(mockClient.post).toHaveBeenCalledWith('/v1/tpm/ek', {});
    });

    it('maps every attribute set on provision and leaves out the unset ones', async () => {
      await service.provision({
        createEk: true,
        ekAttributes: { cn: 'ek', algorithm: 'RSA_2048' },
        akAttributes: { cn: 'ak', algorithm: 'ECDSA_P256' },
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/tpm/provision', {
        createEk: true,
        ekAttributes: { cn: 'ek', algorithm: 'KEY_ALGORITHM_RSA_2048' },
        akAttributes: { cn: 'ak', algorithm: 'KEY_ALGORITHM_ECDSA_P256' },
      });
    });
  });

  describe('key deletion', () => {
    // The router serves bare DELETE /ek, /srk and /ak (no /{handle} segment)
    // and decodes handle, algorithm and password from the body.
    it.each([
      ['EK', '/v1/tpm/ek', (s: TPMService) => s.deleteEK({ handle: 0x81010001, algorithm: 'RSA_2048', password: 'pw' })],
      ['SRK', '/v1/tpm/srk', (s: TPMService) => s.deleteSRK({ handle: 0x81000001, algorithm: 'RSA_2048', password: 'pw' })],
      ['AK', '/v1/tpm/ak', (s: TPMService) => s.deleteAK({ handle: 0x81010002, algorithm: 'ECDSA_P256', password: 'pw' })],
    ])('deletes the %s on its served route with the handle in the body', async (_name, path, call) => {
      vi.mocked(mockClient.delete).mockResolvedValue({ success: true, data: {} });

      await call(service);

      const calls = vi.mocked(mockClient.delete).mock.calls;
      expect(calls).toHaveLength(1);
      expect(calls[0]?.[0]).toBe(path);
      expect(calls[0]?.[2]).toMatchObject({ handle: expect.any(Number) as number, password: 'pw' });
      expect(String((calls[0]?.[2] as Record<string, unknown>).algorithm)).toMatch(/^KEY_ALGORITHM_/);
    });

    it('rejects an unknown algorithm with a typed error and sends nothing', async () => {
      await expect(service.deleteEK({ handle: 1, algorithm: 'BOGUS' as KeyAlgorithm })).rejects.toThrow(
        InvalidEnumValueError
      );
      expect(mockClient.delete).not.toHaveBeenCalled();
    });
  });

  describe('PCR bank', () => {
    it.each(pcrBanks)('seal sends bank %s as %s', async (pcrBank, protoName) => {
      await service.seal({ data: 'ZGF0YQ==', cn: 'secret', pcrIndices: [7], pcrBank });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/tpm/seal', {
        data: 'ZGF0YQ==',
        cn: 'secret',
        pcrIndices: [7],
        pcrBank: protoName,
      });
    });

    it.each(pcrBanks)('unseal sends bank %s as %s', async (pcrBank, protoName) => {
      await service.unseal({ cn: 'secret', pcrIndices: [7], pcrBank });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/tpm/unseal', {
        cn: 'secret',
        pcrIndices: [7],
        pcrBank: protoName,
      });
    });

    it.each(pcrBanks)('quote sends bank %s as %s', async (pcrBank, protoName) => {
      await service.quote({ akHandle: 1, pcrIndices: [0, 7], pcrBank, nonce: 'bm9uY2U=' });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/tpm/quote', {
        akHandle: 1,
        pcrIndices: [0, 7],
        pcrBank: protoName,
        nonce: 'bm9uY2U=',
      });
    });

    it('leaves the bank out when the caller does not set it', async () => {
      await service.quote({ akHandle: 1, pcrIndices: [0], nonce: 'bm9uY2U=' });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/tpm/quote', {
        akHandle: 1,
        pcrIndices: [0],
        nonce: 'bm9uY2U=',
      });
    });
  });
});
