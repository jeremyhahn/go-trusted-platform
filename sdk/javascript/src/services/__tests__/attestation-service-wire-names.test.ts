/**
 * Unit tests for the attestation request enum names.
 *
 * `pkg/webservice/v1/rest/attestation/server_router.go` decodes request
 * bodies with protojson, which discards a short hash algorithm such as
 * 'SHA384' and reads it as UNSPECIFIED. These tests pin the proto name on the
 * wire for every request that carries one.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AttestationService } from '../attestation-service.js';
import type { ApiClient } from '../../client/api-client.js';
import type { AttestationHashAlgorithm } from '../../types/attestation.js';

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

const hashAlgorithms: Array<[AttestationHashAlgorithm, string]> = [
  ['UNSPECIFIED', 'ATTESTATION_HASH_ALGORITHM_UNSPECIFIED'],
  ['SHA1', 'ATTESTATION_HASH_ALGORITHM_SHA1'],
  ['SHA256', 'ATTESTATION_HASH_ALGORITHM_SHA256'],
  ['SHA384', 'ATTESTATION_HASH_ALGORITHM_SHA384'],
  ['SHA512', 'ATTESTATION_HASH_ALGORITHM_SHA512'],
];

const quote = {
  quoteData: 'cXVvdGU=',
  signature: 'c2ln',
  signatureAlgorithm: 'SHA256-RSAPSS',
  pcrValues: [],
  nonce: 'bm9uY2U=',
};

describe('AttestationService request enum names', () => {
  let service: AttestationService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new AttestationService(mockClient);
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: {} });
  });

  it.each(hashAlgorithms)('buildManifest sends %s as %s', async (hashAlgorithm, protoName) => {
    await service.buildManifest({ config: { hostId: 'h1', hashAlgorithm }, sign: true });

    expect(mockClient.post).toHaveBeenCalledWith('/v1/attestation/manifests/build', {
      config: { hostId: 'h1', hashAlgorithm: protoName },
      sign: true,
    });
  });

  it.each(hashAlgorithms)('verifyManifest sends %s as %s', async (hashAlgorithm, protoName) => {
    const manifest = { id: 'm1' } as never;
    await service.verifyManifest({ manifest, config: { hashAlgorithm } });

    expect(mockClient.post).toHaveBeenCalledWith('/v1/attestation/manifests/verify', {
      manifest,
      config: { hashAlgorithm: protoName },
    });
  });

  it('verifyManifest leaves out a config the caller did not set', async () => {
    const manifest = { id: 'm1' } as never;
    await service.verifyManifest({ manifest });

    expect(mockClient.post).toHaveBeenCalledWith('/v1/attestation/manifests/verify', { manifest });
  });

  it.each(hashAlgorithms)('getQuote sends %s as %s', async (hashAlgorithm, protoName) => {
    await service.getQuote({ config: { akHandle: 1, hashAlgorithm }, nonce: 'bm9uY2U=' });

    expect(mockClient.post).toHaveBeenCalledWith('/v1/attestation/quote', {
      config: { akHandle: 1, hashAlgorithm: protoName },
      nonce: 'bm9uY2U=',
    });
  });

  it.each(hashAlgorithms)('collectHostAttestation sends %s as %s', async (hashAlgorithm, protoName) => {
    await service.collectHostAttestation({ config: { pcrIndices: [0], hashAlgorithm }, nonce: 'bm9uY2U=' });

    expect(mockClient.post).toHaveBeenCalledWith('/v1/attestation/host', {
      config: { pcrIndices: [0], hashAlgorithm: protoName },
      nonce: 'bm9uY2U=',
    });
  });

  it.each(hashAlgorithms)('collectVMAttestation sends %s as %s', async (hashAlgorithm, protoName) => {
    await service.collectVMAttestation({ vmId: 'vm1', config: { hashAlgorithm }, nonce: 'bm9uY2U=' });

    expect(mockClient.post).toHaveBeenCalledWith('/v1/attestation/vm/vm1', {
      vmId: 'vm1',
      config: { hashAlgorithm: protoName },
      nonce: 'bm9uY2U=',
    });
  });

  it.each(hashAlgorithms)('verifyQuote sends expected PCR algorithm %s as %s', async (algorithm, protoName) => {
    await service.verifyQuote({
      quote,
      akPublicKeyPem: 'cGVt',
      expectedNonce: 'bm9uY2U=',
      expectedPcrs: [{ index: 7, value: 'AAAA', algorithm }],
    });

    expect(mockClient.post).toHaveBeenCalledWith('/v1/attestation/quote/verify', {
      quote,
      akPublicKeyPem: 'cGVt',
      expectedNonce: 'bm9uY2U=',
      expectedPcrs: [{ index: 7, value: 'AAAA', algorithm: protoName }],
    });
  });

  it('leaves the hash algorithm out when the caller does not set it', async () => {
    await service.getQuote({ config: { akHandle: 1 }, nonce: 'bm9uY2U=' });

    expect(mockClient.post).toHaveBeenCalledWith('/v1/attestation/quote', {
      config: { akHandle: 1 },
      nonce: 'bm9uY2U=',
    });
  });
});
