/**
 * Unit tests for the CA request bodies.
 *
 * `pkg/webservice/v1/rest/ca/handlers.go` decodes request bodies with
 * protojson, which accepts only the full enum name and the protobuf JSON
 * field names: a short key algorithm such as 'RSA_4096' is discarded and the
 * certificate is issued with the default algorithm. These tests pin the
 * protobuf shape on the wire.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CAService } from '../ca-service.js';
import type { ApiClient } from '../../client/api-client.js';
import type { CertificateType, KeyAlgorithm, RevocationReason } from '../../types/ca.js';

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

describe('CAService request bodies', () => {
  let service: CAService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new CAService(mockClient);
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: {} });
  });

  describe('issueCertificate', () => {
    it('wraps the request and sends protobuf names', async () => {
      await service.issueCertificate({
        subject: { commonName: 'www.example.com' },
        keyAlgorithm: 'RSA_4096',
        certificateType: 'SERVER',
        isCA: false,
        validDays: 30,
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/ca/certificates', {
        request: {
          subject: { commonName: 'www.example.com' },
          keyAlgorithm: 'KEY_ALGORITHM_RSA_4096',
          certificateType: 'CERTIFICATE_TYPE_SERVER',
          isCa: false,
          validDays: 30,
        },
      });
    });

    it('leaves out the enums and isCa the caller did not set', async () => {
      await service.issueCertificate({ subject: { commonName: 'www.example.com' } });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/ca/certificates', {
        request: { subject: { commonName: 'www.example.com' } },
      });
    });

    it.each<[KeyAlgorithm, string]>([
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
    ])('sends key algorithm %s as %s', async (keyAlgorithm, protoName) => {
      await service.issueCertificate({ subject: { commonName: 'a' }, keyAlgorithm });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/ca/certificates', {
        request: { subject: { commonName: 'a' }, keyAlgorithm: protoName },
      });
    });

    it.each<[CertificateType, string]>([
      ['UNSPECIFIED', 'CERTIFICATE_TYPE_UNSPECIFIED'],
      ['SERVER', 'CERTIFICATE_TYPE_SERVER'],
      ['CLIENT', 'CERTIFICATE_TYPE_CLIENT'],
      ['CA', 'CERTIFICATE_TYPE_CA'],
      ['CODE_SIGNING', 'CERTIFICATE_TYPE_CODE_SIGNING'],
      ['EMAIL', 'CERTIFICATE_TYPE_EMAIL'],
    ])('sends certificate type %s as %s', async (certificateType, protoName) => {
      await service.issueCertificate({ subject: { commonName: 'a' }, certificateType });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/ca/certificates', {
        request: { subject: { commonName: 'a' }, certificateType: protoName },
      });
    });
  });

  describe('revokeCertificate', () => {
    it.each<[RevocationReason, string]>([
      ['UNSPECIFIED', 'REVOCATION_REASON_UNSPECIFIED'],
      ['KEY_COMPROMISE', 'REVOCATION_REASON_KEY_COMPROMISE'],
      ['CA_COMPROMISE', 'REVOCATION_REASON_CA_COMPROMISE'],
      ['AFFILIATION_CHANGED', 'REVOCATION_REASON_AFFILIATION_CHANGED'],
      ['SUPERSEDED', 'REVOCATION_REASON_SUPERSEDED'],
      ['CESSATION_OF_OPERATION', 'REVOCATION_REASON_CESSATION_OF_OPERATION'],
      ['CERTIFICATE_HOLD', 'REVOCATION_REASON_CERTIFICATE_HOLD'],
      ['REMOVE_FROM_CRL', 'REVOCATION_REASON_REMOVE_FROM_CRL'],
      ['PRIVILEGE_WITHDRAWN', 'REVOCATION_REASON_PRIVILEGE_WITHDRAWN'],
      ['AA_COMPROMISE', 'REVOCATION_REASON_AA_COMPROMISE'],
    ])('sends reason %s as %s', async (reason, protoName) => {
      await service.revokeCertificate({ serial: 'ab12', reason, deleteKeys: true });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/ca/certificates/ab12/revoke', {
        reason: protoName,
        deleteKeys: true,
      });
    });
  });
});
