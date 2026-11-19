/**
 * Unit tests for the CA service (#1779): every public method is driven
 * through a mocked transport, asserting the HTTP method, the path (with
 * its query and encoded segments), the body and the request headers, and
 * that a transport failure reaches the caller unchanged.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CAService } from './ca-service.js';
import type { ApiClient } from '../client/api-client.js';
import type {
  CertificateRequest,
  RenewCertificateRequest,
  RevokeCertificateRequest,
  VerifyCertificateRequest,
} from '../types/ca.js';

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

/** A serial with characters that must be percent-encoded in a path. */
const RAW_SERIAL = '0a:1b/2c?3d';
const ENC_SERIAL = '0a%3A1b%2F2c%3F3d';

describe('CAService', () => {
  let mockClient: ApiClient;
  let service: CAService;
  const failure = new Error('transport down');

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new CAService(mockClient);
  });

  function expectOnlyGet(): void {
    expect(mockClient.get).toHaveBeenCalledTimes(1);
    expect(mockClient.post).not.toHaveBeenCalled();
    expect(mockClient.put).not.toHaveBeenCalled();
    expect(mockClient.delete).not.toHaveBeenCalled();
  }

  function expectOnlyPost(): void {
    expect(mockClient.post).toHaveBeenCalledTimes(1);
    expect(mockClient.get).not.toHaveBeenCalled();
    expect(mockClient.put).not.toHaveBeenCalled();
    expect(mockClient.delete).not.toHaveBeenCalled();
  }

  describe('getInfo', () => {
    it('GETs /v1/ca/info with no query and returns the response', async () => {
      const response = { success: true, data: { commonName: 'root' } };
      vi.mocked(mockClient.get).mockResolvedValue(response);

      await expect(service.getInfo()).resolves.toBe(response);

      expectOnlyGet();
      expect(mockClient.get).toHaveBeenCalledWith('/v1/ca/info');
    });

    it('propagates a transport failure', async () => {
      vi.mocked(mockClient.get).mockRejectedValue(failure);
      await expect(service.getInfo()).rejects.toBe(failure);
      expect(mockClient.get).toHaveBeenCalledWith('/v1/ca/info');
    });
  });

  describe('getRootCertificate', () => {
    it('GETs /v1/ca/root', async () => {
      const response = { success: true, data: { serialNumber: '01' } };
      vi.mocked(mockClient.get).mockResolvedValue(response);

      await expect(service.getRootCertificate()).resolves.toBe(response);

      expectOnlyGet();
      expect(mockClient.get).toHaveBeenCalledWith('/v1/ca/root');
    });

    it('propagates a transport failure', async () => {
      vi.mocked(mockClient.get).mockRejectedValue(failure);
      await expect(service.getRootCertificate()).rejects.toBe(failure);
    });
  });

  describe('listCertificates', () => {
    it('GETs /v1/ca/certificates with no query when no options are given', async () => {
      const response = { success: true, data: { certificates: [] } };
      vi.mocked(mockClient.get).mockResolvedValue(response);

      await expect(service.listCertificates()).resolves.toBe(response);

      expectOnlyGet();
      expect(mockClient.get).toHaveBeenCalledWith('/v1/ca/certificates');
    });

    it('carries paging, sorting and filters in the query string', async () => {
      vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: { certificates: [] } });

      await service.listCertificates({
        page: 2,
        limit: 25,
        sortBy: 'notAfter',
        ascending: false,
        filters: { status: 'REVOKED' },
      });

      expectOnlyGet();
      const url = vi.mocked(mockClient.get).mock.calls[0]?.[0] as string;
      const [path, query] = url.split('?');
      expect(path).toBe('/v1/ca/certificates');
      const params = new URLSearchParams(query);
      expect(Object.fromEntries(params)).toEqual({
        page: '2',
        limit: '25',
        sortBy: 'notAfter',
        ascending: 'false',
        status: 'REVOKED',
      });
    });

    it('sends no query for empty options', async () => {
      vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: { certificates: [] } });
      await service.listCertificates({});
      expect(mockClient.get).toHaveBeenCalledWith('/v1/ca/certificates');
    });

    it('propagates a transport failure', async () => {
      vi.mocked(mockClient.get).mockRejectedValue(failure);
      await expect(service.listCertificates({ page: 1 })).rejects.toBe(failure);
    });
  });

  describe('getCertificate', () => {
    it('GETs /v1/ca/certificates/{serial} with the serial encoded', async () => {
      const response = { success: true, data: { certificate: { serialNumber: RAW_SERIAL } } };
      vi.mocked(mockClient.get).mockResolvedValue(response);

      await expect(service.getCertificate(RAW_SERIAL)).resolves.toBe(response);

      expectOnlyGet();
      expect(mockClient.get).toHaveBeenCalledWith(`/v1/ca/certificates/${ENC_SERIAL}`);
    });

    it('propagates a transport failure', async () => {
      vi.mocked(mockClient.get).mockRejectedValue(failure);
      await expect(service.getCertificate('01')).rejects.toBe(failure);
      expect(mockClient.get).toHaveBeenCalledWith('/v1/ca/certificates/01');
    });
  });

  describe('issueCertificate', () => {
    const request: CertificateRequest = {
      subject: { commonName: 'device-7', organization: 'Org' },
      sans: { uris: ['urn:device:7'] },
      validDays: 90,
      keyAlgorithm: 'ECDSA_P256',
      isCA: false,
      certificateType: 'CLIENT',
    };

    it('POSTs the request unchanged to /v1/ca/certificates', async () => {
      const response = { success: true, data: { certificate: { serialNumber: '02' } } };
      vi.mocked(mockClient.post).mockResolvedValue(response);

      await expect(service.issueCertificate(request)).resolves.toBe(response);

      expectOnlyPost();
      expect(mockClient.post).toHaveBeenCalledWith('/v1/ca/certificates', request);
    });

    it('propagates a transport failure', async () => {
      vi.mocked(mockClient.post).mockRejectedValue(failure);
      await expect(service.issueCertificate(request)).rejects.toBe(failure);
    });
  });

  describe('revokeCertificate', () => {
    const request: RevokeCertificateRequest = {
      serial: RAW_SERIAL,
      reason: 'KEY_COMPROMISE',
      deleteKeys: true,
    };

    it('POSTs reason and deleteKeys to /v1/ca/certificates/{serial}/revoke, the serial only in the path', async () => {
      const response = { success: true, data: { revoked: true } };
      vi.mocked(mockClient.post).mockResolvedValue(response);

      await expect(service.revokeCertificate(request)).resolves.toBe(response);

      expectOnlyPost();
      expect(mockClient.post).toHaveBeenCalledWith(`/v1/ca/certificates/${ENC_SERIAL}/revoke`, {
        reason: 'KEY_COMPROMISE',
        deleteKeys: true,
      });
      const body = vi.mocked(mockClient.post).mock.calls[0]?.[1] as Record<string, unknown>;
      expect(body).not.toHaveProperty('serial');
    });

    it('propagates a transport failure', async () => {
      vi.mocked(mockClient.post).mockRejectedValue(failure);
      await expect(service.revokeCertificate(request)).rejects.toBe(failure);
    });
  });

  describe('renewCertificate', () => {
    const request: RenewCertificateRequest = {
      serial: RAW_SERIAL,
      validDays: 30,
      preserveSans: false,
      newSans: { uris: ['urn:device:8'] },
    };

    it('POSTs the renewal options to /v1/ca/certificates/{serial}/renew, the serial only in the path', async () => {
      const response = { success: true, data: { certificate: { serialNumber: '03' } } };
      vi.mocked(mockClient.post).mockResolvedValue(response);

      await expect(service.renewCertificate(request)).resolves.toBe(response);

      expectOnlyPost();
      expect(mockClient.post).toHaveBeenCalledWith(`/v1/ca/certificates/${ENC_SERIAL}/renew`, {
        validDays: 30,
        preserveSans: false,
        newSans: { uris: ['urn:device:8'] },
      });
      const body = vi.mocked(mockClient.post).mock.calls[0]?.[1] as Record<string, unknown>;
      expect(body).not.toHaveProperty('serial');
    });

    it('propagates a transport failure', async () => {
      vi.mocked(mockClient.post).mockRejectedValue(failure);
      await expect(service.renewCertificate(request)).rejects.toBe(failure);
    });
  });

  describe('verifyCertificate', () => {
    const request: VerifyCertificateRequest = {
      certificatePem: '-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n',
      verifyRevocation: true,
      verifyExpiration: true,
    };

    it('POSTs the request unchanged to /v1/ca/certificates/verify', async () => {
      const response = { success: true, data: { valid: true } };
      vi.mocked(mockClient.post).mockResolvedValue(response);

      await expect(service.verifyCertificate(request)).resolves.toBe(response);

      expectOnlyPost();
      expect(mockClient.post).toHaveBeenCalledWith('/v1/ca/certificates/verify', request);
    });

    it('propagates a transport failure', async () => {
      vi.mocked(mockClient.post).mockRejectedValue(failure);
      await expect(service.verifyCertificate(request)).rejects.toBe(failure);
    });
  });

  describe('getCRL', () => {
    it('GETs /v1/ca/crl', async () => {
      const response = { success: true, data: { crlPem: '' } };
      vi.mocked(mockClient.get).mockResolvedValue(response);

      await expect(service.getCRL()).resolves.toBe(response);

      expectOnlyGet();
      expect(mockClient.get).toHaveBeenCalledWith('/v1/ca/crl');
    });

    it('propagates a transport failure', async () => {
      vi.mocked(mockClient.get).mockRejectedValue(failure);
      await expect(service.getCRL()).rejects.toBe(failure);
    });
  });

  describe('downloadCRL', () => {
    it('GETs /v1/ca/crl/download asking for application/pkix-crl', async () => {
      const response = { success: true, data: new ArrayBuffer(4) };
      vi.mocked(mockClient.get).mockResolvedValue(response);

      await expect(service.downloadCRL()).resolves.toBe(response);

      expectOnlyGet();
      expect(mockClient.get).toHaveBeenCalledWith('/v1/ca/crl/download', {
        headers: { Accept: 'application/pkix-crl' },
      });
    });

    it('propagates a transport failure', async () => {
      vi.mocked(mockClient.get).mockRejectedValue(failure);
      await expect(service.downloadCRL()).rejects.toBe(failure);
    });
  });

  describe('getBundle', () => {
    it('GETs /v1/ca/bundle', async () => {
      const response = { success: true, data: { certificates: [] } };
      vi.mocked(mockClient.get).mockResolvedValue(response);

      await expect(service.getBundle()).resolves.toBe(response);

      expectOnlyGet();
      expect(mockClient.get).toHaveBeenCalledWith('/v1/ca/bundle');
    });

    it('propagates a transport failure', async () => {
      vi.mocked(mockClient.get).mockRejectedValue(failure);
      await expect(service.getBundle()).rejects.toBe(failure);
    });
  });

  describe('downloadBundle', () => {
    it('GETs /v1/ca/bundle/download asking for application/x-pem-file', async () => {
      const response = { success: true, data: '-----BEGIN CERTIFICATE-----' };
      vi.mocked(mockClient.get).mockResolvedValue(response);

      await expect(service.downloadBundle()).resolves.toBe(response);

      expectOnlyGet();
      expect(mockClient.get).toHaveBeenCalledWith('/v1/ca/bundle/download', {
        headers: { Accept: 'application/x-pem-file' },
      });
    });

    it('propagates a transport failure', async () => {
      vi.mocked(mockClient.get).mockRejectedValue(failure);
      await expect(service.downloadBundle()).rejects.toBe(failure);
    });
  });

  describe('downloadCertificatePEM', () => {
    it('GETs /v1/ca/certificates/{serial}/download asking for application/x-pem-file', async () => {
      const response = { success: true, data: '-----BEGIN CERTIFICATE-----' };
      vi.mocked(mockClient.get).mockResolvedValue(response);

      await expect(service.downloadCertificatePEM(RAW_SERIAL)).resolves.toBe(response);

      expectOnlyGet();
      expect(mockClient.get).toHaveBeenCalledWith(`/v1/ca/certificates/${ENC_SERIAL}/download`, {
        headers: { Accept: 'application/x-pem-file' },
      });
    });

    it('propagates a transport failure', async () => {
      vi.mocked(mockClient.get).mockRejectedValue(failure);
      await expect(service.downloadCertificatePEM('01')).rejects.toBe(failure);
    });
  });

  describe('downloadCertificateDER', () => {
    it('GETs /v1/ca/certificates/{serial}/download asking for application/x-x509-ca-cert', async () => {
      const response = { success: true, data: new ArrayBuffer(8) };
      vi.mocked(mockClient.get).mockResolvedValue(response);

      await expect(service.downloadCertificateDER(RAW_SERIAL)).resolves.toBe(response);

      expectOnlyGet();
      expect(mockClient.get).toHaveBeenCalledWith(`/v1/ca/certificates/${ENC_SERIAL}/download`, {
        headers: { Accept: 'application/x-x509-ca-cert' },
      });
    });

    it('propagates a transport failure', async () => {
      vi.mocked(mockClient.get).mockRejectedValue(failure);
      await expect(service.downloadCertificateDER('01')).rejects.toBe(failure);
    });
  });

  describe('getCertificateChain', () => {
    it('GETs /v1/ca/certificates/{serial}/chain with the serial encoded', async () => {
      const response = { success: true, data: [{ serialNumber: '01' }] };
      vi.mocked(mockClient.get).mockResolvedValue(response);

      await expect(service.getCertificateChain(RAW_SERIAL)).resolves.toBe(response);

      expectOnlyGet();
      expect(mockClient.get).toHaveBeenCalledWith(`/v1/ca/certificates/${ENC_SERIAL}/chain`);
    });

    it('propagates a transport failure', async () => {
      vi.mocked(mockClient.get).mockRejectedValue(failure);
      await expect(service.getCertificateChain('01')).rejects.toBe(failure);
    });
  });

  describe('isRevoked', () => {
    it('GETs /v1/ca/certificates/{serial}/status with the serial encoded', async () => {
      const response = {
        success: true,
        data: { revoked: true, reason: 'SUPERSEDED', revokedAt: '2026-01-01T00:00:00Z' },
      };
      vi.mocked(mockClient.get).mockResolvedValue(response);

      await expect(service.isRevoked(RAW_SERIAL)).resolves.toBe(response);

      expectOnlyGet();
      expect(mockClient.get).toHaveBeenCalledWith(`/v1/ca/certificates/${ENC_SERIAL}/status`);
    });

    it('propagates a transport failure', async () => {
      vi.mocked(mockClient.get).mockRejectedValue(failure);
      await expect(service.isRevoked('01')).rejects.toBe(failure);
    });
  });
});
