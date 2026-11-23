/**
 * Unit tests for the BMC enrollment and factory-certificate restore
 * ceremonies (pkg/webservice/v1/bmc/enroll.go EnrollBMC,
 * pkg/webservice/v1/bmc/cert_restore.go RestoreBMC).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { BMCCertService } from '../bmc-cert-service.js';
import type { BMCEnrollResult, BMCRestoreResult } from '../bmc-cert-service.js';
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

const certMeta = {
  subject: 'CN=f',
  issuer: 'CN=v',
  serial_number: '01',
  not_before: '2026-01-01T00:00:00Z',
  not_after: '2027-01-01T00:00:00Z',
  spki_sha256: 'cd',
  sha256: 'ef',
  captured_at: '2026-11-01T00:00:00Z',
};

describe('BMCCertService', () => {
  let service: BMCCertService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new BMCCertService(mockClient);
  });

  it('is exported from the package entry point', async () => {
    const mod = await import('../../index.js');
    expect(mod.BMCCertService).toBe(BMCCertService);
  });

  describe('enrollBMC', () => {
    it('posts an empty JSON object to the enroll route when no option is given', async () => {
      vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: {} });

      await service.enrollBMC(7);

      expect(mockClient.post).toHaveBeenCalledWith('/v1/bmc/7/enroll', {});
    });

    it('maps every given option to its snake_case key', async () => {
      vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: {} });

      await service.enrollBMC('9007199254740993', {
        replaceCertificate: true,
        rotatePassword: false,
        dnsRegister: true,
        danePublish: false,
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/bmc/9007199254740993/enroll', {
        replace_certificate: true,
        rotate_password: false,
        dns_register: true,
        dane_publish: false,
      });
    });

    it('leaves out the options not given so the profile defaults hold', async () => {
      vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: {} });

      await service.enrollBMC(7, { danePublish: true });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/bmc/7/enroll', { dane_publish: true });
    });

    it('returns the enroll answer unchanged', async () => {
      const data: BMCEnrollResult = {
        device_id: '9007199254740993',
        endpoint: 'https://bmc-1.example.com',
        hostname: 'bmc-1',
        pin_spki_sha256: 'ab',
        factory_cert_meta: certMeta,
        steps: [{ name: 'capture_factory_cert', ok: true }],
      };
      const answer = { success: true, data };
      vi.mocked(mockClient.post).mockResolvedValue(answer);

      const result = await service.enrollBMC(7);

      expect(result).toEqual(answer);
      expect(result.data?.device_id).toBe('9007199254740993');
    });

    it('passes a 503 answer through unchanged', async () => {
      const answer = {
        success: false,
        error: { code: 'SERVICE_UNAVAILABLE', message: 'enroller not available', status: 503 },
      };
      vi.mocked(mockClient.post).mockResolvedValue(answer);

      const result = await service.enrollBMC(7);

      expect(result).toEqual(answer);
    });
  });

  describe('restoreFactoryCert', () => {
    it('posts to the restore route with no body and returns the answer unchanged', async () => {
      const data: BMCRestoreResult = {
        device_id: '7',
        endpoint: 'e',
        hostname: 'h',
        new_cert_meta: certMeta,
        new_cert_pem: 'PEM',
        steps: [],
      };
      const answer = { success: true, data };
      vi.mocked(mockClient.post).mockResolvedValue(answer);

      const result = await service.restoreFactoryCert(7);

      expect(mockClient.post).toHaveBeenCalledTimes(1);
      expect(vi.mocked(mockClient.post).mock.calls[0]).toEqual(['/v1/bmc/7/cert/restore']);
      expect(result).toEqual(answer);
    });

    it('passes a 404 answer through unchanged', async () => {
      const answer = {
        success: false,
        error: { code: 'NOT_FOUND', message: 'profile not found', status: 404 },
      };
      vi.mocked(mockClient.post).mockResolvedValue(answer);

      const result = await service.restoreFactoryCert(42);

      expect(result).toEqual(answer);
    });
  });
});
