/**
 * EABService QR code and validate replies use the field names the server
 * sends (platform.v1 GetEABCredentialQRCodeResponse and
 * ValidateEABCredentialResponse, protojson), and getQRCode sends only an
 * integer size (the server reads it with QueryUint32).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { EABService } from '../eab-service.js';
import type { ApiClient } from '../../client/api-client.js';
import type { GetEABQRCodeResponse, ValidateEABCredentialResponse } from '../../types/eab.js';

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

describe('EABService QR code and validate wire', () => {
  let service: EABService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new EABService(mockClient);
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: {} });
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: {} });
  });

  it('getQRCode without a size sends no query', async () => {
    await service.getQRCode(7);

    expect(mockClient.get).toHaveBeenCalledWith('/v1/eab/credentials/7/qrcode');
  });

  it('getQRCode floors a fractional size to an integer', async () => {
    await service.getQRCode(7, 256.9);

    expect(mockClient.get).toHaveBeenCalledWith('/v1/eab/credentials/7/qrcode?size=256');
  });

  it('getQRCode leaves out a negative or non-finite size', async () => {
    await service.getQRCode(7, -1);
    await service.getQRCode(7, Number.NaN);

    expect(mockClient.get).toHaveBeenNthCalledWith(1, '/v1/eab/credentials/7/qrcode');
    expect(mockClient.get).toHaveBeenNthCalledWith(2, '/v1/eab/credentials/7/qrcode');
  });

  it('getQRCode returns the served qrCode and contentType', async () => {
    const qr: GetEABQRCodeResponse = {
      qrCode: 'iVBORw0KGgo=',
      contentType: 'image/png',
      timestamp: '2026-11-21T00:00:00Z',
    };
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: qr });

    const result = await service.getQRCode(7);

    expect(result.success).toBe(true);
    expect(result.data?.contentType).toBe('image/png');
    expect(result.data?.qrCode).toBe('iVBORw0KGgo=');
  });

  it('validate posts the key pair and returns the served errorMessage', async () => {
    const reply: ValidateEABCredentialResponse = {
      valid: false,
      errorMessage: 'credential revoked',
      timestamp: '2026-11-21T00:00:00Z',
    };
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: reply });

    const result = await service.validate({ keyId: 'k1', hmacKey: 'aGs=' });

    expect(mockClient.post).toHaveBeenCalledWith('/v1/eab/credentials/validate', {
      keyId: 'k1',
      hmacKey: 'aGs=',
    });
    expect(result.data?.valid).toBe(false);
    expect(result.data?.errorMessage).toBe('credential revoked');
  });

  it('validate returns the served credential summary', async () => {
    const reply: ValidateEABCredentialResponse = {
      valid: true,
      credential: {
        id: 7,
        keyId: 'k1',
        profileId: 2,
        tenantId: 't1',
        expiresAt: '2026-12-01T00:00:00Z',
        status: 'ACTIVE',
        createdAt: '2026-11-21T00:00:00Z',
        updatedAt: '2026-11-21T00:00:00Z',
      },
    };
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: reply });

    const result = await service.validate({ keyId: 'k1', hmacKey: 'aGs=' });

    expect(result.data?.valid).toBe(true);
    expect(result.data?.credential?.keyId).toBe('k1');
  });

  it('getQRCode passes an error answer through unchanged', async () => {
    const failure = {
      success: false as const,
      error: { code: 'NOT_FOUND', message: 'no credential', status: 404 },
    };
    vi.mocked(mockClient.get).mockResolvedValue(failure);

    const result = await service.getQRCode(7);

    expect(result).toEqual(failure);
  });
});
