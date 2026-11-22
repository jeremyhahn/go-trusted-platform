/**
 * Unit tests for IDevIDService.createLDevID: the server routes
 * `POST /api/v1/idevid/ldevid` (pkg/webservice/v1/rest/idevid/router.go).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { IDevIDService } from '../idevid-service.js';
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

describe('IDevIDService.createLDevID', () => {
  let service: IDevIDService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new IDevIDService(mockClient);
  });

  it('posts the request to /v1/idevid/ldevid', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({
      success: true,
      data: { status: { success: true }, certificatePem: 'PEM' },
    });

    const request = { template: { commonName: 'node-1' }, algorithm: 'ECDSA_P256' as const, overwrite: true };
    const result = await service.createLDevID(request);

    expect(mockClient.post).toHaveBeenCalledTimes(1);
    const call = vi.mocked(mockClient.post).mock.calls[0];
    if (!call) {
      throw new Error('post was not called');
    }
    const [url, body] = call;
    expect(url).toMatch(/\/v1\/idevid\/ldevid$/);
    expect(body).toEqual({ template: { common_name: 'node-1' }, algorithm: 1, overwrite: true });
    expect(result.data?.certificatePem).toBe('PEM');
  });

  function postedBody(): unknown {
    const call = vi.mocked(mockClient.post).mock.calls[0];
    if (!call) {
      throw new Error('post was not called');
    }
    return call[1];
  }

  // pkg/api/daemon/rest_idevid_ldevid.go decodes with encoding/json into
  // CreateLDevIDRequest: algorithm is the int32 DeviceKeyAlgorithm and the
  // field is validity_days. protojson in the webservice accepts both too.
  it('sends the algorithm as the proto enum number', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: { status: { success: true } } });

    await service.createLDevID({ algorithm: 'RSA_3072' });

    expect(postedBody()).toEqual({ algorithm: 4 });
  });

  it('sends every algorithm as its proto enum number', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: { status: { success: true } } });

    for (const algorithm of ['UNSPECIFIED', 'ECDSA_P256', 'ECDSA_P384', 'RSA_2048', 'RSA_3072'] as const) {
      await service.createLDevID({ algorithm });
    }

    const bodies = vi.mocked(mockClient.post).mock.calls.map((call) => call[1]);
    expect(bodies).toEqual([{ algorithm: 0 }, { algorithm: 1 }, { algorithm: 2 }, { algorithm: 3 }, { algorithm: 4 }]);
  });

  it('sends validityDays as validity_days', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: { status: { success: true } } });

    await service.createLDevID({ algorithm: 'ECDSA_P384', validityDays: 30, overwrite: true });

    expect(postedBody()).toEqual({ algorithm: 2, validity_days: 30, overwrite: true });
  });

  it('normalises the daemon snake_case response', async () => {
    // CreateLDevIDResponse as encoding/json writes it in the daemon handler.
    vi.mocked(mockClient.post).mockResolvedValue({
      success: true,
      data: { status: { success: true }, csr_pem: 'Q1NS', certificate_pem: 'Q0VSVA==' },
    });

    const result = await service.createLDevID({ algorithm: 'ECDSA_P384' });

    expect(result.data).toEqual({ status: { success: true }, csrPem: 'Q1NS', certificatePem: 'Q0VSVA==' });
  });

  // CSRTemplate and TCGDeviceAttributes in sdk/go/gen/idevid.pb.go carry
  // snake_case json tags; encoding/json in the daemon ignores camelCase keys
  // and protojson in the webservice accepts the proto field names too.
  it('sends the complete nested template with snake_case keys', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: { status: { success: true } } });

    await service.createLDevID({
      template: {
        commonName: 'node-1',
        organization: 'Acme',
        organizationalUnit: 'Edge',
        country: 'US',
        province: 'CA',
        locality: 'SF',
        emailAddresses: ['ops@example.com'],
        dnsNames: ['node-1.example.com'],
        tcgAttributes: {
          tpmManufacturer: 'IFX',
          tpmModel: 'SLB9670',
          tpmVersion: '7.85',
          platformManufacturer: 'Dell',
          platformModel: 'R650',
          platformVersion: '1.0',
          platformSerial: 'SN123',
        },
      },
    });

    expect(postedBody()).toEqual({
      template: {
        common_name: 'node-1',
        organization: 'Acme',
        organizational_unit: 'Edge',
        country: 'US',
        province: 'CA',
        locality: 'SF',
        email_addresses: ['ops@example.com'],
        dns_names: ['node-1.example.com'],
        tcg_attributes: {
          tpm_manufacturer: 'IFX',
          tpm_model: 'SLB9670',
          tpm_version: '7.85',
          platform_manufacturer: 'Dell',
          platform_model: 'R650',
          platform_version: '1.0',
          platform_serial: 'SN123',
        },
      },
    });
  });

  it('omits template fields that are not set', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: { status: { success: true } } });

    await service.createLDevID({ template: { commonName: 'node-1', tcgAttributes: { tpmModel: 'X' } } });

    expect(postedBody()).toEqual({ template: { common_name: 'node-1', tcg_attributes: { tpm_model: 'X' } } });
  });

  // DeviceIdentityCertificate as encoding/json writes it: snake_case keys
  // and timestamppb.Timestamp as {seconds, nanos}.
  it('normalises the daemon snake_case certificate and its timestamps', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({
      success: true,
      data: {
        status: { success: true },
        certificate_pem: 'Q0VSVA==',
        certificate: {
          pem: 'UEVN',
          der: 'REVS',
          key_type: 'LDevID',
          tpm_handle: 0x81020001,
          issued_at: { seconds: 1767225600 },
          expires_at: { seconds: 1798761600, nanos: 500000000 },
          issuer_cn: 'Platform CA',
          subject_cn: 'node-1',
          serial_number: '0a1b',
          fingerprint: 'ff00',
          key_algorithm: 'ECDSA',
          signature_algorithm: 'ECDSA-SHA384',
          key_size: 384,
        },
      },
    });

    const result = await service.createLDevID({ algorithm: 'ECDSA_P384' });

    expect(result.data).toEqual({
      status: { success: true },
      certificatePem: 'Q0VSVA==',
      certificate: {
        pem: 'UEVN',
        der: 'REVS',
        keyType: 'LDevID',
        tpmHandle: 0x81020001,
        issuedAt: '2026-01-01T00:00:00.000Z',
        expiresAt: '2027-01-01T00:00:00.500Z',
        issuerCn: 'Platform CA',
        subjectCn: 'node-1',
        serialNumber: '0a1b',
        fingerprint: 'ff00',
        keyAlgorithm: 'ECDSA',
        signatureAlgorithm: 'ECDSA-SHA384',
        keySize: 384,
      },
    });
  });

  it('keeps a webservice camelCase certificate unchanged', async () => {
    const data = {
      status: { success: true },
      certificatePem: 'Q0VSVA==',
      certificate: {
        keyType: 'LDevID',
        tpmHandle: 1,
        issuedAt: '2026-01-01T00:00:00Z',
        expiresAt: '2027-01-01T00:00:00Z',
        issuerCn: 'CA',
        subjectCn: 'node-1',
        serialNumber: '01',
        fingerprint: 'ff',
        keyAlgorithm: 'ECDSA',
        signatureAlgorithm: 'ECDSA-SHA256',
        keySize: 256,
      },
    };
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data });

    const result = await service.createLDevID();

    expect(result.data).toEqual(data);
  });

  it('keeps the webservice camelCase response', async () => {
    const data = { status: { success: true }, csrPem: 'Q1NS', certificatePem: 'Q0VSVA==' };
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data });

    const result = await service.createLDevID();

    expect(result.data).toEqual(data);
  });

  it('posts no algorithm key when none is given', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: { status: { success: true } } });

    await service.createLDevID({ overwrite: true });

    const body = postedBody();
    expect(body).toEqual({ overwrite: true });
    expect(Object.prototype.hasOwnProperty.call(body, 'algorithm')).toBe(false);
  });

  it('posts an empty body when called without a request', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: { status: { success: true } } });

    await service.createLDevID();

    const call = vi.mocked(mockClient.post).mock.calls[0];
    if (!call) {
      throw new Error('post was not called');
    }
    const [url, body] = call;
    expect(url).toMatch(/\/v1\/idevid\/ldevid$/);
    expect(body).toEqual({});
  });
});
