/**
 * Unit tests for the BMC certificate service. The service offers no
 * ceremony (#2199): enrolment cannot capture a trust pin on the profile
 * path and factory restore cannot carry the pin across the regenerated
 * certificate.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { BMCCertService, bmcProfileSegment } from '../bmc-cert-service.js';
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

  describe('ceremonies withheld', () => {
    it('offers no enrolment until the profile path captures a trust pin', () => {
      expect('enrollBMC' in service).toBe(false);
    });

    it('offers no factory restore until the server re-pins the regenerated certificate', () => {
      expect('restoreFactoryCert' in service).toBe(false);
    });

    it('sends no request on construction', () => {
      expect(mockClient.post).not.toHaveBeenCalled();
      expect(mockClient.put).not.toHaveBeenCalled();
    });
  });

  // The web-certificate replace rotates no SPKI pin and no TLSA record, so
  // the SDK refuses it by not offering it (#2199).
  describe('web certificate replace', () => {
    it('is not offered until it rotates the pin and the TLSA record', () => {
      expect('replaceWebCertificate' in service).toBe(false);
    });

    it('is wired on the platform client as bmcCert', async () => {
      const { PlatformClient } = await import('../../index.js');
      const client = new PlatformClient({ baseUrl: 'https://api.example.com' });

      expect(client.bmcCert).toBeInstanceOf(BMCCertService);
    });
  });
});

describe('BMC profile ID validation', () => {
  const malformed = ['42/../43', '1e3', '-1', '18446744073709551616', 'abc'];

  for (const id of malformed) {
    it(`refuses profile ID ${JSON.stringify(id)}`, () => {
      expect(() => bmcProfileSegment(id)).toThrow(TypeError);
    });
  }

  it('accepts a decimal ID and the uint64 maximum', () => {
    expect(bmcProfileSegment('42')).toBe('42');
    expect(bmcProfileSegment(42)).toBe('42');
    expect(bmcProfileSegment('18446744073709551615')).toBe('18446744073709551615');
  });

  // A numeric ID past 2^53 has already lost precision before String() runs:
  // 9007199254740993 arrives as 9007199254740992 and would reach another BMC.
  const unsafeNumbers: Array<[string, number]> = [
    ['9007199254740993', Number('9007199254740993')],
    ['MAX_SAFE_INTEGER + 1', Number.MAX_SAFE_INTEGER + 1],
    ['1.5', 1.5],
    ['-1', -1],
    ['NaN', Number.NaN],
  ];

  for (const [label, id] of unsafeNumbers) {
    it(`refuses numeric profile ID ${label}`, () => {
      expect(() => bmcProfileSegment(id)).toThrow(TypeError);
    });
  }

  it('accepts numeric MAX_SAFE_INTEGER and a larger ID as a decimal string', () => {
    expect(bmcProfileSegment(Number.MAX_SAFE_INTEGER)).toBe('9007199254740991');
    expect(bmcProfileSegment('9007199254740993')).toBe('9007199254740993');
  });
});
