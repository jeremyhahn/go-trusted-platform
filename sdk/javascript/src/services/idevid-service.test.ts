/**
 * Unit tests for the IDevID / IAK service client.
 *
 * Each method is pinned to its verb, its path under /v1/idevid, the absence
 * of a query string, and the exact body handed to the transport. Each method
 * also gets an error case: a transport rejection propagates to the caller,
 * and an error response is returned unchanged.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { IDevIDService } from './idevid-service.js';
import type { ApiClient } from '../client/api-client.js';

type Verb = 'get' | 'post' | 'delete';

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

interface Case {
  /** Method under test */
  name: string;
  /** Transport verb the method must use */
  verb: Verb;
  /** Full path the method must request */
  path: string;
  /** Invokes the method with its test arguments */
  call: (s: IDevIDService) => Promise<unknown>;
  /** Exact transport arguments after the path (the body, for POST) */
  rest: unknown[];
}

const certPem = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n';

const cases: Case[] = [
  {
    name: 'generateIDevID',
    verb: 'post',
    path: '/v1/idevid/generate',
    call: (s) =>
      s.generateIDevID({ config: { hierarchy: 'endorsement', subjectCommonName: 'device-001', overwrite: true } }),
    rest: [{ config: { hierarchy: 'endorsement', subjectCommonName: 'device-001', overwrite: true } }],
  },
  {
    name: 'getIDevIDInfo',
    verb: 'get',
    path: '/v1/idevid/info',
    call: (s) => s.getIDevIDInfo(),
    rest: [],
  },
  {
    name: 'hasIDevID',
    verb: 'get',
    path: '/v1/idevid/exists',
    call: (s) => s.hasIDevID(),
    rest: [],
  },
  {
    name: 'deleteIDevID',
    verb: 'delete',
    path: '/v1/idevid',
    call: (s) => s.deleteIDevID(),
    rest: [],
  },
  {
    name: 'createIDevIDCSR',
    verb: 'post',
    path: '/v1/idevid/csr',
    call: (s) => s.createIDevIDCSR({ template: { commonName: 'device-001', organization: 'Acme' } }),
    rest: [{ template: { commonName: 'device-001', organization: 'Acme' } }],
  },
  {
    name: 'installIDevIDCertificate',
    verb: 'post',
    path: '/v1/idevid/certificate',
    call: (s) => s.installIDevIDCertificate({ certificatePem: certPem }),
    rest: [{ certificatePem: certPem }],
  },
  {
    name: 'getIDevIDCertificate',
    verb: 'get',
    path: '/v1/idevid/certificate',
    call: (s) => s.getIDevIDCertificate(),
    rest: [],
  },
  {
    name: 'deleteIDevIDCertificate',
    verb: 'delete',
    path: '/v1/idevid/certificate',
    call: (s) => s.deleteIDevIDCertificate(),
    rest: [],
  },
  {
    name: 'generateIAK',
    verb: 'post',
    path: '/v1/idevid/iak/generate',
    call: (s) => s.generateIAK({ config: { hierarchy: 'endorsement', handle: 0x81010003 } }),
    rest: [{ config: { hierarchy: 'endorsement', handle: 0x81010003 } }],
  },
  {
    name: 'getIAKInfo',
    verb: 'get',
    path: '/v1/idevid/iak',
    call: (s) => s.getIAKInfo(),
    rest: [],
  },
  {
    name: 'hasIAK',
    verb: 'get',
    path: '/v1/idevid/iak/exists',
    call: (s) => s.hasIAK(),
    rest: [],
  },
  {
    name: 'deleteIAK',
    verb: 'delete',
    path: '/v1/idevid/iak',
    call: (s) => s.deleteIAK(),
    rest: [],
  },
  {
    name: 'createIAKCSR',
    verb: 'post',
    path: '/v1/idevid/iak/csr',
    call: (s) => s.createIAKCSR({ template: { commonName: 'iak-001', dnsNames: ['device-001'] } }),
    rest: [{ template: { commonName: 'iak-001', dnsNames: ['device-001'] } }],
  },
  {
    name: 'installIAKCertificate',
    verb: 'post',
    path: '/v1/idevid/iak/certificate',
    call: (s) => s.installIAKCertificate({ certificatePem: certPem }),
    rest: [{ certificatePem: certPem }],
  },
  {
    name: 'getIAKCertificate',
    verb: 'get',
    path: '/v1/idevid/iak/certificate',
    call: (s) => s.getIAKCertificate(),
    rest: [],
  },
  {
    name: 'deleteIAKCertificate',
    verb: 'delete',
    path: '/v1/idevid/iak/certificate',
    call: (s) => s.deleteIAKCertificate(),
    rest: [],
  },
  {
    name: 'getDeviceAttributes',
    verb: 'get',
    path: '/v1/idevid/attributes',
    call: (s) => s.getDeviceAttributes(),
    rest: [],
  },
  {
    name: 'flushTransientContexts',
    verb: 'post',
    path: '/v1/idevid/flush',
    call: (s) => s.flushTransientContexts(),
    rest: [{}],
  },
  {
    name: 'activateCredential',
    verb: 'post',
    path: '/v1/idevid/activate-credential',
    call: (s) => s.activateCredential({ credentialBlob: 'Y3JlZA==', secret: 'c2VjcmV0' }),
    rest: [{ credentialBlob: 'Y3JlZA==', secret: 'c2VjcmV0' }],
  },
];

const verbs: Verb[] = ['get', 'post', 'delete'];

describe('IDevIDService', () => {
  let service: IDevIDService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new IDevIDService(mockClient);
  });

  it('covers every public method of the service', () => {
    const proto = IDevIDService.prototype as unknown as Record<string, unknown>;
    const methods = Object.getOwnPropertyNames(IDevIDService.prototype)
      .filter((n) => n !== 'constructor' && typeof proto[n] === 'function')
      .sort();
    expect(cases.map((c) => c.name).sort()).toEqual(methods);
  });

  describe.each(cases)('$name', (c) => {
    it(`sends ${c.verb.toUpperCase()} ${c.path} with no query and the exact body`, async () => {
      const data = { ok: true };
      vi.mocked(mockClient[c.verb]).mockResolvedValue({ success: true, data });

      const result = await c.call(service);

      expect(result).toEqual({ success: true, data });
      expect(mockClient[c.verb]).toHaveBeenCalledTimes(1);
      const args = vi.mocked(mockClient[c.verb]).mock.calls[0] as unknown[];
      expect(args).toEqual([c.path, ...c.rest]);
      expect(String(args[0])).not.toContain('?');
      for (const other of verbs.filter((v) => v !== c.verb)) {
        expect(mockClient[other]).not.toHaveBeenCalled();
      }
    });

    it('propagates a transport rejection', async () => {
      vi.mocked(mockClient[c.verb]).mockRejectedValue(new Error('tpm unavailable'));

      await expect(c.call(service)).rejects.toThrow('tpm unavailable');
    });

    it('returns an error response unchanged', async () => {
      const failure = { success: false, error: { code: 'NOT_FOUND', message: 'no key' } };
      vi.mocked(mockClient[c.verb]).mockResolvedValue(failure);

      await expect(c.call(service)).resolves.toEqual(failure);
    });
  });

  describe('optional request bodies', () => {
    it.each([
      ['generateIDevID', '/v1/idevid/generate', (s: IDevIDService) => s.generateIDevID()],
      ['createIDevIDCSR', '/v1/idevid/csr', (s: IDevIDService) => s.createIDevIDCSR()],
      ['generateIAK', '/v1/idevid/iak/generate', (s: IDevIDService) => s.generateIAK()],
      ['createIAKCSR', '/v1/idevid/iak/csr', (s: IDevIDService) => s.createIAKCSR()],
    ] as const)('%s posts an empty object when called without a request', async (_name, path, call) => {
      vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: {} });

      await call(service);

      expect(mockClient.post).toHaveBeenCalledWith(path, {});
    });
  });
});
