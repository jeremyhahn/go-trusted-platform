/**
 * Unit tests for the TPM service: every public method against a mocked
 * transport, pinning the HTTP verb, the path, the query string and the body
 * it sends, and that a transport failure reaches the caller unchanged.
 *
 * The PCR bank translation of `getPCRs` has its own file
 * (`__tests__/tpm-service-pcr-bank.test.ts`); here it is covered only as one
 * call among the others.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { TPMService, TPM_BASE_PATH } from './tpm-service.js';
import type { ApiClient } from '../client/api-client.js';

type Verb = 'get' | 'post' | 'put' | 'delete';

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
    baseUrl: 'http://localhost',
  } as unknown as ApiClient;
}

interface CallCase {
  /** Public method under test. */
  name: string;
  /** Calls the method on the service. */
  invoke: (service: TPMService) => Promise<unknown>;
  /** Transport verb the method must use. */
  verb: Verb;
  /** Full URL (path and query) the method must request. */
  url: string;
  /** Body the method must send; omitted for verbs that carry none. */
  body?: unknown;
  /** Request options the method must pass as the third transport argument. */
  options?: unknown;
}

const cases: CallCase[] = [
  {
    name: 'getInfo',
    invoke: (s) => s.getInfo(),
    verb: 'get',
    url: '/v1/tpm/info',
  },
  {
    name: 'provision',
    invoke: (s) => s.provision({ ownerPassword: 'owner', createEk: true, createSrk: false }),
    verb: 'post',
    url: '/v1/tpm/provision',
    body: { ownerPassword: 'owner', createEk: true, createSrk: false },
  },
  {
    name: 'clear',
    invoke: (s) => s.clear({ ownerPassword: 'owner', confirm: true }),
    verb: 'post',
    url: '/v1/tpm/clear',
    body: { ownerPassword: 'owner', confirm: true },
  },
  {
    name: 'createEK',
    invoke: (s) => s.createEK({ persistent: true }),
    verb: 'post',
    url: '/v1/tpm/ek',
    body: { persistent: true },
  },
  {
    name: 'getEK',
    invoke: (s) => s.getEK({ algorithm: 'RSA_2048', handle: 0x81010001 }),
    verb: 'get',
    url: '/v1/tpm/ek?algorithm=RSA_2048&handle=2164326401',
  },
  {
    name: 'getEKCertificate',
    invoke: (s) => s.getEKCertificate({ algorithm: 'RSA_2048', handle: 7 }),
    verb: 'get',
    url: '/v1/tpm/ek/certificate?algorithm=RSA_2048&handle=7',
  },
  {
    name: 'importEKCertificate',
    invoke: (s) => s.importEKCertificate({ certificate: 'Y2VydA==', format: 'DER', nvramIndex: 5 }),
    verb: 'post',
    url: '/v1/tpm/ek/certificate',
    body: { certificate: 'Y2VydA==', format: 'DER', nvramIndex: 5 },
  },
  {
    name: 'deleteEK',
    invoke: (s) => s.deleteEK({ handle: 0x81010001 }),
    verb: 'delete',
    url: '/v1/tpm/ek/2164326401',
  },
  {
    name: 'createSRK',
    invoke: (s) => s.createSRK({ parentHandle: 1, parentPassword: 'p' }),
    verb: 'post',
    url: '/v1/tpm/srk',
    body: { parentHandle: 1, parentPassword: 'p' },
  },
  {
    name: 'getSRK',
    invoke: (s) => s.getSRK({ handle: 0x81000001 }),
    verb: 'get',
    url: '/v1/tpm/srk?handle=2164260865',
  },
  {
    name: 'deleteSRK',
    invoke: (s) => s.deleteSRK({ handle: 0x81000001 }),
    verb: 'delete',
    url: '/v1/tpm/srk/2164260865',
  },
  {
    name: 'createAK',
    invoke: (s) => s.createAK({ persistent: false, parentHandle: 2 }),
    verb: 'post',
    url: '/v1/tpm/ak',
    body: { persistent: false, parentHandle: 2 },
  },
  {
    name: 'getAK',
    invoke: (s) => s.getAK({ algorithm: 'RSA_2048' }),
    verb: 'get',
    url: '/v1/tpm/ak?algorithm=RSA_2048',
  },
  {
    name: 'deleteAK',
    invoke: (s) => s.deleteAK({ handle: 0x81010002 }),
    verb: 'delete',
    url: '/v1/tpm/ak/2164326402',
  },
  {
    name: 'seal',
    invoke: (s) => s.seal({ data: 'c2VjcmV0', cn: 'disk-key', pcrIndices: [0, 7], pcrBank: 'SHA256' }),
    verb: 'post',
    url: '/v1/tpm/seal',
    body: { data: 'c2VjcmV0', cn: 'disk-key', pcrIndices: [0, 7], pcrBank: 'SHA256' },
  },
  {
    name: 'unseal',
    invoke: (s) => s.unseal({ cn: 'disk-key', password: 'pw' }),
    verb: 'post',
    url: '/v1/tpm/unseal',
    body: { cn: 'disk-key', password: 'pw' },
  },
  {
    name: 'quote',
    invoke: (s) => s.quote({ akHandle: 3, pcrIndices: [0, 1, 2], nonce: 'bm9uY2U=' }),
    verb: 'post',
    url: '/v1/tpm/quote',
    body: { akHandle: 3, pcrIndices: [0, 1, 2], nonce: 'bm9uY2U=' },
  },
  {
    name: 'verifyQuote',
    invoke: (s) =>
      s.verifyQuote({
        quote: 'cQ==',
        signature: 'cw==',
        nonce: 'bg==',
        signatureAlgorithm: 'SHA256-RSAPSS',
      }),
    verb: 'post',
    url: '/v1/tpm/quote/verify',
    body: { quote: 'cQ==', signature: 'cw==', nonce: 'bg==', signatureAlgorithm: 'SHA256-RSAPSS' },
  },
  {
    name: 'getEventLog',
    invoke: (s) => s.getEventLog({ format: 'text' }),
    verb: 'get',
    url: '/v1/tpm/eventlog?format=text',
  },
  {
    name: 'getPCRs',
    invoke: (s) => s.getPCRs({ indices: [0, 7], bank: 'SHA256' }),
    verb: 'post',
    url: '/v1/tpm/pcrs',
    body: { indices: [0, 7], bank: 'PCR_BANK_SHA256' },
  },
  {
    name: 'defineNVRAM',
    invoke: (s) => s.defineNVRAM({ index: 0x1500016, size: 32, attributes: ['OWNERWRITE'] }),
    verb: 'post',
    url: '/v1/tpm/nvram',
    body: { index: 0x1500016, size: 32, attributes: ['OWNERWRITE'] },
  },
  {
    name: 'writeNVRAM',
    invoke: (s) => s.writeNVRAM({ index: 22020118, data: 'ZGF0YQ==', password: 'pw', offset: 4 }),
    verb: 'put',
    url: '/v1/tpm/nvram/22020118',
    body: { data: 'ZGF0YQ==', password: 'pw', offset: 4 },
  },
  {
    name: 'readNVRAM',
    invoke: (s) => s.readNVRAM({ index: 22020118, offset: 4, size: 16 }),
    verb: 'get',
    url: '/v1/tpm/nvram/22020118?offset=4&size=16',
  },
  {
    name: 'undefineNVRAM',
    invoke: (s) => s.undefineNVRAM({ index: 22020118 }),
    verb: 'delete',
    url: '/v1/tpm/nvram/22020118',
  },
  {
    name: 'getRandom',
    invoke: (s) => s.getRandom({ numBytes: 32 }),
    verb: 'post',
    url: '/v1/tpm/random',
    body: { numBytes: 32 },
  },
  {
    name: 'extendPCR',
    invoke: (s) => s.extendPCR({ index: 16, hashAlg: 'SHA256', data: 'ZXh0ZW5k' }),
    verb: 'post',
    url: '/v1/tpm/pcrs/extend',
    body: { index: 16, hashAlg: 'sha256', data: 'ZXh0ZW5k' },
    // A retried extend would extend the PCR twice, so retries must be off.
    options: { retry: { enabled: false } },
  },
  {
    name: 'makeCredential',
    invoke: (s) => s.makeCredential({ akName: 'YWtuYW1l', secret: 'c2VjcmV0', ekCert: 'ZWtjZXJ0' }),
    verb: 'post',
    url: '/v1/tpm/make-credential',
    body: { akName: 'YWtuYW1l', secret: 'c2VjcmV0', ekCert: 'ZWtjZXJ0' },
  },
  {
    name: 'activateCredential',
    invoke: (s) => s.activateCredential({ credentialBlob: 'YmxvYg==', encryptedSecret: 'ZW5j' }),
    verb: 'post',
    url: '/v1/tpm/activate-credential',
    body: { credentialBlob: 'YmxvYg==', encryptedSecret: 'ZW5j' },
  },
];

const VERBS: Verb[] = ['get', 'post', 'put', 'delete'];

describe('TPMService', () => {
  let service: TPMService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    for (const verb of VERBS) {
      vi.mocked(mockClient[verb]).mockResolvedValue({ success: true, data: { ok: verb } });
    }
    service = new TPMService(mockClient);
  });

  it('uses /v1/tpm as its base path', () => {
    expect(TPM_BASE_PATH).toBe('/v1/tpm');
  });

  it('covers every public method of the service', () => {
    const methods = Object.getOwnPropertyNames(TPMService.prototype)
      .filter((name) => name !== 'constructor')
      .sort();
    expect(cases.map((c) => c.name).sort()).toEqual(methods);
  });

  describe.each(cases)('$name', ({ invoke, verb, url, body, options }) => {
    it(`sends ${verb.toUpperCase()} to the expected path, query and body`, async () => {
      await invoke(service);

      const calls = vi.mocked(mockClient[verb]).mock.calls;
      expect(calls).toHaveLength(1);
      if (options !== undefined) {
        expect(mockClient[verb]).toHaveBeenCalledWith(url, body, options);
      } else if (body === undefined) {
        expect(calls[0]).toEqual([url]);
      } else {
        expect(calls[0]).toEqual([url, body]);
      }
      for (const other of VERBS.filter((v) => v !== verb)) {
        expect(mockClient[other]).not.toHaveBeenCalled();
      }
    });

    it('returns the transport response unchanged', async () => {
      await expect(invoke(service)).resolves.toEqual({ success: true, data: { ok: verb } });
    });

    it('rejects with the transport error', async () => {
      const failure = new Error(`${verb} failed`);
      vi.mocked(mockClient[verb]).mockRejectedValue(failure);

      await expect(invoke(service)).rejects.toBe(failure);
    });
  });

  describe('optional requests', () => {
    it('createEK, createSRK and createAK post an empty body without a request', async () => {
      await service.createEK();
      await service.createSRK();
      await service.createAK();

      expect(vi.mocked(mockClient.post).mock.calls).toEqual([
        ['/v1/tpm/ek', {}],
        ['/v1/tpm/srk', {}],
        ['/v1/tpm/ak', {}],
      ]);
    });

    it('getEK, getEKCertificate, getSRK, getAK and getEventLog send no query without a request', async () => {
      await service.getEK();
      await service.getEKCertificate();
      await service.getSRK();
      await service.getAK();
      await service.getEventLog();

      expect(vi.mocked(mockClient.get).mock.calls).toEqual([
        ['/v1/tpm/ek'],
        ['/v1/tpm/ek/certificate'],
        ['/v1/tpm/srk'],
        ['/v1/tpm/ak'],
        ['/v1/tpm/eventlog'],
      ]);
    });

    it('readNVRAM sends no query when neither offset nor size is set', async () => {
      await service.readNVRAM({ index: 1 });

      expect(vi.mocked(mockClient.get).mock.calls).toEqual([['/v1/tpm/nvram/1']]);
    });

    it('readNVRAM keeps an offset of zero in the query', async () => {
      await service.readNVRAM({ index: 1, offset: 0 });

      expect(vi.mocked(mockClient.get).mock.calls).toEqual([['/v1/tpm/nvram/1?offset=0']]);
    });

    it('getEK keeps a handle of zero in the query', async () => {
      await service.getEK({ handle: 0 });

      expect(vi.mocked(mockClient.get).mock.calls).toEqual([['/v1/tpm/ek?handle=0']]);
    });
  });

  it('writeNVRAM moves the index into the path and leaves it out of the body', async () => {
    await service.writeNVRAM({ index: 9, data: 'eA==' });

    expect(vi.mocked(mockClient.put).mock.calls).toEqual([
      ['/v1/tpm/nvram/9', { data: 'eA==', password: undefined, offset: undefined }],
    ]);
  });
});
