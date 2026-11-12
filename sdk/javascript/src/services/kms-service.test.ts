/**
 * Unit tests for KMSService: every public method is driven through a mocked
 * client, asserting the HTTP verb, the path, the query string and the body,
 * plus one error case per method (a client rejection propagates).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { KMSService } from './kms-service.js';
import type { ApiClient } from '../client/api-client.js';
import type {
  DecryptRequest,
  DeleteKeyRequest,
  EncryptRequest,
  ExportKeyRequest,
  GenerateDataKeyRequest,
  GenerateKeyRequest,
  GenerateRandomRequest,
  GenerateWrappedDataKeyRequest,
  GetKeyVersionsRequest,
  HashRequest,
  HMACRequest,
  ImportKeyRequest,
  RotateKeyRequest,
  SignRequest,
  UpdateKeyStatusRequest,
  VerifyHMACRequest,
  VerifyRequest,
} from '../types/kms.js';

type Verb = 'get' | 'post' | 'put' | 'patch' | 'delete';
const VERBS: Verb[] = ['get', 'post', 'put', 'patch', 'delete'];

type MockClient = Record<Verb, ReturnType<typeof vi.fn>>;

function createMockClient(): MockClient {
  return {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
  };
}

describe('KMSService', () => {
  let mock: MockClient;
  let service: KMSService;
  const ok = { success: true, data: { marker: 'kms-response' } };

  beforeEach(() => {
    mock = createMockClient();
    for (const verb of VERBS) {
      mock[verb].mockResolvedValue(ok);
    }
    service = new KMSService(mock as unknown as ApiClient);
  });

  /** Asserts that exactly one call went out, on `verb`, with these arguments. */
  function expectOnlyCall(verb: Verb, ...args: unknown[]): void {
    for (const other of VERBS) {
      if (other !== verb) {
        expect(mock[other]).not.toHaveBeenCalled();
      }
    }
    expect(mock[verb]).toHaveBeenCalledTimes(1);
    expect(mock[verb]).toHaveBeenCalledWith(...args);
  }

  /** Makes `verb` reject and asserts that `call` rejects with the same error. */
  async function expectRejects(verb: Verb, call: () => Promise<unknown>): Promise<void> {
    const err = new Error(`kms ${verb} failed`);
    mock[verb].mockRejectedValue(err);
    await expect(call()).rejects.toBe(err);
    expect(mock[verb]).toHaveBeenCalledTimes(1);
  }

  // ===========================================================================
  // Key management
  // ===========================================================================

  describe('generateKey', () => {
    const req: GenerateKeyRequest = {
      name: 'app-key',
      description: 'application key',
      keySpec: { algorithm: 'AES_256', usage: ['ENCRYPT', 'DECRYPT'], exportable: false },
      tags: { team: 'platform' },
      owner: 'alice',
    };

    it('POSTs the request to /v1/kms/keys and returns the response', async () => {
      await expect(service.generateKey(req)).resolves.toBe(ok);
      expectOnlyCall('post', '/v1/kms/keys', req);
    });

    it('propagates a client error', async () => {
      await expectRejects('post', () => service.generateKey(req));
    });
  });

  describe('importKey', () => {
    const req: ImportKeyRequest = {
      name: 'imported',
      keyMaterial: 'a2V5',
      wrappingKeyId: 'wrap-1',
      keySpec: { algorithm: 'ECDSA_P256', usage: ['SIGN', 'VERIFY'] },
    };

    it('POSTs the request to /v1/kms/keys/import', async () => {
      await expect(service.importKey(req)).resolves.toBe(ok);
      expectOnlyCall('post', '/v1/kms/keys/import', req);
    });

    it('propagates a client error', async () => {
      await expectRejects('post', () => service.importKey(req));
    });
  });

  describe('getKey', () => {
    it('GETs /v1/kms/keys/{id} without a query when no version is given', async () => {
      await expect(service.getKey('key-1')).resolves.toBe(ok);
      expectOnlyCall('get', '/v1/kms/keys/key-1');
    });

    it('adds ?version= when a version is given, including version 0', async () => {
      await service.getKey('key-1', 0);
      expectOnlyCall('get', '/v1/kms/keys/key-1?version=0');
    });

    it('encodes the key id as one path segment', async () => {
      await service.getKey('a/b c', 3);
      expectOnlyCall('get', '/v1/kms/keys/a%2Fb%20c?version=3');
    });

    it('propagates a client error', async () => {
      await expectRejects('get', () => service.getKey('key-1'));
    });
  });

  describe('listKeys', () => {
    it('GETs /v1/kms/keys without a query when no options are given', async () => {
      await expect(service.listKeys()).resolves.toBe(ok);
      expectOnlyCall('get', '/v1/kms/keys');
    });

    it('sends limit and every filter pair as query parameters', async () => {
      await service.listKeys({ limit: 10, filter: { owner: 'alice', state: 'ENABLED' } });
      expectOnlyCall('get', '/v1/kms/keys?limit=10&owner=alice&state=ENABLED');
    });

    it('propagates a client error', async () => {
      await expectRejects('get', () => service.listKeys({ limit: 1 }));
    });
  });

  describe('deleteKey', () => {
    it('DELETEs /v1/kms/keys/{id} without a query when no options are set', async () => {
      const req: DeleteKeyRequest = { keyId: 'key-1' };
      await expect(service.deleteKey(req)).resolves.toBe(ok);
      expectOnlyCall('delete', '/v1/kms/keys/key-1');
    });

    it('sends pendingWindowDays and force as query parameters', async () => {
      const req: DeleteKeyRequest = { keyId: 'key-1', pendingWindowDays: 7, force: false };
      await service.deleteKey(req);
      expectOnlyCall('delete', '/v1/kms/keys/key-1?pendingWindowDays=7&force=false');
    });

    it('propagates a client error', async () => {
      await expectRejects('delete', () => service.deleteKey({ keyId: 'key-1', force: true }));
    });
  });

  describe('rotateKey', () => {
    it('POSTs only retainOldVersion to /v1/kms/keys/{id}/rotate', async () => {
      const req: RotateKeyRequest = { keyId: 'key-1', retainOldVersion: true };
      await expect(service.rotateKey(req)).resolves.toBe(ok);
      expectOnlyCall('post', '/v1/kms/keys/key-1/rotate', { retainOldVersion: true });
    });

    it('propagates a client error', async () => {
      await expectRejects('post', () => service.rotateKey({ keyId: 'key-1' }));
    });
  });

  describe('updateKeyStatus', () => {
    it('PATCHes version and status to /v1/kms/keys/{id}/status', async () => {
      const req: UpdateKeyStatusRequest = { keyId: 'key-1', version: 2, status: 'DISABLED' };
      await expect(service.updateKeyStatus(req)).resolves.toBe(ok);
      expectOnlyCall('patch', '/v1/kms/keys/key-1/status', { version: 2, status: 'DISABLED' });
    });

    it('propagates a client error', async () => {
      await expectRejects('patch', () =>
        service.updateKeyStatus({ keyId: 'key-1', status: 'ENABLED' })
      );
    });
  });

  describe('exportKey', () => {
    it('POSTs the wrapping options without keyId to /v1/kms/keys/{id}/export', async () => {
      const req: ExportKeyRequest = {
        keyId: 'key-1',
        wrappingKeyId: 'wrap-1',
        wrappingAlgorithm: 'RSA_OAEP_SHA256',
        format: 'PKCS8',
        version: 4,
      };
      await expect(service.exportKey(req)).resolves.toBe(ok);
      expectOnlyCall('post', '/v1/kms/keys/key-1/export', {
        wrappingKeyId: 'wrap-1',
        wrappingAlgorithm: 'RSA_OAEP_SHA256',
        format: 'PKCS8',
        version: 4,
      });
    });

    it('propagates a client error', async () => {
      await expectRejects('post', () => service.exportKey({ keyId: 'key-1' }));
    });
  });

  describe('getKeyVersions', () => {
    it('GETs /v1/kms/keys/{id}/versions with the limit as a query parameter', async () => {
      const req: GetKeyVersionsRequest = { keyId: 'key-1', limit: 5 };
      await expect(service.getKeyVersions(req)).resolves.toBe(ok);
      expectOnlyCall('get', '/v1/kms/keys/key-1/versions?limit=5');
    });

    it('omits the query when no limit is given', async () => {
      await service.getKeyVersions({ keyId: 'key-1' });
      expectOnlyCall('get', '/v1/kms/keys/key-1/versions');
    });

    it('propagates a client error', async () => {
      await expectRejects('get', () => service.getKeyVersions({ keyId: 'key-1' }));
    });
  });

  // ===========================================================================
  // Cryptographic operations and key-generation helpers: each POSTs its
  // request unchanged to a fixed path.
  // ===========================================================================

  const encryptReq: EncryptRequest = { keyId: 'key-1', plaintext: 'cGxhaW4=', context: 'YWFk' };
  const decryptReq: DecryptRequest = { keyId: 'key-1', ciphertext: 'Y2lwaGVy', keyVersion: 2 };
  const signReq: SignRequest = { keyId: 'key-1', message: 'bXNn', hashAlgorithm: 'SHA256' };
  const verifyReq: VerifyRequest = {
    keyId: 'key-1',
    message: 'bXNn',
    signature: 'c2ln',
    hashAlgorithm: 'SHA384',
    keyVersion: 1,
  };
  const hashReq: HashRequest = { data: 'ZGF0YQ==', algorithm: 'SHA3_256' };
  const hmacReq: HMACRequest = { keyId: 'hmac-1', message: 'bXNn', hashAlgorithm: 'SHA512' };
  const verifyHmacReq: VerifyHMACRequest = { keyId: 'hmac-1', message: 'bXNn', hmac: 'bWFj' };
  const randomReq: GenerateRandomRequest = { numBytes: 32 };
  const dataKeyReq: GenerateDataKeyRequest = { keyId: 'kek-1', algorithm: 'AES_256', keySize: 256 };
  const wrappedDataKeyReq: GenerateWrappedDataKeyRequest = {
    wrappingKeyId: 'wrap-1',
    wrappingAlgorithm: 'AES_KWP',
    keyAlgorithm: 'AES_128',
    keySize: 128,
  };

  const postCases: Array<{ method: string; path: string; body: unknown; call: () => Promise<unknown> }> = [
    { method: 'encrypt', path: '/v1/kms/encrypt', body: encryptReq, call: () => service.encrypt(encryptReq) },
    { method: 'decrypt', path: '/v1/kms/decrypt', body: decryptReq, call: () => service.decrypt(decryptReq) },
    { method: 'sign', path: '/v1/kms/sign', body: signReq, call: () => service.sign(signReq) },
    { method: 'verify', path: '/v1/kms/verify', body: verifyReq, call: () => service.verify(verifyReq) },
    { method: 'hash', path: '/v1/kms/hash', body: hashReq, call: () => service.hash(hashReq) },
    { method: 'hmac', path: '/v1/kms/hmac', body: hmacReq, call: () => service.hmac(hmacReq) },
    {
      method: 'verifyHMAC',
      path: '/v1/kms/hmac/verify',
      body: verifyHmacReq,
      call: () => service.verifyHMAC(verifyHmacReq),
    },
    {
      method: 'generateRandom',
      path: '/v1/kms/random',
      body: randomReq,
      call: () => service.generateRandom(randomReq),
    },
    {
      method: 'generateDataKey',
      path: '/v1/kms/datakey',
      body: dataKeyReq,
      call: () => service.generateDataKey(dataKeyReq),
    },
    {
      method: 'generateWrappedDataKey',
      path: '/v1/kms/datakey/wrapped',
      body: wrappedDataKeyReq,
      call: () => service.generateWrappedDataKey(wrappedDataKeyReq),
    },
  ];

  for (const c of postCases) {
    describe(c.method, () => {
      it(`POSTs the request unchanged to ${c.path} with no query`, async () => {
        await expect(c.call()).resolves.toBe(ok);
        expectOnlyCall('post', c.path, c.body);
      });

      it('propagates a client error', async () => {
        await expectRejects('post', c.call);
      });
    });
  }

  // ===========================================================================
  // Backend operations
  // ===========================================================================

  describe('getBackendStatus', () => {
    it('GETs /v1/kms/backend/status with no query', async () => {
      await expect(service.getBackendStatus()).resolves.toBe(ok);
      expectOnlyCall('get', '/v1/kms/backend/status');
    });

    it('propagates a client error', async () => {
      await expectRejects('get', () => service.getBackendStatus());
    });
  });
});
