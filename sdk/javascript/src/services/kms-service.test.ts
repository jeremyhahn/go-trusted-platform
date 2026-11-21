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

    it('POSTs the server ImportKeyRequest wire body to /v1/kms/keys/import', async () => {
      await expect(service.importKey(req)).resolves.toBe(ok);
      expectOnlyCall('post', '/v1/kms/keys/import', {
        name: 'imported',
        algorithm: 'ECDSA_P256',
        key_material: 'a2V5',
        wrapping_key_id: 'wrap-1',
        usage: ['SIGN', 'VERIFY'],
      });
    });

    it('sends description and tags when they are set', async () => {
      await service.importKey({
        name: 'imported',
        keyMaterial: 'a2V5',
        keySpec: { algorithm: 'ECDSA_P256', usage: ['SIGN', 'VERIFY'] },
        description: 'd',
        tags: { env: 'dev' },
      });
      expectOnlyCall('post', '/v1/kms/keys/import', {
        name: 'imported',
        algorithm: 'ECDSA_P256',
        key_material: 'a2V5',
        usage: ['SIGN', 'VERIFY'],
        description: 'd',
        tags: { env: 'dev' },
      });
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
    it('PUTs version and status to /v1/kms/keys/{id}/status, as the REST router serves', async () => {
      const req: UpdateKeyStatusRequest = { keyId: 'key-1', version: 2, status: 'DISABLED' };
      await expect(service.updateKeyStatus(req)).resolves.toBe(ok);
      expectOnlyCall('put', '/v1/kms/keys/key-1/status', { version: 2, status: 'DISABLED' });
    });

    it('propagates a client error', async () => {
      await expectRejects('put', () =>
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
  const signReq: SignRequest = {
    keyId: 'key-1',
    message: 'bXNn',
    hashAlgorithm: 'SHA256',
    keyVersion: 3,
    preHashed: true,
  };
  const verifyReq: VerifyRequest = {
    keyId: 'key-1',
    message: 'bXNn',
    signature: 'c2ln',
    hashAlgorithm: 'SHA384',
    keyVersion: 1,
  };

  describe('hmac', () => {
    const req: HMACRequest = { keyId: 'hmac-1', message: 'bXNn', hashAlgorithm: 'SHA512' };

    it('POSTs { data, hash } to /v1/kms/hmac/{name}', async () => {
      await expect(service.hmac(req)).resolves.toBe(ok);
      expectOnlyCall('post', '/v1/kms/hmac/hmac-1', { data: 'bXNn', hash: 'SHA512' });
    });

    it('encodes the key name as one path segment and omits an unset hash', async () => {
      await service.hmac({ keyId: 'a/b', message: 'bXNn' });
      expectOnlyCall('post', '/v1/kms/hmac/a%2Fb', { data: 'bXNn' });
    });

    it('propagates a client error', async () => {
      await expectRejects('post', () => service.hmac(req));
    });
  });

  describe('verifyHMAC', () => {
    const req: VerifyHMACRequest = { keyId: 'hmac-1', message: 'bXNn', hmac: 'bWFj', hashAlgorithm: 'SHA256' };

    it('POSTs { data, hmac, hash } to /v1/kms/hmac/{name}/verify', async () => {
      await expect(service.verifyHMAC(req)).resolves.toBe(ok);
      expectOnlyCall('post', '/v1/kms/hmac/hmac-1/verify', { data: 'bXNn', hmac: 'bWFj', hash: 'SHA256' });
    });

    it('propagates a client error', async () => {
      await expectRejects('post', () => service.verifyHMAC(req));
    });
  });

  describe('hash', () => {
    const req: HashRequest = { data: 'ZGF0YQ==', algorithm: 'SHA3_256' };

    it('POSTs { data, hash } to /v1/kms/hash', async () => {
      await expect(service.hash(req)).resolves.toBe(ok);
      expectOnlyCall('post', '/v1/kms/hash', { data: 'ZGF0YQ==', hash: 'SHA3_256' });
    });

    it('propagates a client error', async () => {
      await expectRejects('post', () => service.hash(req));
    });
  });

  describe('generateRandom', () => {
    const req: GenerateRandomRequest = { numBytes: 32 };

    it('POSTs { num_bytes } to /v1/kms/random', async () => {
      await expect(service.generateRandom(req)).resolves.toBe(ok);
      expectOnlyCall('post', '/v1/kms/random', { num_bytes: 32 });
    });

    it('propagates a client error', async () => {
      await expectRejects('post', () => service.generateRandom(req));
    });
  });

  describe('generateDataKey', () => {
    const req: GenerateDataKeyRequest = { keyId: 'kek-1', algorithm: 'AES_256', keySize: 256, context: 'Y3R4' };

    it('POSTs { key_id, algorithm, key_size, context } to /v1/kms/data-keys', async () => {
      await expect(service.generateDataKey(req)).resolves.toBe(ok);
      expectOnlyCall('post', '/v1/kms/data-keys', {
        key_id: 'kek-1',
        algorithm: 'AES_256',
        key_size: 256,
        context: 'Y3R4',
      });
    });

    it('propagates a client error', async () => {
      await expectRejects('post', () => service.generateDataKey(req));
    });
  });

  describe('generateWrappedDataKey', () => {
    const req: GenerateWrappedDataKeyRequest = { wrappingKeyId: 'wrap-1', keyAlgorithm: 'AES_128', keySize: 128 };

    it('POSTs { wrapping_key_id, key_algorithm, key_size } to /v1/kms/data-keys/wrapped', async () => {
      await expect(service.generateWrappedDataKey(req)).resolves.toBe(ok);
      expectOnlyCall('post', '/v1/kms/data-keys/wrapped', {
        wrapping_key_id: 'wrap-1',
        key_algorithm: 'AES_128',
        key_size: 128,
      });
      const body = mock.post.mock.calls[0]?.[1] as Record<string, unknown>;
      expect(Object.keys(body).sort()).toEqual(['key_algorithm', 'key_size', 'wrapping_key_id']);
    });

    it('propagates a client error', async () => {
      await expectRejects('post', () => service.generateWrappedDataKey(req));
    });
  });

  const postCases: Array<{ method: string; path: string; body: unknown; call: () => Promise<unknown> }> = [
    {
      method: 'encrypt',
      path: '/v1/kms/encrypt/key-1',
      body: { plaintext: 'cGxhaW4=', context: 'YWFk' },
      call: () => service.encrypt(encryptReq),
    },
    {
      method: 'decrypt',
      path: '/v1/kms/decrypt/key-1',
      body: { ciphertext: 'Y2lwaGVy', version: 2 },
      call: () => service.decrypt(decryptReq),
    },
    {
      method: 'sign',
      path: '/v1/kms/sign/key-1',
      body: { data: 'bXNn', hash: 'SHA256', version: 3, pre_hashed: true },
      call: () => service.sign(signReq),
    },
    {
      method: 'verify',
      path: '/v1/kms/verify/key-1',
      body: { data: 'bXNn', signature: 'c2ln', hash: 'SHA384', version: 1 },
      call: () => service.verify(verifyReq),
    },
    {
      method: 'encrypt',
      path: '/v1/kms/encrypt/a%2Fb',
      body: { plaintext: 'cGxhaW4=' },
      call: () => service.encrypt({ keyId: 'a/b', plaintext: 'cGxhaW4=' }),
    },
  ];

  for (const c of postCases) {
    describe(c.method, () => {
      it(`POSTs the server's wire body to ${c.path}, as the REST router serves`, async () => {
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
