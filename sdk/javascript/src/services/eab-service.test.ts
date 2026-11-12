/**
 * EABService wire tests: each public method sends the expected HTTP method,
 * path, query and body through a mocked transport, and passes a transport
 * failure through to the caller.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { EABService } from './eab-service.js';
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

/** The single call made on the transport: which verb, and its arguments. */
function onlyCall(client: ApiClient): { verb: Verb; path: string; query: URLSearchParams; body: unknown; argc: number } {
  const verbs: Verb[] = ['get', 'post', 'delete'];
  const made = verbs.filter((v) => vi.mocked(client[v]).mock.calls.length > 0);
  expect(made).toHaveLength(1);
  const verb = made[0] as Verb;
  const calls = vi.mocked(client[verb]).mock.calls;
  expect(calls).toHaveLength(1);
  const args = calls[0] as unknown[];
  const [path, query = ''] = String(args[0]).split('?', 2);
  return { verb, path: path ?? '', query: new URLSearchParams(query), body: args[1], argc: args.length };
}

describe('EABService', () => {
  let client: ApiClient;
  let service: EABService;
  const ok = { success: true, data: { ok: true } };

  beforeEach(() => {
    client = createMockApiClient();
    for (const v of ['get', 'post', 'delete'] as Verb[]) {
      vi.mocked(client[v]).mockResolvedValue(ok);
    }
    service = new EABService(client);
  });

  function failNext(verb: Verb): Error {
    const err = new Error(`${verb} failed`);
    vi.mocked(client[verb]).mockRejectedValueOnce(err);
    return err;
  }

  describe('create', () => {
    it('posts the request to /v1/eab/credentials with no query', async () => {
      const request = { profileId: 3, tenantId: 'tenant-a', description: 'lab' };
      const res = await service.create(request as never);
      const call = onlyCall(client);
      expect(call.verb).toBe('post');
      expect(call.path).toBe('/v1/eab/credentials');
      expect([...call.query.keys()]).toEqual([]);
      expect(call.body).toEqual(request);
      expect(res).toBe(ok);
    });

    it('passes a transport failure through', async () => {
      const err = failNext('post');
      await expect(service.create({} as never)).rejects.toBe(err);
    });
  });

  describe('get', () => {
    it('gets /v1/eab/credentials/{id} with no query and no body', async () => {
      const res = await service.get(42);
      const call = onlyCall(client);
      expect(call.verb).toBe('get');
      expect(call.path).toBe('/v1/eab/credentials/42');
      expect([...call.query.keys()]).toEqual([]);
      expect(call.argc).toBe(1);
      expect(res).toBe(ok);
    });

    it('passes a transport failure through', async () => {
      const err = failNext('get');
      await expect(service.get(1)).rejects.toBe(err);
    });
  });

  describe('getByKeyId', () => {
    it('gets /v1/eab/credentials/key/{keyId} with no query and no body', async () => {
      await service.getByKeyId('kid-1');
      const call = onlyCall(client);
      expect(call.verb).toBe('get');
      expect(call.path).toBe('/v1/eab/credentials/key/kid-1');
      expect([...call.query.keys()]).toEqual([]);
      expect(call.argc).toBe(1);
    });

    it('encodes a key id that holds path separators', async () => {
      await service.getByKeyId('a/b?c');
      const call = onlyCall(client);
      expect(call.path).toBe('/v1/eab/credentials/key/a%2Fb%3Fc');
      expect([...call.query.keys()]).toEqual([]);
    });

    it('passes a transport failure through', async () => {
      const err = failNext('get');
      await expect(service.getByKeyId('kid-1')).rejects.toBe(err);
    });
  });

  describe('list', () => {
    it('gets /v1/eab/credentials with no query when called without a request', async () => {
      await service.list();
      const call = onlyCall(client);
      expect(call.verb).toBe('get');
      expect(call.path).toBe('/v1/eab/credentials');
      expect([...call.query.keys()]).toEqual([]);
      expect(call.argc).toBe(1);
    });

    it('sends paging and every filter in the query', async () => {
      await service.list({ page: 2, pageSize: 25, profileId: 7, tenantId: 'tenant-a', status: 'active' } as never);
      const call = onlyCall(client);
      expect(call.verb).toBe('get');
      expect(call.path).toBe('/v1/eab/credentials');
      expect(Object.fromEntries(call.query)).toEqual({
        page: '2',
        limit: '25',
        profileId: '7',
        tenantId: 'tenant-a',
        status: 'active',
      });
      expect(call.argc).toBe(1);
    });

    it('leaves unset filters out of the query', async () => {
      await service.list({ status: 'revoked' } as never);
      expect(Object.fromEntries(onlyCall(client).query)).toEqual({ status: 'revoked' });
    });

    it('passes a transport failure through', async () => {
      const err = failNext('get');
      await expect(service.list()).rejects.toBe(err);
    });
  });

  describe('revoke', () => {
    it('posts an empty body to /v1/eab/credentials/{id}/revoke', async () => {
      const res = await service.revoke(9);
      const call = onlyCall(client);
      expect(call.verb).toBe('post');
      expect(call.path).toBe('/v1/eab/credentials/9/revoke');
      expect([...call.query.keys()]).toEqual([]);
      expect(call.body).toEqual({});
      expect(res).toBe(ok);
    });

    it('passes a transport failure through', async () => {
      const err = failNext('post');
      await expect(service.revoke(9)).rejects.toBe(err);
    });
  });

  describe('validate', () => {
    it('posts the request to /v1/eab/credentials/validate', async () => {
      const request = { keyId: 'kid-1', hmacKey: 'c2VjcmV0' };
      await service.validate(request as never);
      const call = onlyCall(client);
      expect(call.verb).toBe('post');
      expect(call.path).toBe('/v1/eab/credentials/validate');
      expect([...call.query.keys()]).toEqual([]);
      expect(call.body).toEqual(request);
    });

    it('passes a transport failure through', async () => {
      const err = failNext('post');
      await expect(service.validate({ keyId: 'k', hmacKey: 'h' } as never)).rejects.toBe(err);
    });
  });

  describe('delete', () => {
    it('deletes /v1/eab/credentials/{id} with no query and no body', async () => {
      const res = await service.delete(5);
      const call = onlyCall(client);
      expect(call.verb).toBe('delete');
      expect(call.path).toBe('/v1/eab/credentials/5');
      expect([...call.query.keys()]).toEqual([]);
      expect(call.argc).toBe(1);
      expect(res).toBe(ok);
    });

    it('passes a transport failure through', async () => {
      const err = failNext('delete');
      await expect(service.delete(5)).rejects.toBe(err);
    });
  });

  describe('getQRCode', () => {
    it('gets /v1/eab/credentials/{id}/qrcode with no query when no size is given', async () => {
      await service.getQRCode(4);
      const call = onlyCall(client);
      expect(call.verb).toBe('get');
      expect(call.path).toBe('/v1/eab/credentials/4/qrcode');
      expect([...call.query.keys()]).toEqual([]);
      expect(call.argc).toBe(1);
    });

    it('sends the size in the query', async () => {
      await service.getQRCode(4, 256);
      const call = onlyCall(client);
      expect(call.path).toBe('/v1/eab/credentials/4/qrcode');
      expect(Object.fromEntries(call.query)).toEqual({ size: '256' });
    });

    it('passes a transport failure through', async () => {
      const err = failNext('get');
      await expect(service.getQRCode(4)).rejects.toBe(err);
    });
  });

  describe('getEnrollmentURL', () => {
    it('gets /v1/eab/credentials/{id}/enrollment-url with no query and no body', async () => {
      await service.getEnrollmentURL(8);
      const call = onlyCall(client);
      expect(call.verb).toBe('get');
      expect(call.path).toBe('/v1/eab/credentials/8/enrollment-url');
      expect([...call.query.keys()]).toEqual([]);
      expect(call.argc).toBe(1);
    });

    it('passes a transport failure through', async () => {
      const err = failNext('get');
      await expect(service.getEnrollmentURL(8)).rejects.toBe(err);
    });
  });
});
