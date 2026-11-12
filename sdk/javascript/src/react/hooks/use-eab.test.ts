/**
 * Unit tests for the EAB React hooks (#1802).
 *
 * The SDK has no React renderer in its dev dependencies, so the hooks are
 * exercised as plain functions: the platform client context, useMutation and
 * useApi are mocked, and each test inspects the mutation function or fetcher
 * the hook hands to them.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../context.js', () => ({ usePlatformClient: vi.fn() }));
vi.mock('./use-mutation.js', () => ({
  useMutation: vi.fn((fn: unknown) => ({ mutationFn: fn })),
}));
vi.mock('./use-api.js', () => ({
  useApi: vi.fn((fn: unknown, deps: unknown, options: unknown) => ({ fetcher: fn, deps, options })),
}));

import { usePlatformClient } from '../context.js';
import { useMutation } from './use-mutation.js';
import { useApi } from './use-api.js';
import { useEAB, useEABList } from './use-eab.js';

type Fn = (...args: unknown[]) => Promise<unknown>;

const service = {
  create: vi.fn(),
  revoke: vi.fn(),
  validate: vi.fn(),
  delete: vi.fn(),
  getQRCode: vi.fn(),
  getEnrollmentURL: vi.fn(),
  list: vi.fn(),
};

function mutationFn(result: unknown): Fn {
  return (result as { mutationFn: Fn }).mutationFn;
}

function apiCall(): { fetcher: Fn; deps: unknown[]; options: unknown } {
  const calls = vi.mocked(useApi).mock.calls;
  const last = calls[calls.length - 1];
  if (!last) {
    throw new Error('useApi was not called');
  }
  return { fetcher: last[0] as Fn, deps: last[1], options: last[2] };
}

beforeEach(() => {
  vi.clearAllMocks();
  for (const fn of Object.values(service)) {
    fn.mockResolvedValue({ success: true, data: 'ok' });
  }
  vi.mocked(usePlatformClient).mockReturnValue({ eab: service } as never);
});

describe('useEAB', () => {
  it('returns the client EAB service', () => {
    expect(useEAB().service).toBe(service);
  });

  it('builds exactly six mutations', () => {
    useEAB();
    expect(useMutation).toHaveBeenCalledTimes(6);
  });

  it('create forwards the request to service.create', async () => {
    const req = { profileId: 1, tenantId: 'tenant-a', expiresInSeconds: 60 };
    await expect(mutationFn(useEAB().create)(req)).resolves.toEqual({ success: true, data: 'ok' });
    expect(service.create).toHaveBeenCalledWith(req);
  });

  it('revoke forwards the id to service.revoke', async () => {
    await mutationFn(useEAB().revoke)(7);
    expect(service.revoke).toHaveBeenCalledWith(7);
  });

  it('validate forwards the request to service.validate', async () => {
    const req = { keyId: 'kid', hmacKey: 'secret' };
    await mutationFn(useEAB().validate)(req);
    expect(service.validate).toHaveBeenCalledWith(req);
  });

  it('deleteCredential forwards the id to service.delete', async () => {
    await mutationFn(useEAB().deleteCredential)(9);
    expect(service.delete).toHaveBeenCalledWith(9);
  });

  it('getQRCode passes id and size', async () => {
    await mutationFn(useEAB().getQRCode)({ id: 3, size: 256 });
    expect(service.getQRCode).toHaveBeenCalledWith(3, 256);
  });

  it('getQRCode passes an undefined size when none is given', async () => {
    await mutationFn(useEAB().getQRCode)({ id: 3 });
    expect(service.getQRCode).toHaveBeenCalledWith(3, undefined);
  });

  it('getEnrollmentURL forwards the id', async () => {
    await mutationFn(useEAB().getEnrollmentURL)(4);
    expect(service.getEnrollmentURL).toHaveBeenCalledWith(4);
  });

  it('propagates a service rejection through the mutation function', async () => {
    service.revoke.mockRejectedValueOnce(new Error('revoke failed'));
    await expect(mutationFn(useEAB().revoke)(-1)).rejects.toThrow('revoke failed');
    expect(service.revoke).toHaveBeenCalledWith(-1);
  });

  it('throws when the platform client is missing', () => {
    vi.mocked(usePlatformClient).mockImplementationOnce(() => {
      throw new Error('usePlatformClient must be used within a PlatformProvider');
    });
    expect(() => useEAB()).toThrow('PlatformProvider');
  });
});

describe('useEABList', () => {
  it('passes undefined options and undefined filters when called without options', async () => {
    useEABList();
    const { fetcher, deps, options } = apiCall();
    expect(options).toBeUndefined();
    expect(deps).toEqual([undefined, undefined, undefined, undefined, undefined]);
    await fetcher();
    expect(service.list).toHaveBeenCalledWith(undefined);
  });

  it('passes undefined options for an empty options object', () => {
    useEABList({});
    expect(apiCall().options).toBeUndefined();
  });

  it('forwards enabled and refetchInterval', () => {
    useEABList({ enabled: false, refetchInterval: 5000 });
    expect(apiCall().options).toEqual({ enabled: false, refetchInterval: 5000 });
  });

  it('forwards only enabled when refetchInterval is absent', () => {
    useEABList({ enabled: true });
    expect(apiCall().options).toEqual({ enabled: true });
  });

  it('keeps a zero refetchInterval', () => {
    useEABList({ refetchInterval: 0 });
    expect(apiCall().options).toEqual({ refetchInterval: 0 });
  });

  it('puts every filter field in the dependency list in order', async () => {
    const filters = { page: 2, pageSize: 50, status: 'ACTIVE', tenantId: 't', profileId: 5 };
    useEABList({ filters: filters as never });
    const { fetcher, deps } = apiCall();
    expect(deps).toEqual([2, 50, 'ACTIVE', 't', 5]);
    await fetcher();
    expect(service.list).toHaveBeenCalledWith(filters);
  });

  it('propagates a list rejection through the fetcher', async () => {
    service.list.mockRejectedValueOnce(new Error('list failed'));
    useEABList();
    await expect(apiCall().fetcher()).rejects.toThrow('list failed');
  });
});
