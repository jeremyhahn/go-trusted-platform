/**
 * Unit tests for the invitation React hooks (#1802).
 *
 * The hooks run as plain functions: the platform client context, useMutation
 * and useApi are mocked (see use-eab.test.ts for the rationale).
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
import { useInvitation, useInvitationList } from './use-invitation.js';

type Fn = (...args: unknown[]) => Promise<unknown>;

const service = {
  create: vi.fn(),
  revoke: vi.fn(),
  accept: vi.fn(),
  resend: vi.fn(),
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
  vi.mocked(usePlatformClient).mockReturnValue({ invitation: service } as never);
});

describe('useInvitation', () => {
  it('returns the client invitation service', () => {
    expect(useInvitation().service).toBe(service);
  });

  it('builds exactly four mutations', () => {
    useInvitation();
    expect(useMutation).toHaveBeenCalledTimes(4);
  });

  it('create forwards the request to service.create', async () => {
    const req = { email: 'user@example.invalid', role: 'viewer' };
    await expect(mutationFn(useInvitation().create)(req)).resolves.toEqual({
      success: true,
      data: 'ok',
    });
    expect(service.create).toHaveBeenCalledWith(req);
  });

  it('revoke forwards the id to service.revoke', async () => {
    await mutationFn(useInvitation().revoke)('inv-1');
    expect(service.revoke).toHaveBeenCalledWith('inv-1');
  });

  it('accept forwards the request to service.accept', async () => {
    const req = { token: 'tok', password: 'pw' };
    await mutationFn(useInvitation().accept)(req);
    expect(service.accept).toHaveBeenCalledWith(req);
  });

  it('resend forwards the id to service.resend', async () => {
    await mutationFn(useInvitation().resend)('inv-2');
    expect(service.resend).toHaveBeenCalledWith('inv-2');
  });

  it('passes an empty id through unchanged', async () => {
    await mutationFn(useInvitation().revoke)('');
    expect(service.revoke).toHaveBeenCalledWith('');
  });

  it('propagates a service rejection through the mutation function', async () => {
    service.accept.mockRejectedValueOnce(new Error('token expired'));
    await expect(mutationFn(useInvitation().accept)({ token: 'bad' })).rejects.toThrow(
      'token expired'
    );
  });

  it('throws when the platform client is missing', () => {
    vi.mocked(usePlatformClient).mockImplementationOnce(() => {
      throw new Error('usePlatformClient must be used within a PlatformProvider');
    });
    expect(() => useInvitation()).toThrow('PlatformProvider');
  });
});

describe('useInvitationList', () => {
  it('passes undefined options and undefined filters when called without options', async () => {
    useInvitationList();
    const { fetcher, deps, options } = apiCall();
    expect(options).toBeUndefined();
    expect(deps).toEqual([undefined, undefined, undefined, undefined]);
    await fetcher();
    expect(service.list).toHaveBeenCalledWith(undefined);
  });

  it('passes undefined options for an empty options object', () => {
    useInvitationList({});
    expect(apiCall().options).toBeUndefined();
  });

  it('forwards enabled and refetchInterval', () => {
    useInvitationList({ enabled: false, refetchInterval: 1000 });
    expect(apiCall().options).toEqual({ enabled: false, refetchInterval: 1000 });
  });

  it('forwards only refetchInterval when enabled is absent', () => {
    useInvitationList({ refetchInterval: 0 });
    expect(apiCall().options).toEqual({ refetchInterval: 0 });
  });

  it('puts every filter field in the dependency list in order', async () => {
    const filters = { page: 1, pageSize: 10, status: 'PENDING', email: 'a@example.invalid' };
    useInvitationList({ filters: filters as never });
    const { fetcher, deps } = apiCall();
    expect(deps).toEqual([1, 10, 'PENDING', 'a@example.invalid']);
    await fetcher();
    expect(service.list).toHaveBeenCalledWith(filters);
  });

  it('propagates a list rejection through the fetcher', async () => {
    service.list.mockRejectedValueOnce(new Error('list failed'));
    useInvitationList();
    await expect(apiCall().fetcher()).rejects.toThrow('list failed');
  });
});
