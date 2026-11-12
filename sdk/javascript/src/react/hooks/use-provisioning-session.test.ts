/**
 * Unit tests for the provisioning-session React hook (#1802).
 *
 * The hook runs as a plain function: the platform client context, useMutation
 * and useApi are mocked (see use-eab.test.ts for the rationale).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../context.js', () => ({ usePlatformClient: vi.fn() }));
vi.mock('./use-mutation.js', () => ({
  useMutation: vi.fn((fn: unknown) => ({ mutationFn: fn })),
}));
vi.mock('./use-api.js', () => ({ useApi: vi.fn() }));

import { usePlatformClient } from '../context.js';
import { useMutation } from './use-mutation.js';
import { useApi } from './use-api.js';
import { useProvisioningSessions } from './use-provisioning-session.js';

type Fn = (...args: unknown[]) => Promise<unknown>;

const service = {
  listProvisioningSessions: vi.fn(),
  fulfillProvisioningSession: vi.fn(),
};

const refetch = vi.fn();

function listResult(data: unknown, extra: Record<string, unknown> = {}): void {
  vi.mocked(useApi).mockReturnValue({
    data,
    isLoading: false,
    error: null,
    refetch,
    ...extra,
  } as never);
}

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

const s1 = { id: 's1', status: 'PENDING' };
const s2 = { id: 's2', status: 'FULFILLED' };

beforeEach(() => {
  vi.clearAllMocks();
  for (const fn of Object.values(service)) {
    fn.mockResolvedValue({ success: true, data: 'ok' });
  }
  refetch.mockResolvedValue(undefined);
  vi.mocked(usePlatformClient).mockReturnValue({ device: service } as never);
  listResult(undefined);
});

describe('useProvisioningSessions list fetcher', () => {
  it('lists sessions with no arguments, an empty dependency list and no options', async () => {
    useProvisioningSessions();
    const { fetcher, deps, options } = apiCall();
    expect(deps).toEqual([]);
    expect(options).toBeUndefined();
    await fetcher();
    expect(service.listProvisioningSessions).toHaveBeenCalledWith();
  });

  it('propagates a list rejection through the fetcher', async () => {
    service.listProvisioningSessions.mockRejectedValueOnce(new Error('list failed'));
    useProvisioningSessions();
    await expect(apiCall().fetcher()).rejects.toThrow('list failed');
  });
});

describe('useProvisioningSessions sessions', () => {
  it('returns a bare array response as is', () => {
    listResult([s1, s2]);
    expect(useProvisioningSessions().sessions).toEqual([s1, s2]);
  });

  it('unwraps a {sessions} envelope', () => {
    listResult({ sessions: [s2] });
    expect(useProvisioningSessions().sessions).toEqual([s2]);
  });

  it('returns an empty array for an empty envelope', () => {
    listResult({ sessions: [] });
    expect(useProvisioningSessions().sessions).toEqual([]);
  });

  it.each([
    ['undefined data', undefined],
    ['null data', null],
    ['an object without sessions', { total: 0 }],
    ['a non-array sessions field', { sessions: { id: 's1' } }],
    ['a string', 'sessions'],
    ['a boolean', true],
  ])('returns an empty list for %s', (_name, data) => {
    listResult(data);
    expect(useProvisioningSessions().sessions).toEqual([]);
  });
});

describe('useProvisioningSessions state', () => {
  it('passes isLoading through', () => {
    listResult(undefined, { isLoading: true });
    expect(useProvisioningSessions().isLoading).toBe(true);
  });

  it('passes an error through', () => {
    const err = new Error('boom');
    listResult(undefined, { error: err });
    expect(useProvisioningSessions().error).toBe(err);
  });

  it('maps an undefined error to null', () => {
    listResult(undefined, { error: undefined });
    expect(useProvisioningSessions().error).toBeNull();
  });

  it('refetch calls the list refetch and returns nothing', () => {
    const result = useProvisioningSessions();
    expect(result.refetch()).toBeUndefined();
    expect(refetch).toHaveBeenCalledTimes(1);
  });
});

describe('useProvisioningSessions fulfill', () => {
  it('builds exactly one mutation', () => {
    useProvisioningSessions();
    expect(useMutation).toHaveBeenCalledTimes(1);
  });

  it('forwards the request to service.fulfillProvisioningSession', async () => {
    const req = { sessionId: 's1', profileId: 'p1' };
    await expect(mutationFn(useProvisioningSessions().fulfill)(req)).resolves.toEqual({
      success: true,
      data: 'ok',
    });
    expect(service.fulfillProvisioningSession).toHaveBeenCalledWith(req);
  });

  it('propagates a service rejection through the mutation function', async () => {
    service.fulfillProvisioningSession.mockRejectedValueOnce(new Error('session expired'));
    await expect(
      mutationFn(useProvisioningSessions().fulfill)({ sessionId: 'gone' })
    ).rejects.toThrow('session expired');
  });

  it('throws when the platform client is missing', () => {
    vi.mocked(usePlatformClient).mockImplementationOnce(() => {
      throw new Error('usePlatformClient must be used within a PlatformProvider');
    });
    expect(() => useProvisioningSessions()).toThrow('PlatformProvider');
  });
});
