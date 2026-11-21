/**
 * Tests for the single-invitation read hooks (#2056).
 *
 * The context and the generic hooks are mocked so the invitation hooks run
 * as plain functions: the tests check which fetcher, deps and options the
 * hooks hand to useApi.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';

const service = {
  get: vi.fn(),
  getByToken: vi.fn(),
};

vi.mock('../context.js', () => ({
  usePlatformClient: () => ({ invitation: service }),
}));

vi.mock('./use-mutation.js', () => ({
  useMutation: vi.fn(() => ({})),
}));

const useApiMock = vi.fn(() => ({ data: undefined }));

vi.mock('./use-api.js', () => ({
  useApi: (...args: unknown[]) => useApiMock(...(args as [])),
}));

import { useInvitationGet, useInvitationGetByToken } from './use-invitation.js';

type UseApiCall = [() => unknown, unknown[], Record<string, unknown> | undefined];

function lastCall(): UseApiCall {
  const calls = useApiMock.mock.calls as unknown as UseApiCall[];
  expect(calls.length).toBeGreaterThan(0);
  return calls[calls.length - 1] as UseApiCall;
}

describe('useInvitationGet', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('fetches the invitation by id with the id as the dependency', () => {
    useInvitationGet('7');
    const [fetcher, deps] = lastCall();
    fetcher();
    expect(service.get).toHaveBeenCalledWith('7');
    expect(deps).toEqual(['7']);
  });

  it('passes no options for a valid id without caller options', () => {
    useInvitationGet('7');
    expect(lastCall()[2]).toBeUndefined();
  });

  it('is disabled for an undefined or empty id', () => {
    useInvitationGet(undefined);
    expect(lastCall()[2]).toEqual({ enabled: false });
    useInvitationGet('');
    expect(lastCall()[2]).toEqual({ enabled: false });
  });

  it('lets the caller disable a valid id', () => {
    useInvitationGet('7', { enabled: false });
    expect(lastCall()[2]).toEqual({ enabled: false });
  });

  it('forwards refetchInterval', () => {
    useInvitationGet('7', { refetchInterval: 5000 });
    expect(lastCall()[2]).toEqual({ refetchInterval: 5000 });
  });
});

describe('useInvitationGetByToken', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('fetches the invitation by token with the token as the dependency', () => {
    useInvitationGetByToken('tok');
    const [fetcher, deps] = lastCall();
    fetcher();
    expect(service.getByToken).toHaveBeenCalledWith('tok');
    expect(deps).toEqual(['tok']);
  });

  it('passes no options for a valid token without caller options', () => {
    useInvitationGetByToken('tok');
    expect(lastCall()[2]).toBeUndefined();
  });

  it('is disabled for an undefined or empty token', () => {
    useInvitationGetByToken(undefined);
    expect(lastCall()[2]).toEqual({ enabled: false });
    useInvitationGetByToken('');
    expect(lastCall()[2]).toEqual({ enabled: false });
  });

  it('lets the caller disable a valid token', () => {
    useInvitationGetByToken('tok', { enabled: false });
    expect(lastCall()[2]).toEqual({ enabled: false });
  });

  it('forwards refetchInterval', () => {
    useInvitationGetByToken('tok', { refetchInterval: 1000 });
    expect(lastCall()[2]).toEqual({ refetchInterval: 1000 });
  });
});
