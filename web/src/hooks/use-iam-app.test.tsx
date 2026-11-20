import { renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

const iam = vi.hoisted(() => ({
  getApp: vi.fn(),
}));

const captured = vi.hoisted(() => ({
  apiFn: undefined as unknown,
  apiDeps: undefined as unknown,
  apiData: undefined as unknown,
}));

vi.mock('trusted-platform-sdk', () => ({
  useIAM: () => iam,
  useApi: (fn: unknown, deps: unknown) => {
    captured.apiFn = fn;
    captured.apiDeps = deps;
    return { data: captured.apiData, isLoading: false, error: null, refetch: vi.fn() };
  },
}));

import { useAppDetail } from './use-iam-app';

type ApiFn = () => Promise<unknown>;

afterEach(() => {
  vi.clearAllMocks();
  captured.apiData = undefined;
});

describe('useAppDetail', () => {
  it('fetches the app by client ID for the tenant', async () => {
    iam.getApp.mockResolvedValue({ success: true, data: {} });
    renderHook(() => useAppDetail('t-1', 'client-1'));
    await (captured.apiFn as ApiFn)();
    expect(iam.getApp).toHaveBeenCalledWith('t-1', 'client-1');
    expect(captured.apiDeps).toEqual(['t-1', 'client-1']);
  });

  it('unwraps a nested {app} response with snake_case lists', () => {
    captured.apiData = {
      app: {
        name: 'portal',
        redirect_uris: ['https://a/cb'],
        grant_types: ['authorization_code'],
        created_at: '2026-11-20T00:00:00Z',
      },
    };
    const { result } = renderHook(() => useAppDetail('t-1', 'client-1'));
    expect(result.current.app).toEqual({
      name: 'portal',
      redirectUris: ['https://a/cb'],
      grantTypes: ['authorization_code'],
      createdAt: '2026-11-20T00:00:00Z',
    });
  });

  it('reads a flat camelCase response', () => {
    captured.apiData = { name: 'cli', redirectUris: ['https://b/cb'], grantTypes: ['client_credentials'] };
    const { result } = renderHook(() => useAppDetail('t-1', 'client-1'));
    expect(result.current.app).toEqual({
      name: 'cli',
      redirectUris: ['https://b/cb'],
      grantTypes: ['client_credentials'],
      createdAt: undefined,
    });
  });

  it('defaults missing lists to empty', () => {
    captured.apiData = { app: { name: 'bare' } };
    const { result } = renderHook(() => useAppDetail('t-1', 'client-1'));
    expect(result.current.app?.redirectUris).toEqual([]);
    expect(result.current.app?.grantTypes).toEqual([]);
  });

  it('is null before the server answers', () => {
    const { result } = renderHook(() => useAppDetail('t-1', 'client-1'));
    expect(result.current.app).toBeNull();
  });

  it('errors without a tenant and calls no SDK method', async () => {
    renderHook(() => useAppDetail(null, 'client-1'));
    await expect((captured.apiFn as ApiFn)()).rejects.toThrow(/tenant/i);
    expect(iam.getApp).not.toHaveBeenCalled();
  });
});
