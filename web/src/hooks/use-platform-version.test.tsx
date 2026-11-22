import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { usePlatformVersion } from '@/hooks/use-platform-version';

// #2047: the daemon version is read through the SDK PlatformService
// (GET /api/v1/platform/version), whose wire body is flat snake_case.

const VERSION_PATH = 'GET /api/v1/platform/version';

function served(): Answer {
  return ok({
    version: '1.4.2',
    build_time: '2026-11-20T00:00:00Z',
    git_commit: 'abc1234',
    go_version: 'go1.25.4',
  });
}

const wrapper = ({ children }: { children: ReactNode }) => withControlPlane(children);

describe('usePlatformVersion', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('reads the version through GET /platform/version', async () => {
    const sent = stubControlPlane({ [VERSION_PATH]: served() });
    const { result } = renderHook(() => usePlatformVersion(), { wrapper });

    await waitFor(() =>
      expect(result.current.version).toEqual({
        version: '1.4.2',
        buildTime: '2026-11-20T00:00:00Z',
        gitCommit: 'abc1234',
        goVersion: 'go1.25.4',
      })
    );
    expect(result.current.isLoading).toBe(false);
    expect(result.current.error).toBeNull();
    expect(sent).toContainEqual({ method: 'GET', path: '/api/v1/platform/version', body: undefined });
  });

  it('shows a refused read as the error with the HTTP status', async () => {
    stubControlPlane({ [VERSION_PATH]: refused(403, 'forbidden') });
    const { result } = renderHook(() => usePlatformVersion(), { wrapper });

    await waitFor(() => expect(result.current.error).toBe('HTTP 403: forbidden'));
    expect(result.current.version).toBeNull();
  });

  it('refetch reads the version again', async () => {
    const sent = stubControlPlane({ [VERSION_PATH]: served() });
    const { result } = renderHook(() => usePlatformVersion(), { wrapper });

    await waitFor(() => expect(result.current.version?.version).toBe('1.4.2'));
    await act(() => result.current.refetch());

    expect(sent.filter((r) => r.path === '/api/v1/platform/version')).toHaveLength(2);
  });
});
