import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ReactNode } from 'react';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { useRegistry } from './use-registry';

// #2063: useRegistry reads the registry status, lists tags and deletes
// manifests through the SDK RegistryService: status from the REST surface,
// tags and manifests from the OCI surface at the host root.

const STATUS = 'GET /api/v1/compute/images/status';
const TAGS = 'GET /v2/team/app/tags/list';

const statusAnswer = ok({
  Health: 1,
  Version: '3.0.0',
  ReadOnly: false,
  Components: [],
  StartedAt: '2026-11-20T00:00:00Z',
  Timestamp: '2026-11-21T00:00:00Z',
});

const tagsAnswer: Answer = { status: 200, body: { name: 'team/app', tags: ['v1', 'v2'] } };

function renderRegistry() {
  return renderHook(() => useRegistry(), {
    wrapper: ({ children }: { children: ReactNode }) => withControlPlane(children),
  });
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('useRegistry', () => {
  it('reads the status through GET /compute/images/status', async () => {
    const sent = stubControlPlane({ [STATUS]: statusAnswer });
    const { result } = renderRegistry();

    await waitFor(() => expect(result.current.status?.Health).toBe(1));
    expect(result.current.status?.Version).toBe('3.0.0');
    expect(result.current.isStatusLoading).toBe(false);
    expect(sent).toContainEqual({ method: 'GET', path: '/api/v1/compute/images/status', body: undefined });
  });

  it('shows a refused status as statusError', async () => {
    stubControlPlane({ [STATUS]: refused(403, 'forbidden') });
    const { result } = renderRegistry();

    await waitFor(() => expect(result.current.statusError).toBe('HTTP 403: forbidden'));
    expect(result.current.status).toBeNull();
  });

  it('lists tags through GET /v2/{name}/tags/list at the host root', async () => {
    const sent = stubControlPlane({ [STATUS]: statusAnswer, [TAGS]: tagsAnswer });
    const { result } = renderRegistry();
    await waitFor(() => expect(result.current.isStatusLoading).toBe(false));

    await act(() => result.current.listTags('team/app'));

    expect(sent).toContainEqual({ method: 'GET', path: '/v2/team/app/tags/list', body: undefined });
    expect(result.current.tagsError).toBeNull();
    expect(result.current.tags).toEqual({ name: 'team/app', tags: ['v1', 'v2'] });
  });

  it('deletes a manifest, then lists the tags again', async () => {
    const sent = stubControlPlane({
      [STATUS]: statusAnswer,
      [TAGS]: tagsAnswer,
      'DELETE /v2/team/app/manifests/v1': { status: 202, body: {} },
    });
    const { result } = renderRegistry();
    await waitFor(() => expect(result.current.isStatusLoading).toBe(false));

    await act(() => result.current.deleteManifest('team/app', 'v1'));

    const del = sent.findIndex((r) => r.method === 'DELETE' && r.path === '/v2/team/app/manifests/v1');
    expect(del).toBeGreaterThanOrEqual(0);
    expect(sent[del]).toEqual({ method: 'DELETE', path: '/v2/team/app/manifests/v1', body: undefined });
    expect(sent.slice(del + 1)).toContainEqual({ method: 'GET', path: '/v2/team/app/tags/list', body: undefined });
    expect(result.current.tags).toEqual({ name: 'team/app', tags: ['v1', 'v2'] });
  });

  it('rejects a refused delete with the HTTP status', async () => {
    const sent = stubControlPlane({
      [STATUS]: statusAnswer,
      [TAGS]: tagsAnswer,
      'DELETE /v2/team/app/manifests/v9': refused(404, 'manifest unknown'),
    });
    const { result } = renderRegistry();
    await waitFor(() => expect(result.current.isStatusLoading).toBe(false));

    await act(async () => {
      await expect(result.current.deleteManifest('team/app', 'v9')).rejects.toThrow('HTTP 404: manifest unknown');
    });

    expect(sent).toContainEqual({ method: 'DELETE', path: '/v2/team/app/manifests/v9', body: undefined });
    expect(sent.some((r) => r.method === 'GET' && r.path === '/v2/team/app/tags/list')).toBe(false);
  });
});
