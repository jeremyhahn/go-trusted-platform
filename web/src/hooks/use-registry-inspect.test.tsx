import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ReactNode } from 'react';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { useRegistry } from './use-registry';

// #2063: useRegistry inspects an image by tag through the SDK
// RegistryService.inspect, GET /api/v1/compute/images/{repository}:{tag}.

const STATUS = 'GET /api/v1/compute/images/status';
const INSPECT = 'GET /api/v1/compute/images/team/app:v1';

const statusAnswer = ok({
  Health: 1,
  Version: '3.0.0',
  ReadOnly: false,
  Components: [],
  StartedAt: '2026-11-20T00:00:00Z',
  Timestamp: '2026-11-21T00:00:00Z',
});

const detail = {
  Artifact: {
    Repository: 'team/app',
    Tag: 'v1',
    Digest: 'sha256:' + 'a'.repeat(64),
    Size: 2048,
    Manifest: {
      MediaType: 'application/vnd.oci.image.manifest.v1+json',
      Layers: [{ Digest: 'sha256:' + 'b'.repeat(64), Size: 1024 }],
    },
  },
  Signatures: [],
  ScanResult: null,
  Tags: ['v1', 'latest'],
};

function renderRegistry() {
  return renderHook(() => useRegistry(), {
    wrapper: ({ children }: { children: ReactNode }) => withControlPlane(children),
  });
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('useRegistry inspect', () => {
  it('inspects through GET /compute/images/{repository}:{tag}', async () => {
    const sent = stubControlPlane({ [STATUS]: statusAnswer, [INSPECT]: ok(detail) });
    const { result } = renderRegistry();
    await waitFor(() => expect(result.current.isStatusLoading).toBe(false));

    let got: Awaited<ReturnType<typeof result.current.inspect>> | undefined;
    await act(async () => {
      got = await result.current.inspect('team/app', 'v1');
    });

    expect(got?.Tags).toEqual(['v1', 'latest']);
    expect(got?.Artifact?.Manifest?.Layers).toHaveLength(1);
    expect(sent).toContainEqual({ method: 'GET', path: '/api/v1/compute/images/team/app:v1', body: undefined });
  });

  it('rejects with the server refusal', async () => {
    stubControlPlane({ [STATUS]: statusAnswer, [INSPECT]: refused(404, 'image not found') });
    const { result } = renderRegistry();
    await waitFor(() => expect(result.current.isStatusLoading).toBe(false));

    await act(async () => {
      await expect(result.current.inspect('team/app', 'v1')).rejects.toThrow(/HTTP 404.*image not found/);
    });
  });
});
