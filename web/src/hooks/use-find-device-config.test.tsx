import { act, cleanup, renderHook } from '@testing-library/react';
import type { ReactNode } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { useFindDeviceConfig } from './use-find-device-config';

const ROUTE = 'GET /api/v1/device/profiles/find-config';

const PROFILE = ok({
  id: '12',
  name: 'edge-gw',
  role: 'gateway',
  ek_serial: 'EK-1',
  mac_address: 'aa:bb:cc:dd:ee:ff',
  assigned: true,
  created_at: '2026-11-20T00:00:00Z',
  updated_at: '2026-11-20T00:00:00Z',
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function renderFind() {
  return renderHook(() => useFindDeviceConfig(), {
    wrapper: ({ children }: { children: ReactNode }) => withControlPlane(children),
  });
}

/** sentURL is the URL of the first request the SDK sent, query included. */
function sentURL(): URL {
  const input = vi.mocked(fetch).mock.calls[0][0];
  return new URL(input instanceof Request ? input.url : String(input));
}

describe('useFindDeviceConfig', () => {
  it('finds the profile through GET /device/profiles/find-config with ek_serial and mac', async () => {
    const sent = stubControlPlane({ [ROUTE]: PROFILE });
    const { result } = renderFind();

    await act(() => result.current.mutateAsync({ ekSerial: 'EK-1', macAddress: 'aa:bb:cc:dd:ee:ff' }));

    expect(result.current.data?.name).toBe('edge-gw');
    expect(sent).toContainEqual({ method: 'GET', path: '/api/v1/device/profiles/find-config', body: undefined });
    const url = sentURL();
    expect(url.searchParams.get('ek_serial')).toBe('EK-1');
    expect(url.searchParams.get('mac')).toBe('aa:bb:cc:dd:ee:ff');
  });

  it('leaves a blank EK serial off the query', async () => {
    stubControlPlane({ [ROUTE]: PROFILE });
    const { result } = renderFind();

    await act(() => result.current.mutateAsync({ ekSerial: '  ', macAddress: 'aa:bb:cc:dd:ee:ff' }));

    const url = sentURL();
    expect(url.searchParams.has('ek_serial')).toBe(false);
    expect(url.searchParams.get('mac')).toBe('aa:bb:cc:dd:ee:ff');
  });

  it('reports no match as a 404 error', async () => {
    stubControlPlane({ [ROUTE]: refused(404, 'no matching config') });
    const { result } = renderFind();

    await act(async () => {
      await expect(result.current.mutateAsync({ ekSerial: 'EK-9', macAddress: '' })).rejects.toMatchObject({
        status: 404,
      });
    });

    expect(result.current.error?.status).toBe(404);
    expect(result.current.error?.message).toBe('no matching config');
  });
});
