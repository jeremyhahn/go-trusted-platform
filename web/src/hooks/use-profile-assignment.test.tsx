import { act, cleanup, renderHook } from '@testing-library/react';
import type { ReactNode } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { useProfileAssignment } from './use-profile-assignment';

const ASSIGN = 'POST /api/v1/device/profiles/12/assign';
const UNASSIGN = 'POST /api/v1/device/profiles/12/unassign';

const PROFILE = ok({
  id: '12',
  name: 'edge-gw',
  role: 'gateway',
  ek_serial: 'EK-1',
  mac_address: null,
  assigned: true,
  created_at: '2026-11-20T00:00:00Z',
  updated_at: '2026-11-20T00:00:00Z',
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function renderAssignment() {
  return renderHook(() => useProfileAssignment(), {
    wrapper: ({ children }: { children: ReactNode }) => withControlPlane(children),
  });
}

describe('useProfileAssignment', () => {
  it('assigns through POST /device/profiles/{id}/assign with the trimmed identity', async () => {
    const sent = stubControlPlane({ [ASSIGN]: PROFILE });
    const { result } = renderAssignment();

    let profile: unknown;
    await act(async () => {
      profile = await result.current.assign.mutateAsync({
        profileId: '12',
        ekSerial: ' EK-1 ',
        macAddress: '',
        deviceId: '42',
      });
    });

    expect(sent).toEqual([
      {
        method: 'POST',
        path: '/api/v1/device/profiles/12/assign',
        body: { profile_id: 12, ek_serial: 'EK-1', device_id: '42' },
      },
    ]);
    expect(profile).toMatchObject({ id: '12', name: 'edge-gw' });
  });

  it('unassigns through POST /device/profiles/{id}/unassign', async () => {
    const sent = stubControlPlane({ [UNASSIGN]: ok({ ...PROFILE.body as object, assigned: false }) });
    const { result } = renderAssignment();

    await act(async () => {
      await result.current.unassign.mutateAsync('12');
    });

    expect(sent).toHaveLength(1);
    expect(sent[0]).toMatchObject({ method: 'POST', path: '/api/v1/device/profiles/12/unassign' });
    expect(result.current.unassign.data?.assigned).toBe(false);
  });

  it('surfaces a refusal as the mutation error', async () => {
    stubControlPlane({ [ASSIGN]: refused(400, 'device identity required') });
    const { result } = renderAssignment();

    await act(async () => {
      await expect(result.current.assign.mutateAsync({ profileId: '12', deviceId: '42' })).rejects.toBeTruthy();
    });

    expect(result.current.assign.error?.message).toContain('device identity required');
  });

  it('refuses a profile id the SDK number cannot carry, sending nothing', async () => {
    const sent = stubControlPlane({});
    const { result } = renderAssignment();

    await act(async () => {
      await expect(
        result.current.assign.mutateAsync({ profileId: '9007199254740993', deviceId: '42' })
      ).rejects.toThrow(/profile id/);
    });

    expect(sent).toHaveLength(0);
  });

  it('refuses an assignment with no device identity, sending nothing', async () => {
    const sent = stubControlPlane({});
    const { result } = renderAssignment();

    await act(async () => {
      await expect(
        result.current.assign.mutateAsync({ profileId: '12', ekSerial: ' ', macAddress: '', deviceId: '' })
      ).rejects.toThrow(/identity/);
    });

    expect(sent).toHaveLength(0);
  });
});
