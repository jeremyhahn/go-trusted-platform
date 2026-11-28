import { act, cleanup, renderHook } from '@testing-library/react';
import type { ReactNode } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import {
  callerPolicySummary,
  useAttestationFeed,
  verdictsPath,
  type PollDeviceVerdictsResponse,
} from './use-attestation-feed';

const CALLERS = 'GET /api/v1/attestation/callers';
const VERDICTS = 'GET /api/v1/attestation/verdicts';

function renderFeed() {
  return renderHook(() => useAttestationFeed(), {
    wrapper: ({ children }: { children: ReactNode }) => withControlPlane(children),
  });
}

type Res<T> = { success: boolean; data?: T; error?: { status?: number; message: string } };

describe('useAttestationFeed', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('describes the caller policy through GET /attestation/callers', async () => {
    const sent = stubControlPlane({
      [CALLERS]: ok({
        strategy: 'list',
        identities: ['spiffe://a', 'spiffe://b'],
        list_valid: true,
        anchors_configured: true,
        attested_peers_available: false,
        admits_nobody: false,
      }),
    });
    const { result } = renderFeed();
    let res: Awaited<ReturnType<typeof result.current.describeCallers>> | undefined;
    await act(async () => {
      res = await result.current.describeCallers();
    });
    expect(res?.data?.identities).toHaveLength(2);
    expect(callerPolicySummary(res?.data)).toBe('list: 2 identities');
    expect(sent).toEqual([{ method: 'GET', path: '/api/v1/attestation/callers', body: undefined }]);
  });

  it('summarises a policy that admits nobody', () => {
    expect(callerPolicySummary(undefined)).toBe('Admits no caller');
    expect(
      callerPolicySummary({
        strategy: 'none',
        identities: [],
        list_valid: true,
        anchors_configured: false,
        attested_peers_available: false,
        admits_nobody: true,
      })
    ).toBe('Admits no caller');
    expect(
      callerPolicySummary({
        strategy: 'list',
        identities: [],
        list_valid: false,
        anchors_configured: false,
        attested_peers_available: false,
        admits_nobody: false,
      })
    ).toBe('Caller list invalid');
  });

  it('polls verdicts through GET /attestation/verdicts', async () => {
    const sent = stubControlPlane({
      [VERDICTS]: ok({
        cursor: 'c2',
        verdicts: [
          {
            eventId: 'e1',
            recordedAt: '2026-11-20T10:00:00Z',
            deviceId: '18446744073709551615',
            tenantId: 't1',
            hostId: 'h1',
            serial: 'S1',
            passed: false,
            cryptographic: true,
            reason: 'pcr 7 mismatch',
          },
        ],
      }),
    });
    const { result } = renderFeed();
    let res: Res<PollDeviceVerdictsResponse> | undefined;
    await act(async () => {
      res = await result.current.pollVerdicts({ cursor: 'c1', waitMs: 0 });
    });
    expect(res?.data?.cursor).toBe('c2');
    expect(res?.data?.verdicts[0].deviceId).toBe('18446744073709551615');
    expect(res?.data?.verdicts[0].passed).toBe(false);
    expect(sent).toEqual([{ method: 'GET', path: '/api/v1/attestation/verdicts', body: undefined }]);
  });

  it('builds the verdicts query', () => {
    expect(verdictsPath()).toBe('/v1/attestation/verdicts');
    expect(verdictsPath({ cursor: 'c1' })).toBe('/v1/attestation/verdicts?cursor=c1');
    expect(verdictsPath({ cursor: 'a b', waitMs: 2500.7 })).toBe(
      '/v1/attestation/verdicts?cursor=a+b&wait_ms=2500'
    );
    expect(verdictsPath({ cursor: '', waitMs: -1 })).toBe('/v1/attestation/verdicts');
  });

  it('surfaces the no-tenant refusal', async () => {
    stubControlPlane({
      [VERDICTS]: refused(403, 'attestation: device verdicts denied: the session names no tenant'),
    });
    const { result } = renderFeed();
    let res: Res<PollDeviceVerdictsResponse> | undefined;
    await act(async () => {
      res = await result.current.pollVerdicts();
    });
    expect(res?.success).toBe(false);
    expect(res?.error?.status).toBe(403);
    expect(res?.error?.message).toContain('names no tenant');
  });

  it('surfaces a bad wait_ms refusal', async () => {
    stubControlPlane({ [VERDICTS]: refused(400, 'invalid wait_ms') });
    const { result } = renderFeed();
    let res: Res<PollDeviceVerdictsResponse> | undefined;
    await act(async () => {
      res = await result.current.pollVerdicts({ waitMs: 99999999 });
    });
    expect(res?.success).toBe(false);
    expect(res?.error?.status).toBe(400);
  });
});
