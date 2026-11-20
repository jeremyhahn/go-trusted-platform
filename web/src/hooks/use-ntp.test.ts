import { afterEach, describe, expect, it, vi } from 'vitest';
import { renderHook } from '@testing-library/react';

const ntp = {
  getStatus: vi.fn(),
  listSources: vi.fn(),
  step: vi.fn(),
};
const getApiClient = vi.fn();

vi.mock('trusted-platform-sdk', async (importOriginal) => {
  const actual = await importOriginal<typeof import('trusted-platform-sdk')>();
  return {
    ...actual,
    usePlatformClient: () => ({ ntp, getApiClient }),
  };
});

import { ntpStepCapability, useNTP } from './use-ntp';

const status = {
  synced: true,
  stratum: 2,
  leapStatus: 'normal',
  offsetSeconds: 0.001,
  rootDispersion: 0,
  rootDelay: 0,
  lastSyncUnix: 1700000000,
  mode: 'client',
  referenceId: 'C0A80001',
  referenceName: 'ntp.example',
  sourcesReachable: 1,
  sourcesTotal: 1,
  anomaly: false,
  anomalyReason: '',
};

afterEach(() => {
  vi.clearAllMocks();
});

describe('useNTP', () => {
  it('reads the status through the SDK NTP service, not a hand-written request', async () => {
    ntp.getStatus.mockResolvedValue({ success: true, data: { status } });
    const { result } = renderHook(() => useNTP());

    const res = await result.current.getStatus();

    expect(ntp.getStatus).toHaveBeenCalledTimes(1);
    expect(getApiClient).not.toHaveBeenCalled();
    expect(res.data?.status.referenceName).toBe('ntp.example');
  });

  it('lists the sources through the SDK NTP service', async () => {
    ntp.listSources.mockResolvedValue({ success: true, data: { sources: [] } });
    const { result } = renderHook(() => useNTP());

    await result.current.listSources();

    expect(ntp.listSources).toHaveBeenCalledTimes(1);
    expect(getApiClient).not.toHaveBeenCalled();
  });

  it('steps the clock through the SDK NTP service', async () => {
    ntp.step.mockResolvedValue({ success: true, data: { status } });
    const { result } = renderHook(() => useNTP());

    const res = await result.current.step();

    expect(ntp.step).toHaveBeenCalledTimes(1);
    expect(getApiClient).not.toHaveBeenCalled();
    expect(res.data?.status.synced).toBe(true);
  });
});

describe('ntpStepCapability', () => {
  it('allows Step once a status read succeeded', () => {
    expect(ntpStepCapability({ status, error: null })).toEqual({ allowed: true, reason: null });
  });

  it('gates Step off with the server reason when the status read failed', () => {
    const gate = ntpStepCapability({ status: undefined, error: { message: 'ntp is not configured on this node' } });
    expect(gate.allowed).toBe(false);
    expect(gate.reason).toContain('ntp is not configured on this node');
  });

  it('gates Step off while a cached status is stale from a failed refresh', () => {
    const gate = ntpStepCapability({ status, error: { message: 'chrony control command failed' } });
    expect(gate.allowed).toBe(false);
    expect(gate.reason).toContain('chrony control command failed');
  });

  it('gates Step off before the first status read', () => {
    const gate = ntpStepCapability({ status: undefined, error: null });
    expect(gate.allowed).toBe(false);
    expect(gate.reason).toBeTruthy();
  });
});
