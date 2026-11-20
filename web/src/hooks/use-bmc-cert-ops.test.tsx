import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, renderHook } from '@testing-library/react';
import { useBMCCertOps } from './use-bmc-cert-ops';

const bmc = vi.hoisted(() => ({
  enrollBMC: vi.fn(),
  restoreFactoryCert: vi.fn(),
}));

vi.mock('trusted-platform-sdk', () => ({
  usePlatformClient: () => ({ bmc }),
}));

function reply(res: unknown): void {
  bmc.enrollBMC.mockResolvedValue(res);
  bmc.restoreFactoryCert.mockResolvedValue(res);
}

beforeEach(() => {
  bmc.enrollBMC.mockReset();
  bmc.restoreFactoryCert.mockReset();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('useBMCCertOps', () => {
  it('sends enrol and restore through the SDK BMCService', async () => {
    reply({ success: true, data: { steps: [] } });
    const { result } = renderHook(() => useBMCCertOps('7'));
    await act(async () => {
      await result.current.enroll({ replaceCertificate: true, dnsRegister: false });
      await result.current.restoreFactoryCert();
    });
    expect(bmc.enrollBMC).toHaveBeenCalledTimes(1);
    expect(bmc.enrollBMC).toHaveBeenCalledWith('7', { replaceCertificate: true, dnsRegister: false });
    expect(bmc.restoreFactoryCert).toHaveBeenCalledWith('7');
  });

  it('returns the enrolment result from the SDK payload', async () => {
    reply({
      success: true,
      data: {
        device_id: '42',
        endpoint: 'https://bmc',
        hostname: 'bmc-1',
        pin_spki_sha256: 'abc',
        steps: [{ name: 'replace_certificate', ok: true }],
      },
    });
    const { result } = renderHook(() => useBMCCertOps('7'));
    let out: unknown;
    await act(async () => {
      out = await result.current.enroll({});
    });
    expect(bmc.enrollBMC).toHaveBeenCalledWith('7', {});
    expect(out).toMatchObject({ device_id: '42', hostname: 'bmc-1' });
    expect(result.current.lastResult).toMatchObject({ operation: 'enroll' });
    expect(result.current.error).toBeNull();
  });

  it('reports the server error of a refused call and returns null', async () => {
    reply({ success: false, error: { message: 'bmc enroller not available' } });
    const { result } = renderHook(() => useBMCCertOps('7'));
    let out: unknown = 'unset';
    await act(async () => {
      out = await result.current.restoreFactoryCert();
    });
    expect(out).toBeNull();
    expect(result.current.error).toBe('bmc enroller not available');
    expect(result.current.busy).toBe(false);
  });

  it('hands the raw profile ID to the SDK, which encodes it as one path segment', async () => {
    reply({ success: true, data: {} });
    const { result } = renderHook(() => useBMCCertOps('a/b'));
    await act(async () => {
      await result.current.restoreFactoryCert();
    });
    expect(bmc.restoreFactoryCert).toHaveBeenCalledWith('a/b');
  });
});
