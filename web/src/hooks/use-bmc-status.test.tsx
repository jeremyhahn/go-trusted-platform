import { act, cleanup, renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ReactNode } from 'react';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import {
  bmcStatusPath,
  isProvisionDone,
  sensorsNeedingAttention,
  useBMCStatus,
  type BMCProvisionResult,
  type BMCSensorReading,
} from './use-bmc-status';

// #2039: the BMC status hook reads PowerStatus, GetSensors, GetSystemInfo,
// GetWebCertificate and ProvisionStatus, and starts Provision, through the
// SDK API client against the routes under /api/v1/bmc/{profileID}.

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const wrapper = ({ children }: { children: ReactNode }) => withControlPlane(children);

function renderStatus(profileID = '42') {
  return renderHook(() => useBMCStatus(profileID), { wrapper });
}

describe('useBMCStatus', () => {
  it('reads the power state', async () => {
    const sent = stubControlPlane({ 'GET /api/v1/bmc/42/power': ok({ state: 'on' }) });
    const { result } = renderStatus();
    let res: Awaited<ReturnType<typeof result.current.getPower>> | undefined;
    await act(async () => {
      res = await result.current.getPower();
    });
    expect(res?.data).toEqual({ state: 'on' });
    expect(sent).toEqual([{ method: 'GET', path: '/api/v1/bmc/42/power', body: undefined }]);
  });

  it('reads the sensors and picks the ones needing attention', async () => {
    const readings: BMCSensorReading[] = [
      { name: 'CPU Temp', value: 54, units: 'C', status: 'ok' },
      { name: 'Fan1', value: 0, units: 'RPM', status: 'critical' },
    ];
    stubControlPlane({ 'GET /api/v1/bmc/42/sensors': ok(readings) });
    const { result } = renderStatus();
    let res: Awaited<ReturnType<typeof result.current.getSensors>> | undefined;
    await act(async () => {
      res = await result.current.getSensors();
    });
    expect(res?.data).toHaveLength(2);
    expect(sensorsNeedingAttention(res!.data!)).toEqual([
      { name: 'Fan1', value: 0, units: 'RPM', status: 'critical' },
    ]);
  });

  it('reads the system info and the web certificate', async () => {
    stubControlPlane({
      'GET /api/v1/bmc/42/system-info': ok({
        manufacturer: 'Acme',
        product: 'X1',
        serial_number: 'SN1',
        firmware_version: '1.2',
        bios_version: '3.4',
        power_state: 'off',
      }),
      'GET /api/v1/bmc/42/cert': ok({
        subject: 'CN=bmc-42',
        issuer: 'CN=Platform CA',
        serial_number: '0a',
        not_before: '2026-01-01T00:00:00Z',
        not_after: '2027-01-01T00:00:00Z',
        days_remaining: 41,
      }),
    });
    const { result } = renderStatus();
    let info: Awaited<ReturnType<typeof result.current.getSystemInfo>> | undefined;
    let cert: Awaited<ReturnType<typeof result.current.getWebCertificate>> | undefined;
    await act(async () => {
      info = await result.current.getSystemInfo();
    });
    await act(async () => {
      cert = await result.current.getWebCertificate();
    });
    expect(info?.data?.serial_number).toBe('SN1');
    expect(cert?.data?.days_remaining).toBe(41);
  });

  it('starts a provision with and without an ISO', async () => {
    const started: BMCProvisionResult = {
      provision_id: 'p1',
      profile_id: 42,
      status: 'pending',
      started_at: '2026-11-21T10:00:00Z',
      updated_at: '2026-11-21T10:00:00Z',
    };
    const sent = stubControlPlane({ 'POST /api/v1/bmc/42/provision': ok(started) });
    const { result } = renderStatus();
    let res: Awaited<ReturnType<typeof result.current.provision>> | undefined;
    await act(async () => {
      res = await result.current.provision(' https://images.test/os.iso ');
    });
    await act(async () => {
      res = await result.current.provision();
    });
    expect(sent.map((s) => s.body)).toEqual([{ iso_url: 'https://images.test/os.iso' }, {}]);
    expect(res?.data?.status).toBe('pending');
  });

  it('surfaces a provision already running', async () => {
    stubControlPlane({
      'POST /api/v1/bmc/42/provision': refused(409, 'baremetal: provision already in progress for profile 42'),
    });
    const { result } = renderStatus();
    let res: Awaited<ReturnType<typeof result.current.provision>> | undefined;
    await act(async () => {
      res = await result.current.provision();
    });
    expect(res?.success).toBe(false);
    expect(res?.error?.status).toBe(409);
    expect(res?.error?.message).toContain('already in progress');
  });

  it('reads the provision status and a missing provision', async () => {
    stubControlPlane({
      'GET /api/v1/bmc/42/provision': ok({
        provision_id: 'p1',
        profile_id: 42,
        status: 'installing',
        started_at: '2026-11-21T10:00:00Z',
        updated_at: '2026-11-21T10:05:00Z',
      }),
    });
    const { result } = renderStatus();
    let res: Awaited<ReturnType<typeof result.current.getProvisionStatus>> | undefined;
    await act(async () => {
      res = await result.current.getProvisionStatus();
    });
    expect(res?.data?.status).toBe('installing');
    expect(isProvisionDone('installing')).toBe(false);

    // The SDK client keeps the fetch it was built with, so the re-stubbed
    // control plane needs a fresh provider (and so a fresh client).
    cleanup();
    vi.unstubAllGlobals();
    stubControlPlane({ 'GET /api/v1/bmc/42/provision': refused(404, 'baremetal: provision not found: 42') });
    const missing = renderStatus().result;
    await act(async () => {
      res = await missing.current.getProvisionStatus();
    });
    expect(res?.error?.status).toBe(404);
  });

  it('knows the done statuses and escapes the profile id', () => {
    expect(isProvisionDone('complete')).toBe(true);
    expect(isProvisionDone('failed')).toBe(true);
    expect(isProvisionDone('pending')).toBe(false);
    expect(bmcStatusPath('7', 'sensors')).toBe('/v1/bmc/7/sensors');
    expect(bmcStatusPath('a/b', 'cert')).toBe('/v1/bmc/a%2Fb/cert');
  });
});
