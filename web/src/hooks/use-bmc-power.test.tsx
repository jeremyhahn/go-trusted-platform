import { act, cleanup, renderHook } from '@testing-library/react';
import type { ReactNode } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import {
  BMC_POWER_ACTIONS,
  bmcPowerActionLabel,
  bmcPowerActionStopsHost,
  bmcPowerPath,
  isBMCPowerAction,
  useBMCPower,
} from './use-bmc-power';

const POWER = 'POST /api/v1/bmc/42/power';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function renderPower() {
  return renderHook(() => useBMCPower('42'), {
    wrapper: ({ children }: { children: ReactNode }) => withControlPlane(children),
  });
}

describe('useBMCPower', () => {
  it('powers on through POST /bmc/{id}/power', async () => {
    const sent = stubControlPlane({ [POWER]: ok({ status: 'ok', action: 'on' }) });
    const { result } = renderPower();

    let res: Awaited<ReturnType<typeof result.current.powerOn>> | undefined;
    await act(async () => {
      res = await result.current.powerOn();
    });

    expect(res?.data).toEqual({ status: 'ok', action: 'on' });
    expect(sent).toEqual([{ method: 'POST', path: '/api/v1/bmc/42/power', body: { action: 'on' } }]);
  });

  it('sends off, reset and cycle with their action', async () => {
    const sent = stubControlPlane({ [POWER]: ok({ status: 'ok', action: 'x' }) });
    const { result } = renderPower();

    await act(async () => {
      await result.current.powerOff();
      await result.current.reset();
      await result.current.cycle();
    });

    expect(sent.map((s) => s.body)).toEqual([{ action: 'off' }, { action: 'reset' }, { action: 'cycle' }]);
    expect(sent.every((s) => s.method === 'POST' && s.path === '/api/v1/bmc/42/power')).toBe(true);
  });

  it('surfaces an unknown profile', async () => {
    stubControlPlane({ [POWER]: refused(404, 'bmc: profile 42 not found') });
    const { result } = renderPower();

    let res: Awaited<ReturnType<typeof result.current.powerOn>> | undefined;
    await act(async () => {
      res = await result.current.powerOn();
    });

    expect(res?.success).toBe(false);
    expect(res?.error?.status).toBe(404);
    expect(res?.error?.message).toContain('not found');
  });

  it("surfaces the server's invalid action refusal", async () => {
    stubControlPlane({ [POWER]: refused(400, 'bmc: invalid action: on') });
    const { result } = renderPower();

    let res: Awaited<ReturnType<typeof result.current.run>> | undefined;
    await act(async () => {
      res = await result.current.run('on');
    });

    expect(res?.success).toBe(false);
    expect(res?.error?.status).toBe(400);
    expect(res?.error?.message).toBe('bmc: invalid action: on');
  });

  it('knows the four actions', () => {
    expect(BMC_POWER_ACTIONS).toEqual(['on', 'off', 'reset', 'cycle']);
    expect(isBMCPowerAction('cycle')).toBe(true);
    expect(isBMCPowerAction('shutdown')).toBe(false);
    expect(bmcPowerActionLabel('cycle')).toBe('Power cycle');
    expect(bmcPowerActionStopsHost('on')).toBe(false);
    expect(bmcPowerActionStopsHost('off')).toBe(true);
    expect(bmcPowerActionStopsHost('reset')).toBe(true);
    expect(bmcPowerActionStopsHost('cycle')).toBe(true);
  });

  it('escapes the profile id in the path', () => {
    expect(bmcPowerPath('7')).toBe('/v1/bmc/7/power');
    expect(bmcPowerPath('a/b')).toBe('/v1/bmc/a%2Fb/power');
  });
});
