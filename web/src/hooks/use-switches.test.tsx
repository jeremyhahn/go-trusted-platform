import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ReactNode } from 'react';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { useSwitches } from './use-switches';

const PORTS = [
  { port: 'Eth1/1', mode: 'access', access_vlan: 10, enabled: true, link_up: true },
  { port: 'Eth1/2', mode: 'access', access_vlan: 10, enabled: false, link_up: false },
];

const LIST = '/api/v1/switches/core-1/ports';
const LIST_ROUTE = `GET ${LIST}`;
const LIST_SENT = { method: 'GET', path: LIST, body: undefined };

function renderSwitches(switchName = 'core-1') {
  return renderHook(() => useSwitches(switchName), {
    wrapper: ({ children }: { children: ReactNode }) => withControlPlane(children),
  });
}

async function renderLoaded() {
  const view = renderSwitches();
  await waitFor(() => expect(view.result.current.ports).toEqual(PORTS));
  return view;
}

describe('useSwitches', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('lists the ports of the named switch', async () => {
    const sent = stubControlPlane({ [LIST_ROUTE]: ok(PORTS) });
    const { result } = await renderLoaded();
    expect(result.current.ports).toEqual(PORTS);
    expect(sent).toEqual([LIST_SENT]);
  });

  it('moves a port to a VLAN and re-reads the ports', async () => {
    const sent = stubControlPlane({
      [LIST_ROUTE]: ok(PORTS),
      [`POST ${LIST}/Eth1%2F1/vlan`]: ok({ switch: 'core-1', port: 'Eth1/1', vlan_id: 20, status: 'ok' }),
    });
    const { result } = await renderLoaded();
    await act(() => result.current.setPortVLAN('Eth1/1', 20));
    expect(sent).toEqual([
      LIST_SENT,
      { method: 'POST', path: `${LIST}/Eth1%2F1/vlan`, body: { vlan_id: 20 } },
      LIST_SENT,
    ]);
  });

  it('enables and disables a port and re-reads the ports', async () => {
    const sent = stubControlPlane({
      [LIST_ROUTE]: ok(PORTS),
      [`POST ${LIST}/Eth1%2F2/enable`]: ok({ switch: 'core-1', port: 'Eth1/2', status: 'ok' }),
      [`POST ${LIST}/Eth1%2F1/disable`]: ok({ switch: 'core-1', port: 'Eth1/1', status: 'ok' }),
    });
    const { result } = await renderLoaded();
    await act(() => result.current.enablePort('Eth1/2'));
    await act(() => result.current.disablePort('Eth1/1'));
    expect(sent).toEqual([
      LIST_SENT,
      { method: 'POST', path: `${LIST}/Eth1%2F2/enable`, body: {} },
      LIST_SENT,
      { method: 'POST', path: `${LIST}/Eth1%2F1/disable`, body: {} },
      LIST_SENT,
    ]);
  });

  it('reads one port status', async () => {
    stubControlPlane({
      [LIST_ROUTE]: ok(PORTS),
      [`GET ${LIST}/Eth1%2F1`]: ok(PORTS[0]),
    });
    const { result } = await renderLoaded();
    let status: unknown;
    await act(async () => {
      status = await result.current.getPortStatus('Eth1/1');
    });
    expect(status).toEqual(PORTS[0]);
  });

  it('rejects a refused write with the server message and does not re-read', async () => {
    const sent = stubControlPlane({
      [LIST_ROUTE]: ok(PORTS),
      [`POST ${LIST}/Eth1%2F1/vlan`]: refused(409, 'port is a trunk'),
    });
    const { result } = await renderLoaded();
    let caught: unknown;
    await act(async () => {
      try {
        await result.current.setPortVLAN('Eth1/1', 20);
      } catch (err) {
        caught = err;
      }
    });
    expect(caught).toBeInstanceOf(Error);
    expect((caught as Error).message).toContain('port is a trunk');
    expect(sent).toEqual([
      LIST_SENT,
      { method: 'POST', path: `${LIST}/Eth1%2F1/vlan`, body: { vlan_id: 20 } },
    ]);
  });

  it('sends nothing for a VLAN out of range', async () => {
    const sent = stubControlPlane({ [LIST_ROUTE]: ok(PORTS) });
    const { result } = await renderLoaded();
    let caught: unknown;
    await act(async () => {
      try {
        await result.current.setPortVLAN('Eth1/1', 4095);
      } catch (err) {
        caught = err;
      }
    });
    expect(caught).toBeInstanceOf(RangeError);
    expect(sent).toEqual([LIST_SENT]);
  });
});
