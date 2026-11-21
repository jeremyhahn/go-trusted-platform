import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { GatewayModeCard } from './gateway-mode-card';

// #2051: the gateway mode card sets the Overlay / Edge / Transit modes
// through the SDK GatewayService after the operator confirms, and shows a
// refusal verbatim.

const MODE_PATH = 'POST /api/v1/gateway/mode';

async function clickButton(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

async function clickMode(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('checkbox', { name }));
  });
}

describe('GatewayModeCard', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('keeps Apply disabled until a mode is picked', async () => {
    stubControlPlane({});
    render(withControlPlane(<GatewayModeCard />));

    const apply = screen.getByRole('button', { name: 'Apply modes' });
    expect((apply as HTMLButtonElement).disabled).toBe(true);
    await clickMode('Edge');
    expect((apply as HTMLButtonElement).disabled).toBe(false);
    await clickMode('Edge');
    expect((apply as HTMLButtonElement).disabled).toBe(true);
  });

  it('asks before setting the modes and sends nothing on Cancel', async () => {
    const sent = stubControlPlane({
      [MODE_PATH]: ok({ status: { success: true, message: 'gateway modes updated successfully' } }),
    });
    render(withControlPlane(<GatewayModeCard />));

    await clickMode('Overlay');
    await clickMode('Edge');
    await clickButton('Apply modes');

    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText('Change the gateway modes?')).toBeDefined();
    expect(within(dialog).getByText(/Overlay \+ Edge/)).toBeDefined();

    await clickButton('Cancel');
    expect(sent.some((r) => r.method === 'POST')).toBe(false);
  });

  it('sets the modes after the confirm', async () => {
    const sent = stubControlPlane({
      [MODE_PATH]: ok({
        status: { success: true, message: 'gateway modes updated successfully' },
        gatewayStatus: { id: 'gw1', nodeId: 'n1', modes: 3, reputation: 1, uptimeSeconds: 10 },
      }),
    });
    render(withControlPlane(<GatewayModeCard />));

    await clickMode('Edge');
    await clickMode('Overlay');
    await clickButton('Apply modes');
    await screen.findByRole('dialog');
    await clickButton('Confirm');

    const toast = await screen.findByText('Gateway modes set: Overlay + Edge');
    expect(toast.getAttribute('data-variant')).toBe('success');
    const posts = sent.filter((r) => r.method === 'POST');
    expect(posts).toHaveLength(1);
    expect(posts[0].path).toBe('/api/v1/gateway/mode');
    expect(posts[0].body).toEqual({ modes: 3 });
  });

  it('starts from the initial modes', () => {
    stubControlPlane({});
    render(withControlPlane(<GatewayModeCard initialModes={['TRANSIT']} />));

    expect(screen.getByRole('checkbox', { name: 'Transit' }).getAttribute('data-state')).toBe('checked');
    expect(screen.getByRole('checkbox', { name: 'Overlay' }).getAttribute('data-state')).toBe('unchecked');
    expect((screen.getByRole('button', { name: 'Apply modes' }) as HTMLButtonElement).disabled).toBe(false);
  });

  it('shows a refusal verbatim', async () => {
    stubControlPlane({ [MODE_PATH]: refused(400, 'modes is required') });
    render(withControlPlane(<GatewayModeCard />));

    await clickMode('Edge');
    await clickButton('Apply modes');
    await screen.findByRole('dialog');
    await clickButton('Confirm');

    const toast = await screen.findByText('Set gateway modes failed: modes is required');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
  });
});
