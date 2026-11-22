import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  ok,
  refused,
  stubControlPlane,
  withControlPlane,
  type Answer,
  type SentRequest,
} from '@/test/control-plane-fetch';
import { BMCPowerCard } from './bmc-power-card';

const POWER = 'POST /api/v1/bmc/42/power';
const POWER_OP = 'POST /api/v1/bmc/{profileID:[0-9]+}/power';
const NAMES = ['Power on', 'Power off', 'Reset', 'Power cycle'];

// The server's capabilities listing: the power op enabled unless off.
function caps(off = false): Answer {
  const capabilities = [
    off
      ? { op: POWER_OP, kind: 'route', enabled: false, reason: 'scope bmc:power required' }
      : { op: POWER_OP, kind: 'route', enabled: true },
  ];
  return ok({ capabilities, total: 1, enabled: off ? 0 : 1 });
}

function stub(routes: Record<string, Answer>, off = false): SentRequest[] {
  return stubControlPlane({ 'GET /api/v1/capabilities': caps(off), ...routes });
}

// bmc leaves the capabilities read out of the sent list.
function bmc(sent: SentRequest[]): SentRequest[] {
  return sent.filter((r) => r.path !== '/api/v1/capabilities');
}

function button(name: string): HTMLButtonElement {
  return screen.getByRole('button', { name }) as HTMLButtonElement;
}

async function click(name: string) {
  await act(async () => {
    fireEvent.click(button(name));
  });
}

async function renderCard(onChanged: () => void) {
  render(withControlPlane(<BMCPowerCard profileID="42" onChanged={onChanged} />));
  await waitFor(() => expect(button('Power on').disabled).toBe(false));
}

describe('BMCPowerCard', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('gates each power action on the server power op', async () => {
    stub({});
    await renderCard(vi.fn());
    for (const name of NAMES) {
      expect(button(name).getAttribute('data-capability-op')).toBe(POWER_OP);
      expect(button(name).getAttribute('data-capability-enabled')).toBe('true');
    }
  });

  it('disables the power actions when the server leaves the op out', async () => {
    const sent = stub({ [POWER]: ok({ status: 'ok', action: 'on' }) }, true);
    render(withControlPlane(<BMCPowerCard profileID="42" onChanged={vi.fn()} />));
    await waitFor(() => expect(button('Power on').title).toBe('scope bmc:power required'));
    for (const name of NAMES) {
      expect(button(name).disabled).toBe(true);
      expect(button(name).getAttribute('data-capability-enabled')).toBe('false');
    }
    await click('Power on');
    expect(bmc(sent)).toEqual([]);
  });

  it('shows the four power actions in order', async () => {
    const sent = stub({});
    await renderCard(vi.fn());
    expect(screen.getAllByRole('button').map((b) => b.textContent)).toEqual(NAMES);
    expect(bmc(sent)).toEqual([]);
  });

  it('powers on at once without a confirm', async () => {
    const sent = stub({ [POWER]: ok({ status: 'ok', action: 'on' }) });
    const onChanged = vi.fn();
    await renderCard(onChanged);

    await click('Power on');

    expect(screen.queryByRole('dialog')).toBeNull();
    const toast = await screen.findByText('Power on sent: BMC profile 42');
    expect(toast.getAttribute('data-variant')).toBe('success');
    expect(bmc(sent)).toEqual([{ method: 'POST', path: '/api/v1/bmc/42/power', body: { action: 'on' } }]);
    expect(onChanged).toHaveBeenCalledTimes(1);
  });

  it('asks before powering off and sends nothing on Cancel', async () => {
    const sent = stub({ [POWER]: ok({ status: 'ok', action: 'off' }) });
    const onChanged = vi.fn();
    await renderCard(onChanged);

    await click('Power off');
    const dialog = await screen.findByRole('dialog');
    expect(dialog.textContent).toContain('Power off?');
    expect(dialog.textContent).toContain('This stops the host behind BMC profile 42.');

    await click('Cancel');
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(bmc(sent)).toEqual([]);
    expect(onChanged).not.toHaveBeenCalled();
  });

  it('sends off, reset and cycle after the confirm', async () => {
    const sent = stub({ [POWER]: ok({ status: 'ok', action: 'off' }) });
    const onChanged = vi.fn();
    await renderCard(onChanged);

    const names = ['Power off', 'Reset', 'Power cycle'];
    for (let i = 0; i < names.length; i++) {
      await click(names[i]);
      await screen.findByRole('dialog');
      await click('Confirm');
      await waitFor(() => expect(bmc(sent).length).toBe(i + 1));
      await waitFor(() => expect(onChanged).toHaveBeenCalledTimes(i + 1));
      await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    }

    expect(bmc(sent).map((s) => s.body)).toEqual([{ action: 'off' }, { action: 'reset' }, { action: 'cycle' }]);
    expect(onChanged).toHaveBeenCalledTimes(3);
  });

  it('shows an unknown profile as a destructive toast', async () => {
    stub({ [POWER]: refused(404, 'bmc: profile 42 not found') });
    const onChanged = vi.fn();
    await renderCard(onChanged);

    await click('Power on');

    const toast = await screen.findByText('Power on failed: bmc: profile 42 not found');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(onChanged).not.toHaveBeenCalled();
  });

  it('shows a conflict on power cycle verbatim', async () => {
    stub({ [POWER]: refused(409, 'bmc: power cycle refused while provisioning') });
    const onChanged = vi.fn();
    await renderCard(onChanged);

    await click('Power cycle');
    await screen.findByRole('dialog');
    await click('Confirm');

    const toast = await screen.findByText('Power cycle failed: bmc: power cycle refused while provisioning');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    await waitFor(() => expect(button('Power on').disabled).toBe(false));
    expect(onChanged).not.toHaveBeenCalled();
  });
});
