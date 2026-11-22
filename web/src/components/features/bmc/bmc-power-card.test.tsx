import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { BMCPowerCard } from './bmc-power-card';

const POWER = 'POST /api/v1/bmc/42/power';

async function click(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

function renderCard(onChanged: () => void) {
  render(withControlPlane(<BMCPowerCard profileID="42" onChanged={onChanged} />));
}

describe('BMCPowerCard', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('shows the four power actions in order', () => {
    const sent = stubControlPlane({});
    renderCard(vi.fn());
    expect(screen.getAllByRole('button').map((b) => b.textContent)).toEqual([
      'Power on',
      'Power off',
      'Reset',
      'Power cycle',
    ]);
    expect(sent).toEqual([]);
  });

  it('powers on at once without a confirm', async () => {
    const sent = stubControlPlane({ [POWER]: ok({ status: 'ok', action: 'on' }) });
    const onChanged = vi.fn();
    renderCard(onChanged);

    await click('Power on');

    expect(screen.queryByRole('dialog')).toBeNull();
    const toast = await screen.findByText('Power on sent: BMC profile 42');
    expect(toast.getAttribute('data-variant')).toBe('success');
    expect(sent).toEqual([{ method: 'POST', path: '/api/v1/bmc/42/power', body: { action: 'on' } }]);
    expect(onChanged).toHaveBeenCalledTimes(1);
  });

  it('asks before powering off and sends nothing on Cancel', async () => {
    const sent = stubControlPlane({ [POWER]: ok({ status: 'ok', action: 'off' }) });
    const onChanged = vi.fn();
    renderCard(onChanged);

    await click('Power off');
    const dialog = await screen.findByRole('dialog');
    expect(dialog.textContent).toContain('Power off?');
    expect(dialog.textContent).toContain('This stops the host behind BMC profile 42.');

    await click('Cancel');
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(sent).toEqual([]);
    expect(onChanged).not.toHaveBeenCalled();
  });

  it('sends off, reset and cycle after the confirm', async () => {
    const sent = stubControlPlane({ [POWER]: ok({ status: 'ok', action: 'off' }) });
    const onChanged = vi.fn();
    renderCard(onChanged);

    const names = ['Power off', 'Reset', 'Power cycle'];
    for (let i = 0; i < names.length; i++) {
      await click(names[i]);
      await screen.findByRole('dialog');
      await click('Confirm');
      await waitFor(() => expect(sent.length).toBe(i + 1));
      await waitFor(() => expect(onChanged).toHaveBeenCalledTimes(i + 1));
      await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    }

    expect(sent.map((s) => s.body)).toEqual([{ action: 'off' }, { action: 'reset' }, { action: 'cycle' }]);
    expect(onChanged).toHaveBeenCalledTimes(3);
  });

  it('shows an unknown profile as a destructive toast', async () => {
    stubControlPlane({ [POWER]: refused(404, 'bmc: profile 42 not found') });
    const onChanged = vi.fn();
    renderCard(onChanged);

    await click('Power on');

    const toast = await screen.findByText('Power on failed: bmc: profile 42 not found');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(onChanged).not.toHaveBeenCalled();
  });

  it('shows a conflict on power cycle verbatim', async () => {
    stubControlPlane({ [POWER]: refused(409, 'bmc: power cycle refused while provisioning') });
    const onChanged = vi.fn();
    renderCard(onChanged);

    await click('Power cycle');
    await screen.findByRole('dialog');
    await click('Confirm');

    const toast = await screen.findByText('Power cycle failed: bmc: power cycle refused while provisioning');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    await waitFor(() =>
      expect((screen.getByRole('button', { name: 'Power on' }) as HTMLButtonElement).disabled).toBe(false)
    );
    expect(onChanged).not.toHaveBeenCalled();
  });
});
