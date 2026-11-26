import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { BMCSystemCard, powerStateLabel } from './bmc-system-card';

// #2039: the BMC system card reads PowerStatus and GetSystemInfo through the
// useBMCStatus hook on the SDK API client, on mount and on Refresh, and shows
// a refusal verbatim.

const POWER = 'GET /api/v1/bmc/42/power';
const SYSTEM_INFO = 'GET /api/v1/bmc/42/system-info';

function systemInfo(overrides: Record<string, string> = {}): Answer {
  return ok({
    manufacturer: 'Example Corp',
    product: 'X100',
    serial_number: 'SN-0001',
    firmware_version: '2.10',
    bios_version: '1.4.2',
    power_state: 'on',
    ...overrides,
  });
}

function baseRoutes(): Record<string, Answer> {
  return { [POWER]: ok({ state: 'on' }), [SYSTEM_INFO]: systemInfo() };
}

function renderCard() {
  render(withControlPlane(<BMCSystemCard profileID="42" />));
}

async function click(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

function count(sent: { method: string; path: string }[], method: string, path: string) {
  return sent.filter((r) => r.method === method && r.path === path).length;
}

describe('BMCSystemCard', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('shows the power state and the system info on mount', async () => {
    stubControlPlane(baseRoutes());
    renderCard();

    await waitFor(() => expect(screen.getByTestId('bmc-power-state').textContent).toContain('On'));
    await waitFor(() => expect(screen.getByTestId('bmc-system-info')).toBeDefined());
    const info = within(screen.getByTestId('bmc-system-info'));
    for (const text of ['Example Corp', 'X100', 'SN-0001', '2.10', '1.4.2']) {
      expect(info.getByText(text)).toBeDefined();
    }
    expect(screen.getByText('BMC system')).toBeDefined();
    expect(screen.getByText('BMC profile 42')).toBeDefined();
  });

  it('shows an off host', async () => {
    stubControlPlane({ ...baseRoutes(), [POWER]: ok({ state: 'off' }) });
    renderCard();

    await waitFor(() => expect(screen.getByTestId('bmc-power-state').textContent).toContain('Off'));
  });

  it('re-reads both on Refresh', async () => {
    const sent = stubControlPlane(baseRoutes());
    renderCard();
    await waitFor(() => expect(screen.getByTestId('bmc-system-info')).toBeDefined());
    await waitFor(() => expect((screen.getByRole('button', { name: 'Refresh' }) as HTMLButtonElement).disabled).toBe(false));

    await click('Refresh');

    await waitFor(() => {
      expect(count(sent, 'GET', '/api/v1/bmc/42/power')).toBe(2);
      expect(count(sent, 'GET', '/api/v1/bmc/42/system-info')).toBe(2);
    });
  });

  it('shows an unknown profile verbatim', async () => {
    stubControlPlane({
      [POWER]: refused(404, 'bmc: profile not found: 42'),
      [SYSTEM_INFO]: refused(404, 'bmc: profile not found: 42'),
    });
    renderCard();

    await waitFor(() =>
      expect(screen.getByTestId('bmc-power-state').textContent).toContain(
        'Power state unavailable: bmc: profile not found: 42'
      )
    );
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('System info unavailable: bmc: profile not found: 42');
    expect(screen.queryByTestId('bmc-system-info')).toBeNull();
  });

  it('shows a blank field as a dash', async () => {
    stubControlPlane({ ...baseRoutes(), [SYSTEM_INFO]: systemInfo({ bios_version: '' }) });
    renderCard();

    await waitFor(() => expect(screen.getByTestId('bmc-system-info')).toBeDefined());
    const bios = within(screen.getByTestId('bmc-system-info')).getByText('BIOS');
    expect(bios.nextElementSibling?.textContent).toBe('-');
  });

  it('labels the power states', () => {
    expect(powerStateLabel('on')).toBe('On');
    expect(powerStateLabel('off')).toBe('Off');
    expect(powerStateLabel('unknown')).toBe('Unknown');
    expect(powerStateLabel('')).toBe('Unknown');
  });
});
