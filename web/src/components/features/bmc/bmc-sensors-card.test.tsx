import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { BMCSensorsCard, formatSensorValue } from './bmc-sensors-card';

// #2039: the BMC sensors card reads GetSensors through the useBMCStatus hook
// on the SDK API client, lists the readings, and puts the ones whose status is
// not ok in a warning line and marks their rows.

const SENSORS = 'GET /api/v1/bmc/42/sensors';

const READINGS = [
  { name: 'CPU Temp', value: 48, units: 'C', status: 'ok' },
  { name: 'Fan 2', value: 0, units: 'RPM', status: 'critical' },
  { name: 'Inlet Temp', value: 31.25, units: 'C', status: 'warning' },
];

function stub(answer: Answer = ok(READINGS)) {
  return stubControlPlane({ [SENSORS]: answer });
}

function renderCard() {
  render(withControlPlane(<BMCSensorsCard profileID="42" />));
}

async function click(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

describe('BMCSensorsCard', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('lists the readings', async () => {
    stub();
    renderCard();

    await waitFor(() => expect(screen.getByTestId('bmc-sensors')).toBeDefined());
    const table = within(screen.getByTestId('bmc-sensors'));
    for (const text of ['CPU Temp', '48 C', 'Fan 2', '0 RPM', 'Inlet Temp', '31.3 C']) {
      expect(table.getByText(text)).toBeDefined();
    }
  });

  it('marks the readings needing attention', async () => {
    stub();
    renderCard();

    const line = await screen.findByTestId('bmc-sensors-attention');
    expect(line.textContent).toBe('2 sensors need attention: Fan 2, Inlet Temp');
    const table = within(screen.getByTestId('bmc-sensors'));
    expect(table.getByText('Fan 2').closest('tr')?.getAttribute('data-attention')).toBe('true');
    expect(table.getByText('Inlet Temp').closest('tr')?.getAttribute('data-attention')).toBe('true');
    expect(table.getByText('CPU Temp').closest('tr')?.hasAttribute('data-attention')).toBe(false);
  });

  it('says one sensor in the singular', async () => {
    stub(ok([READINGS[0], READINGS[1]]));
    renderCard();

    const line = await screen.findByTestId('bmc-sensors-attention');
    expect(line.textContent).toBe('1 sensor needs attention: Fan 2');
  });

  it('shows no attention line when all are ok', async () => {
    stub(ok(READINGS.map((r) => ({ ...r, status: 'ok' }))));
    renderCard();

    await waitFor(() => expect(screen.getByTestId('bmc-sensors')).toBeDefined());
    expect(screen.queryByTestId('bmc-sensors-attention')).toBeNull();
  });

  it('shows an empty list', async () => {
    stub(ok([]));
    renderCard();

    expect(await screen.findByText('No sensors reported.')).toBeDefined();
  });

  it('re-reads on Refresh', async () => {
    const sent = stub();
    renderCard();
    await waitFor(() => expect(screen.getByTestId('bmc-sensors')).toBeDefined());
    await waitFor(() => expect((screen.getByRole('button', { name: 'Refresh' }) as HTMLButtonElement).disabled).toBe(false));

    await click('Refresh');

    await waitFor(() =>
      expect(sent.filter((r) => r.method === 'GET' && r.path === '/api/v1/bmc/42/sensors')).toHaveLength(2)
    );
  });

  it('shows an unknown profile verbatim', async () => {
    stub(refused(404, 'bmc: profile not found: 42'));
    renderCard();

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('Sensors unavailable: bmc: profile not found: 42');
    expect(screen.queryByTestId('bmc-sensors')).toBeNull();
  });

  it('formats the values', () => {
    expect(formatSensorValue({ name: 'x', value: 12, units: 'V', status: 'ok' })).toBe('12 V');
    expect(formatSensorValue({ name: 'x', value: 3.04, units: 'V', status: 'ok' })).toBe('3.0 V');
    expect(formatSensorValue({ name: 'x', value: 7, units: '', status: 'ok' })).toBe('7');
  });
});
