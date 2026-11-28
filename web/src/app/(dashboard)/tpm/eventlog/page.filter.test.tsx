import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';

import TPMEventLogPage from './page';
import { ok, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';

const CAPS_ON = ok({ capabilities: [{ op: 'GET /api/v1/tpm/eventlog', kind: 'route', enabled: true }] });

// 250 parsed entries: five on PCR 7 (spread past the first 200 rows),
// the rest on PCR 0.
const pcr7Indexes = [3, 50, 199, 210, 249];

function entries() {
  return Array.from({ length: 250 }, (_, i) => ({
    eventNum: i,
    pcrIndex: pcr7Indexes.includes(i) ? 7 : 0,
    eventType: 'EV_ACTION',
    digestCount: 1,
    digests: [],
    eventSize: 8,
    eventString: `event-${i}`,
  }));
}

function bodyRows() {
  // Every row but the header row.
  return screen.getAllByRole('row').slice(1);
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('TPM event log page PCR filter', () => {
  it('narrows the table to the PCR typed into the filter', async () => {
    stubControlPlane({
      'GET /api/v1/capabilities': CAPS_ON,
      'GET /api/v1/tpm/eventlog': ok({ format: 'tcg2', eventCount: 250, entries: entries() }),
    });
    render(withControlPlane(<TPMEventLogPage />));

    await screen.findByText('event-0');
    expect(bodyRows()).toHaveLength(200);
    expect(screen.getByText(/Showing first 200 of 250 events/)).toBeTruthy();

    fireEvent.change(screen.getByLabelText('Filter by PCR'), { target: { value: '7' } });

    const rows = bodyRows();
    expect(rows).toHaveLength(5);
    for (const i of pcr7Indexes) {
      expect(screen.getByText(`event-${i}`)).toBeTruthy();
    }
    expect(screen.queryByText('event-0')).toBeNull();
    expect(screen.queryByText(/Showing first 200/)).toBeNull();
  });

  it('restores the first 200 rows when the filter is cleared', async () => {
    stubControlPlane({
      'GET /api/v1/capabilities': CAPS_ON,
      'GET /api/v1/tpm/eventlog': ok({ format: 'tcg2', eventCount: 250, entries: entries() }),
    });
    render(withControlPlane(<TPMEventLogPage />));

    await screen.findByText('event-0');
    const filter = screen.getByLabelText('Filter by PCR');
    fireEvent.change(filter, { target: { value: '7' } });
    expect(bodyRows()).toHaveLength(5);

    fireEvent.change(filter, { target: { value: '' } });
    expect(bodyRows()).toHaveLength(200);
    expect(screen.getByText('event-0')).toBeTruthy();
    expect(screen.queryByText('event-210')).toBeNull();
    expect(screen.getByText(/Showing first 200 of 250 events/)).toBeTruthy();
  });
});
