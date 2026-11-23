import { cleanup, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import TPMEventLogPage from './page';

// #2069: the event log page reads GET /api/v1/tpm/eventlog only when the server offers it, and shows the server's reason otherwise.

const READ = 'GET /api/v1/tpm/eventlog';
const REASON = 'not-configured: tpm';

function caps(off: string[] = []): Answer {
  const capabilities = [READ].map((op) =>
    off.includes(op) ? { op, kind: 'route', enabled: false, reason: REASON } : { op, kind: 'route', enabled: true }
  );
  return ok({ capabilities });
}

const LOG = ok({
  format: 'tcg2',
  eventCount: 1,
  entries: [
    {
      eventNum: 0,
      pcrIndex: 7,
      eventType: 'EV_ACTION',
      digestCount: 1,
      digests: [],
      eventSize: 8,
      eventString: 'event-0',
    },
  ],
});

function refreshButton(): HTMLElement {
  return screen.getByRole('button', { name: /Refresh/ });
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('TPM event log page capability gate', () => {
  it('does not read the event log and shows the server reason when the read is not offered', async () => {
    const sent = stubControlPlane({ 'GET /api/v1/capabilities': caps([READ]), [READ]: LOG });
    render(withControlPlane(<TPMEventLogPage />));

    const reason = await screen.findByText(REASON);
    expect(screen.getByTestId('eventlog-withheld').contains(reason)).toBe(true);

    await waitFor(() => expect(refreshButton().getAttribute('data-capability-enabled')).toBe('false'));
    const refresh = refreshButton();
    expect(refresh.getAttribute('title')).toBe(REASON);
    expect(refresh.hasAttribute('disabled')).toBe(true);
    expect(refresh.getAttribute('data-capability-op')).toBe(READ);

    expect(sent.some((r) => r.method === 'GET' && r.path === '/api/v1/tpm/eventlog')).toBe(false);
    expect(screen.queryByText('event-0')).toBeNull();
  });

  it('reads the event log and offers Refresh when the server offers the read', async () => {
    stubControlPlane({ 'GET /api/v1/capabilities': caps(), [READ]: LOG });
    render(withControlPlane(<TPMEventLogPage />));

    await screen.findByText('event-0');
    await waitFor(() => expect(refreshButton().getAttribute('data-capability-enabled')).toBe('true'));
    expect(refreshButton().hasAttribute('disabled')).toBe(false);
    expect(screen.queryByTestId('eventlog-withheld')).toBeNull();
  });
});
