import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import DeviceVerdictsPage from './page';

// #2038: after the server drops the cursor, a failed Resynchronize must keep
// the way to resume: Resynchronize and the device reports link stay, and a
// retry that succeeds resumes polling from the new head cursor.

vi.mock('next/navigation', () => ({
  useParams: () => ({}),
  usePathname: () => '/attestation/verdicts',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const OP = 'GET /api/v1/attestation/verdicts';

// The server's capabilities listing: the verdict poll op, off when off is set.
function caps(off = false): Answer {
  const capabilities = [
    off ? { op: OP, kind: 'route', enabled: false, reason: 'not-configured: attestation' } : { op: OP, kind: 'route', enabled: true },
  ];
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

function pollUrls(): URL[] {
  return vi
    .mocked(fetch)
    .mock.calls.map(([input]) => new URL(input instanceof Request ? input.url : String(input)))
    .filter((u) => u.pathname === '/api/v1/attestation/verdicts');
}

function verdict(eventId: string, serial: string, passed: boolean, cryptographic: boolean, reason: string) {
  return {
    eventId,
    recordedAt: '2026-11-01T00:00:00Z',
    deviceId: eventId,
    tenantId: 't1',
    hostId: 'h1',
    serial,
    passed,
    cryptographic,
    reason,
  };
}

describe('DeviceVerdictsPage resynchronize failure', () => {
  it('a failed Resynchronize keeps Resynchronize and the device reports, and a retry resumes polling', async () => {
    const routes: Record<string, Answer> = {
      'GET /api/v1/capabilities': caps(),
      [OP]: ok({ cursor: 'c1', verdicts: [verdict('e1', 'SN-1', true, false, '')] }),
    };
    stubControlPlane(routes);
    render(withControlPlane(<DeviceVerdictsPage />));

    expect(await screen.findByText('SN-1')).toBeTruthy();
    routes[OP] = refused(429, 'attestation: the device verdict follower fell behind and missed verdicts');
    fireEvent.click(screen.getByRole('button', { name: 'Check for new verdicts' }));
    await screen.findByTestId('verdicts-missed', {}, { timeout: 15000 });

    // 400, not 5xx: the SDK retries 5xx with backoff.
    routes[OP] = refused(400, 'resync refused');
    const first = await screen.findByRole('button', { name: 'Resynchronize' });
    await waitFor(() => expect((first as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(first);

    const card = await screen.findByTestId('verdicts-error');
    expect(card.textContent).toContain('resync refused');
    expect(screen.getByRole('button', { name: 'Resynchronize' })).toBeTruthy();
    expect(screen.getByRole('link', { name: 'Device reports' }).getAttribute('href')).toBe('/devices');

    routes[OP] = ok({ cursor: 'h1', verdicts: [verdict('e9', 'SN-9', true, false, '')] });
    const retry = screen.getByRole('button', { name: 'Resynchronize' });
    await waitFor(() => expect((retry as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(retry);

    await screen.findByTestId('verdicts-gap', {}, { timeout: 15000 });
    expect(screen.queryByTestId('verdicts-error')).toBeNull();
    expect(screen.getByText('SN-1')).toBeTruthy();
    expect(screen.getByText('SN-9')).toBeTruthy();
    const urls = pollUrls();
    expect(urls[urls.length - 1].searchParams.get('cursor')).toBeNull();
    const check = screen.getByRole('button', { name: 'Check for new verdicts' });
    await waitFor(() => expect((check as HTMLButtonElement).disabled).toBe(false));
  }, 20000);
});
