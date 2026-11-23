import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import DeviceVerdictsPage from './page';

// #2038: the device verdicts page polls PollDeviceVerdicts
// (GET /api/v1/attestation/verdicts) through the real SDK client on
// client.attestation, only when the server offers the route, and each
// further poll continues from the cursor of the previous answer.

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

function count(sent: { method: string; path: string }[], method: string, path: string) {
  return sent.filter((r) => r.method === method && r.path === path).length;
}

// The URLs of every verdict poll the stubbed fetch received, in order.
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

describe('DeviceVerdictsPage', () => {
  it('lists the verdicts the first poll answers', async () => {
    stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      [OP]: ok({
        cursor: 'c1',
        verdicts: [
          { eventId: 'e1', recordedAt: '2026-11-01T00:00:00Z', deviceId: '7', tenantId: 't1', hostId: 'h1', serial: 'SN-1', passed: true, cryptographic: false, reason: '' },
          { eventId: 'e2', recordedAt: '2026-11-01T00:01:00Z', deviceId: '8', tenantId: 't1', hostId: 'h1', serial: 'SN-2', passed: false, cryptographic: true, reason: 'pcr mismatch' },
        ],
      }),
    });
    render(withControlPlane(<DeviceVerdictsPage />));

    const first = (await screen.findByText('SN-1')).closest('tr') as HTMLElement;
    expect(first.textContent).toContain('Passed');
    const second = screen.getByText('SN-2').closest('tr') as HTMLElement;
    expect(second.textContent).toContain('Failed');
    expect(second.textContent).toContain('Compromise');
    expect(second.textContent).toContain('pcr mismatch');
    expect(screen.getByTestId('verdicts-table')).toBeTruthy();
    expect(screen.getByTestId('verdict-e1').textContent).toContain('SN-1');
    expect(screen.getByTestId('verdict-e2').textContent).toContain('SN-2');
  });

  it('appends the next poll from the previous cursor', async () => {
    const routes: Record<string, Answer> = {
      'GET /api/v1/capabilities': caps(),
      [OP]: ok({ cursor: 'c1', verdicts: [verdict('e1', 'SN-1', true, false, '')] }),
    };
    stubControlPlane(routes);
    render(withControlPlane(<DeviceVerdictsPage />));

    expect(await screen.findByText('SN-1')).toBeTruthy();
    routes[OP] = ok({ cursor: 'c2', verdicts: [verdict('e3', 'SN-3', false, false, 'stale quote')] });
    fireEvent.click(screen.getByRole('button', { name: 'Check for new verdicts' }));

    expect(await screen.findByText('SN-3')).toBeTruthy();
    expect(screen.getByText('SN-1')).toBeTruthy();
    const urls = pollUrls();
    expect(urls.length).toBe(2);
    expect(urls[1].searchParams.get('cursor')).toBe('c1');
    expect(urls[1].searchParams.get('wait_ms')).toBe('0');
  });

  it('shows a not-enabled card and sends no poll when the server does not offer the route', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/capabilities': caps(true),
      [OP]: ok({ cursor: 'c1', verdicts: [] }),
    });
    render(withControlPlane(<DeviceVerdictsPage />));

    expect((await screen.findByTestId('verdicts-not-enabled')).textContent).toContain('not-configured: attestation');
    expect(count(sent, 'GET', '/api/v1/attestation/verdicts')).toBe(0);
    const button = screen.getByRole('button', { name: 'Check for new verdicts' });
    await waitFor(() => expect(button.getAttribute('data-capability-enabled')).toBe('false'));
    expect(button.getAttribute('data-capability-op')).toBe(OP);
  });

  it('shows the server refusal', async () => {
    stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      // 400, not the server's 503: the SDK retries 5xx with backoff (retryableStatuses).
      [OP]: refused(400, 'no verdict poller'),
    });
    render(withControlPlane(<DeviceVerdictsPage />));

    const card = await screen.findByTestId('verdicts-error');
    expect(card.textContent).toContain('no verdict poller');
  });
});
