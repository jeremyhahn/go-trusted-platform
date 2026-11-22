import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import AttestationVerdictsPage from './page';

const CALLERS = 'GET /api/v1/attestation/callers';
const VERDICTS = 'GET /api/v1/attestation/verdicts';

const LIST_POLICY = ok({
  strategy: 'list',
  identities: ['spiffe://example.org/host/a', 'spiffe://example.org/host/b'],
  identities_source: 'config',
  list_valid: true,
  anchors_configured: true,
  attested_peers_available: false,
  admits_nobody: false,
});

const E1 = {
  eventId: 'e1',
  recordedAt: '2026-11-20T10:00:00Z',
  deviceId: '18446744073709551615',
  tenantId: 't1',
  hostId: 'h1',
  serial: 'S1',
  passed: false,
  cryptographic: true,
  reason: 'pcr 7 mismatch',
};

const E2 = {
  eventId: 'e2',
  recordedAt: '2026-11-20T11:00:00Z',
  deviceId: '2',
  tenantId: 't1',
  hostId: 'h2',
  serial: 'S2',
  passed: true,
  cryptographic: true,
  reason: '',
};

const E3 = {
  eventId: 'e3',
  recordedAt: '2026-11-20T12:00:00Z',
  deviceId: '3',
  tenantId: 't1',
  hostId: 'h3',
  serial: 'S3',
  passed: true,
  cryptographic: false,
  reason: '',
};

function routesWith(over: Record<string, Answer> = {}): Record<string, Answer> {
  return {
    [CALLERS]: LIST_POLICY,
    [VERDICTS]: ok({ cursor: 'c1', verdicts: [E1, E2] }),
    ...over,
  };
}

/** queries lists the query string of every verdicts request the page sent. */
function queries(): string[] {
  return vi
    .mocked(globalThis.fetch)
    .mock.calls.map(([input]) => new URL(input instanceof Request ? input.url : String(input)))
    .filter((u) => u.pathname.endsWith('/verdicts'))
    .map((u) => u.search);
}

function bodyRows(): HTMLElement[] {
  return within(screen.getByTestId('device-verdicts')).getAllByRole('row').slice(1);
}

function renderPage() {
  return render(withControlPlane(<AttestationVerdictsPage />));
}

describe('AttestationVerdictsPage', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('shows the caller policy', async () => {
    stubControlPlane(routesWith());
    renderPage();
    const policy = screen.getByTestId('caller-policy');
    expect(await within(policy).findByText('list: 2 identities')).toBeTruthy();
    expect(within(policy).getByText('spiffe://example.org/host/a')).toBeTruthy();
    expect(within(policy).getByText('spiffe://example.org/host/b')).toBeTruthy();
    expect(within(policy).getByText('config')).toBeTruthy();
    expect(within(policy).getByText('Anchors configured').nextElementSibling?.textContent).toBe('Yes');
    expect(within(policy).getByText('Attested peers').nextElementSibling?.textContent).toBe('No');
  });

  it('shows the verdicts newest first', async () => {
    stubControlPlane(routesWith());
    renderPage();
    const verdicts = screen.getByTestId('device-verdicts');
    expect(await within(verdicts).findByText('S2')).toBeTruthy();
    const [first, second] = bodyRows();
    expect(within(first).getByText('S2')).toBeTruthy();
    expect(within(first).getByText('Passed')).toBeTruthy();
    expect(within(second).getByText('18446744073709551615')).toBeTruthy();
    expect(within(second).getByText('Failed')).toBeTruthy();
    expect(within(second).getByText('pcr 7 mismatch')).toBeTruthy();
    expect(within(verdicts).getByText('Cursor: c1')).toBeTruthy();
    expect(queries()).toEqual(['?wait_ms=0']);
  });

  it('polls from the cursor and adds only new verdicts', async () => {
    const routes = routesWith();
    stubControlPlane(routes);
    renderPage();
    const verdicts = screen.getByTestId('device-verdicts');
    expect(await within(verdicts).findByText('Cursor: c1')).toBeTruthy();
    routes[VERDICTS] = ok({ cursor: 'c2', verdicts: [E2, E3] });
    fireEvent.click(screen.getByRole('button', { name: /Poll for new verdicts/ }));
    expect(await within(verdicts).findByText('Cursor: c2')).toBeTruthy();
    const rows = bodyRows();
    expect(rows).toHaveLength(3);
    expect(within(rows[0]).getByText('S3')).toBeTruthy();
    expect(within(rows[0]).getByText('Policy')).toBeTruthy();
    expect(queries()).toEqual(['?wait_ms=0', '?cursor=c1&wait_ms=0']);
  });

  it('refresh starts again from the beginning', async () => {
    const sent = stubControlPlane(routesWith());
    renderPage();
    expect(await within(screen.getByTestId('device-verdicts')).findByText('Cursor: c1')).toBeTruthy();
    expect(await within(screen.getByTestId('caller-policy')).findByText('list: 2 identities')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: /Refresh/ }));
    await waitFor(() => expect(queries()).toEqual(['?wait_ms=0', '?wait_ms=0']));
    await waitFor(() =>
      expect(sent.filter((s) => s.path === '/api/v1/attestation/callers')).toHaveLength(2)
    );
  });

  it('shows the no-tenant refusal', async () => {
    stubControlPlane(
      routesWith({
        [VERDICTS]: refused(403, 'attestation: device verdicts denied: the session names no tenant'),
      })
    );
    renderPage();
    const alert = await within(screen.getByTestId('device-verdicts')).findByRole('alert');
    expect(alert.textContent).toContain('attestation: device verdicts denied: the session names no tenant');
    expect(await within(screen.getByTestId('caller-policy')).findByText('list: 2 identities')).toBeTruthy();
  });

  it('shows a policy that admits nobody and a refused callers read', async () => {
    stubControlPlane(
      routesWith({
        [CALLERS]: ok({
          strategy: 'none',
          identities: [],
          list_valid: true,
          anchors_configured: false,
          attested_peers_available: false,
          admits_nobody: true,
        }),
      })
    );
    renderPage();
    const policy = screen.getByTestId('caller-policy');
    expect(await within(policy).findByText('Admits no caller')).toBeTruthy();
    expect(within(policy).getByText('None')).toBeTruthy();

    cleanup();
    vi.unstubAllGlobals();
    stubControlPlane(routesWith({ [CALLERS]: refused(403, 'attestation: admin scope required') }));
    renderPage();
    const alert = await within(screen.getByTestId('caller-policy')).findByRole('alert');
    expect(alert.textContent).toContain('attestation: admin scope required');
  });
});
