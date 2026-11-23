import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { CeremonyClaimCertCard } from './ceremony-claim-cert-card';
import { CeremonyClaimShareCard } from './ceremony-claim-share-card';
import { CeremonyInitCard } from './ceremony-init-card';
import { CeremonySignCSRCard } from './ceremony-sign-csr-card';

// #2042: every ceremony write control is wrapped in the capability gate, so an
// op the server does not offer is disabled with the server's reason.

vi.mock('next/navigation', () => ({
  useParams: () => ({}),
  usePathname: () => '/platform/ceremony',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

const INIT_OP = 'POST /api/v1/ceremony/init';
const SIGN_OP = 'POST /api/v1/ceremony/sign-csr';
const CERT_BEGIN_OP = 'POST /api/v1/ceremony/claim-cert/begin';
const SHARE_BEGIN_OP = 'POST /api/v1/ceremony/claim-share/begin';
const REASON = 'not-configured: ceremony';
const CSR = '-----BEGIN CERTIFICATE REQUEST-----\nTEST\n-----END CERTIFICATE REQUEST-----';

const CEREMONY_OPS = [
  INIT_OP,
  'GET /api/v1/ceremony/status',
  CERT_BEGIN_OP,
  'POST /api/v1/ceremony/claim-cert/complete',
  SHARE_BEGIN_OP,
  'POST /api/v1/ceremony/claim-share/complete',
  SIGN_OP,
] as const;

// The server's capabilities listing: every ceremony op enabled except those in off.
function caps(off: string[] = []): Answer {
  const capabilities = CEREMONY_OPS.map((op) =>
    off.includes(op) ? { op, kind: 'route', enabled: false, reason: REASON } : { op, kind: 'route', enabled: true },
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

function fill(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

function button(name: string): HTMLButtonElement {
  return screen.getByRole('button', { name }) as HTMLButtonElement;
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('ceremony write controls are capability-gated', () => {
  it('disables Initialize and Sign CSR when the server does not offer them', async () => {
    stubControlPlane({ 'GET /api/v1/capabilities': caps([INIT_OP, SIGN_OP]) });
    render(
      withControlPlane(
        <>
          <CeremonyInitCard />
          <CeremonySignCSRCard />
        </>,
      ),
    );

    fill('Username', 'officer1');
    fill('CSR (PEM)', CSR);
    for (const pin of screen.getAllByLabelText('SO PIN')) {
      fireEvent.change(pin, { target: { value: 'so-pin-test' } });
    }
    fill('Threshold', '3-of-5');

    for (const [name, op] of [
      ['Initialize', INIT_OP],
      ['Sign CSR', SIGN_OP],
    ] as const) {
      const btn = button(name);
      expect(btn.getAttribute('data-capability-op')).toBe(op);
      await waitFor(() => expect(btn.getAttribute('title')).toBe(REASON));
      expect(btn.getAttribute('data-capability-enabled')).toBe('false');
      expect(btn.disabled).toBe(true);
    }
  });

  it('disables Request challenge on both claim cards when the begin routes are off', async () => {
    stubControlPlane({ 'GET /api/v1/capabilities': caps([CERT_BEGIN_OP, SHARE_BEGIN_OP]) });
    render(
      withControlPlane(
        <>
          <CeremonyClaimCertCard />
          <CeremonyClaimShareCard />
        </>,
      ),
    );

    for (const username of screen.getAllByLabelText('Username')) {
      fireEvent.change(username, { target: { value: 'officer1' } });
    }

    const buttons = screen.getAllByRole('button', { name: 'Request challenge' }) as HTMLButtonElement[];
    expect(buttons).toHaveLength(2);
    expect(buttons.map((b) => b.getAttribute('data-capability-op'))).toEqual([CERT_BEGIN_OP, SHARE_BEGIN_OP]);
    for (const btn of buttons) {
      await waitFor(() => expect(btn.getAttribute('title')).toBe(REASON));
      expect(btn.getAttribute('data-capability-enabled')).toBe('false');
      expect(btn.disabled).toBe(true);
    }
  });

  it('leaves an offered control enabled and marks it', async () => {
    stubControlPlane({ 'GET /api/v1/capabilities': caps() });
    render(withControlPlane(<CeremonyInitCard />));

    fill('SO PIN', 'so-pin-test');
    fill('Threshold', '3-of-5');

    const btn = button('Initialize');
    expect(btn.getAttribute('data-capability-op')).toBe(INIT_OP);
    await waitFor(() => expect(btn).toHaveAttribute('data-capability-enabled', 'true'));
    expect(btn.disabled).toBe(false);
    expect(btn.getAttribute('title')).toBeNull();
  });
});
