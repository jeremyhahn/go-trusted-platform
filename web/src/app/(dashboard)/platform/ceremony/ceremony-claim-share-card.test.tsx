import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  ok,
  refused,
  stubControlPlane,
  withControlPlane,
  type Answer,
  type SentRequest,
} from '@/test/control-plane-fetch';
import { CeremonyClaimShareCard } from './ceremony-claim-share-card';

// #2042: an officer claims their key share through
// CeremonyService.ClaimShareBegin/ClaimShareComplete on useCeremony(); the
// share is shown once and never stored.

vi.mock('next/navigation', () => ({
  useParams: () => ({}),
  usePathname: () => '/platform/ceremony',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

const BEGIN_PATH = 'POST /api/v1/ceremony/claim-share/begin';
const COMPLETE_PATH = 'POST /api/v1/ceremony/claim-share/complete';

const CAPS_PATH = 'GET /api/v1/capabilities';
const CEREMONY_OPS = [
  'POST /api/v1/ceremony/init',
  'GET /api/v1/ceremony/status',
  'POST /api/v1/ceremony/claim-cert/begin',
  'POST /api/v1/ceremony/claim-cert/complete',
  'POST /api/v1/ceremony/claim-share/begin',
  'POST /api/v1/ceremony/claim-share/complete',
  'POST /api/v1/ceremony/sign-csr',
] as const;

// The server's capabilities listing: every ceremony op enabled except those in off.
function caps(off: string[] = []): Answer {
  const capabilities = CEREMONY_OPS.map((op) =>
    off.includes(op)
      ? { op, kind: 'route', enabled: false, reason: 'not-configured: ceremony' }
      : { op, kind: 'route', enabled: true },
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

// The requests the card sent, without the capability gate's read of the listing.
function writes(sent: SentRequest[]): SentRequest[] {
  return sent.filter((r) => !(r.method === 'GET' && r.path === '/api/v1/capabilities'));
}

// The capability gate marks a control off until the capabilities answer is
// in; wait until it no longer does (an ungated control carries no mark).
async function offered(btn: HTMLElement) {
  await waitFor(() => expect(btn.getAttribute('data-capability-enabled')).not.toBe('false'));
}

async function click(name: string) {
  const btn = button(name);
  await offered(btn);
  fireEvent.click(btn);
}

function value(label: string): string {
  return (screen.getByLabelText(label) as HTMLInputElement | HTMLTextAreaElement).value;
}

function button(name: string): HTMLButtonElement {
  return screen.getByRole('button', { name }) as HTMLButtonElement;
}

async function requestChallenge() {
  fireEvent.change(screen.getByLabelText('Username'), { target: { value: ' officer1 ' } });
  await click('Request challenge');
  await screen.findByLabelText('Nonce');
}

describe('CeremonyClaimShareCard', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('keeps Request challenge disabled until a username is set', async () => {
    stubControlPlane({ [CAPS_PATH]: caps() });
    render(withControlPlane(<CeremonyClaimShareCard />));
    await offered(button('Request challenge'));

    expect(button('Request challenge').disabled).toBe(true);
    fireEvent.change(screen.getByLabelText('Username'), { target: { value: '  ' } });
    expect(button('Request challenge').disabled).toBe(true);
    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'officer1' } });
    expect(button('Request challenge').disabled).toBe(false);
  });

  it('requests a share challenge', async () => {
    const sent = stubControlPlane({ [CAPS_PATH]: caps(), [BEGIN_PATH]: ok({ nonce: 'nonce-2' }) });
    render(withControlPlane(<CeremonyClaimShareCard />));

    await requestChallenge();
    expect(writes(sent)).toEqual([
      { method: 'POST', path: '/api/v1/ceremony/claim-share/begin', body: { username: 'officer1' } },
    ]);
    expect(value('Nonce')).toBe('nonce-2');
    expect(screen.queryByLabelText('Expires at')).toBeNull();
  });

  it('keeps Complete claim disabled until a signature is set', async () => {
    stubControlPlane({ [CAPS_PATH]: caps(), [BEGIN_PATH]: ok({ nonce: 'nonce-2' }) });
    render(withControlPlane(<CeremonyClaimShareCard />));

    await requestChallenge();
    expect(button('Complete claim').disabled).toBe(true);
    fireEvent.change(screen.getByLabelText('Signature (base64)'), { target: { value: '  ' } });
    expect(button('Complete claim').disabled).toBe(true);
    fireEvent.change(screen.getByLabelText('Signature (base64)'), { target: { value: 'c2lnLXRlc3Q=' } });
    expect(button('Complete claim').disabled).toBe(false);
  });

  it('completes the claim and shows the share once', async () => {
    const sent = stubControlPlane({
      [CAPS_PATH]: caps(),
      [BEGIN_PATH]: ok({ nonce: 'nonce-2' }),
      [COMPLETE_PATH]: ok({ share: 'share-test', index: 2 }),
    });
    render(withControlPlane(<CeremonyClaimShareCard />));

    await requestChallenge();
    fireEvent.change(screen.getByLabelText('Signature (base64)'), { target: { value: ' c2lnLXRlc3Q= ' } });
    await click('Complete claim');

    expect(await screen.findByText('Store this share offline now: the platform keeps no copy.')).toBeDefined();
    expect(writes(sent)[1].body).toEqual({ username: 'officer1', nonce: 'nonce-2', signature: 'c2lnLXRlc3Q=' });
    expect(value('Share')).toBe('share-test');
    expect(screen.getByText('Share index 2')).toBeDefined();
    const sig = screen.queryByLabelText('Signature (base64)') as HTMLTextAreaElement | null;
    expect(sig === null || sig.value === '').toBe(true);

    fireEvent.click(button('Start over'));
    await waitFor(() => expect(screen.queryByLabelText('Share')).toBeNull());
  });

  it('shows a refusal verbatim', async () => {
    stubControlPlane({ [CAPS_PATH]: caps(), [BEGIN_PATH]: refused(409, 'ceremony: not initialized') });
    render(withControlPlane(<CeremonyClaimShareCard />));

    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'officer1' } });
    await click('Request challenge');

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toBe('Claim share refused: ceremony: not initialized');
    expect(screen.queryByLabelText('Nonce')).toBeNull();
  });
});
