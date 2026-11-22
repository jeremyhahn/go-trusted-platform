import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import {
  CEREMONY_AUTHENTICATOR_TYPES,
  CeremonyClaimCertCard,
  authenticatorTypeLabel,
} from './ceremony-claim-cert-card';

// #2042: an officer claims their certificate through
// CeremonyService.ClaimCertBegin/ClaimCertComplete on useCeremony().

vi.mock('next/navigation', () => ({
  useParams: () => ({}),
  usePathname: () => '/platform/ceremony',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

const BEGIN_PATH = 'POST /api/v1/ceremony/claim-cert/begin';
const COMPLETE_PATH = 'POST /api/v1/ceremony/claim-cert/complete';

function beginOk() {
  return ok({ nonce: 'nonce-1', challengeId: 'ch-1', expiresAt: '2026-01-01T00:00:00Z' });
}

function value(label: string): string {
  return (screen.getByLabelText(label) as HTMLInputElement | HTMLTextAreaElement).value;
}

async function requestChallenge() {
  fireEvent.change(screen.getByLabelText('Username'), { target: { value: ' officer1 ' } });
  fireEvent.click(screen.getByRole('button', { name: 'Request challenge' }));
  await screen.findByLabelText('Nonce');
}

describe('ceremony claim-cert helpers', () => {
  it('labels the authenticator types', () => {
    expect(CEREMONY_AUTHENTICATOR_TYPES).toEqual([
      'CEREMONY_AUTHENTICATOR_TYPE_PIV',
      'CEREMONY_AUTHENTICATOR_TYPE_FIDO2',
      'CEREMONY_AUTHENTICATOR_TYPE_SOFTWARE',
    ]);
    expect(authenticatorTypeLabel('CEREMONY_AUTHENTICATOR_TYPE_FIDO2')).toBe('FIDO2');
    expect(authenticatorTypeLabel('CEREMONY_AUTHENTICATOR_TYPE_UNSPECIFIED')).toBe('Unspecified');
  });
});

describe('CeremonyClaimCertCard', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('keeps Request challenge disabled until a username is set', () => {
    stubControlPlane({});
    render(withControlPlane(<CeremonyClaimCertCard />));

    const button = screen.getByRole('button', { name: 'Request challenge' }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    fireEvent.change(screen.getByLabelText('Username'), { target: { value: '  ' } });
    expect(button.disabled).toBe(true);
    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'officer1' } });
    expect(button.disabled).toBe(false);
  });

  it('requests a challenge with the chosen authenticator', async () => {
    const sent = stubControlPlane({ [BEGIN_PATH]: beginOk() });
    render(withControlPlane(<CeremonyClaimCertCard />));

    fireEvent.change(screen.getByLabelText('Username'), { target: { value: ' officer1 ' } });
    fireEvent.change(screen.getByLabelText('Authenticator'), {
      target: { value: 'CEREMONY_AUTHENTICATOR_TYPE_FIDO2' },
    });
    fireEvent.change(screen.getByLabelText('Credential ID'), { target: { value: 'cred-1' } });
    fireEvent.click(screen.getByRole('button', { name: 'Request challenge' }));

    await screen.findByLabelText('Nonce');
    expect(sent).toEqual([
      {
        method: 'POST',
        path: '/api/v1/ceremony/claim-cert/begin',
        body: {
          username: 'officer1',
          authenticatorType: 'CEREMONY_AUTHENTICATOR_TYPE_FIDO2',
          credentialId: 'cred-1',
        },
      },
    ]);
    expect(value('Nonce')).toBe('nonce-1');
    expect(value('Challenge ID')).toBe('ch-1');
  });

  it('completes the claim with the begin nonce', async () => {
    const sent = stubControlPlane({
      [BEGIN_PATH]: beginOk(),
      [COMPLETE_PATH]: ok({ certificatePem: '<cert>', chainPem: '<chain>' }),
    });
    render(withControlPlane(<CeremonyClaimCertCard />));

    await requestChallenge();
    fireEvent.change(screen.getByLabelText('Signature'), { target: { value: ' sig-test ' } });
    fireEvent.click(screen.getByRole('button', { name: 'Complete claim' }));

    await screen.findByLabelText('Certificate');
    expect(sent[1]).toEqual({
      method: 'POST',
      path: '/api/v1/ceremony/claim-cert/complete',
      body: { username: 'officer1', nonce: 'nonce-1', signature: 'sig-test' },
    });
    expect(value('Certificate')).toBe('<cert>');
    expect(value('Chain')).toBe('<chain>');
    expect(screen.queryByLabelText('Nonce')).toBeNull();
  });

  it('shows a refusal verbatim and keeps the challenge', async () => {
    stubControlPlane({
      [BEGIN_PATH]: beginOk(),
      [COMPLETE_PATH]: refused(403, 'ceremony: signature does not verify'),
    });
    render(withControlPlane(<CeremonyClaimCertCard />));

    await requestChallenge();
    fireEvent.change(screen.getByLabelText('Signature'), { target: { value: 'sig-test' } });
    fireEvent.click(screen.getByRole('button', { name: 'Complete claim' }));

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toBe('Claim refused: ceremony: signature does not verify');
    await waitFor(() => expect(value('Nonce')).toBe('nonce-1'));
    expect(screen.queryByLabelText('Certificate')).toBeNull();
  });
});
