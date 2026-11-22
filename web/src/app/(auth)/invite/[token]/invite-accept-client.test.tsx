import * as React from 'react';
import { act, cleanup, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// #1681 Codex round 2: the invite page must not consume an invitation through
// AcceptInvitation (it marks the invitation accepted without joining the user
// to the tenant), and a normal login session, whose user_id and sub carry the
// login name (see pkg/webservice/v1/jwt/session_issuer.go), must not be sent
// to the passkey sign-up, which redirects signed-in sessions to the dashboard.

const mutateAsync = vi.fn();
let sessionToken: string | null = null;

vi.mock('next/navigation', () => ({
  usePathname: () => '/invite/tok-accept-1',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

vi.mock('@/hooks/use-session-token', () => ({
  useSessionToken: () => sessionToken,
}));

vi.mock('@/hooks', () => ({
  useInvitationByToken: () => ({
    data: { invitation: { id: '7' } },
    isLoading: false,
    error: null,
  }),
  toInvitationView: () => ({
    id: '7',
    email: 'invited@example.com',
    tenantName: 'Acme',
    role: 'member',
    status: 'pending',
  }),
  useInvitation: () => ({ accept: { mutateAsync, isLoading: false } }),
}));

import InviteAcceptClient from './invite-accept-client';

function jwt(claims: Record<string, unknown>): string {
  const b64 = (v: unknown) =>
    btoa(JSON.stringify(v)).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
  return `${b64({ alg: 'EdDSA', typ: 'JWT' })}.${b64(claims)}.sig`;
}

async function renderPage() {
  const params = Promise.resolve({ token: 'tok-accept-1' });
  await act(async () => {
    render(
      <React.Suspense fallback={null}>
        <InviteAcceptClient params={params} />
      </React.Suspense>,
    );
  });
  await screen.findByText(/You have been invited/);
}

describe('InviteAcceptClient', () => {
  beforeEach(() => {
    mutateAsync.mockReset();
    sessionToken = null;
  });
  afterEach(() => cleanup());

  it('signed out: offers the passkey sign-up that joins the tenant', async () => {
    await renderPage();
    const link = screen.getByRole('link', { name: 'Create account with passkey' });
    expect(link.getAttribute('href')).toBe('/auth/webauthn?invitation=tok-accept-1&tenant_name=Acme');
  });

  it('login-issued session (user_id = sub = login name): no passkey dead end', async () => {
    sessionToken = jwt({ sub: 'alice@example.com', user_id: 'alice@example.com', email: 'alice@example.com' });
    await renderPage();
    expect(screen.queryByRole('link', { name: 'Create account with passkey' })).toBeNull();
    expect(screen.queryByText(/then open this link again/)).toBeNull();
    expect(screen.getByRole('status').textContent).toContain('alice@example.com');
  });

  it('numeric user ID session: never consumes the invitation through AcceptInvitation', async () => {
    sessionToken = jwt({ sub: '42', user_id: '42' });
    await renderPage();
    expect(screen.queryByRole('button', { name: 'Accept Invitation' })).toBeNull();
    expect(screen.queryByText(/You have joined/)).toBeNull();
    expect(mutateAsync).not.toHaveBeenCalled();
    expect(screen.getByRole('status')).toBeTruthy();
  });
});
