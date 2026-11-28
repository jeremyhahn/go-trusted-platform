import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { ok, stubControlPlane } from '@/test/control-plane-fetch';
import InvitationsPage from './page';

// The invitations page reads the server's envelope (#2035, Codex round 4 on
// #2341): GET and POST /api/v1/invitations answer { code, success, payload }
// with the invitations (or the created invitation) under payload.

// One router for every render: the page's effect depends on it.
const router = vi.hoisted(() => ({ push: vi.fn() }));
vi.mock('next/navigation', () => ({
  useRouter: () => router,
}));

function b64url(value: unknown): string {
  return btoa(JSON.stringify(value)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function jwtCookie(claims: Record<string, unknown>): string {
  return `${b64url({ alg: 'none' })}.${b64url(claims)}.sig`;
}

const INVITATIONS = '/api/v1/invitations';

function routes() {
  return {
    [`GET ${INVITATIONS}`]: ok({
      invitations: [
        {
          id: 'inv-1',
          email: 'a@example.com',
          role: 'member',
          token: 'tok-1',
          expires_at: '2026-12-01T00:00:00Z',
          created_at: '2026-11-23T00:00:00Z',
        },
      ],
    }),
    [`POST ${INVITATIONS}`]: ok({
      invitation: {
        id: 'inv-2',
        email: 'b@example.com',
        role: 'admin',
        token: 'tok-2',
        expires_at: '2026-12-01T00:00:00Z',
        created_at: '2026-11-23T00:00:00Z',
      },
    }),
    [`DELETE ${INVITATIONS}/inv-1`]: ok({}),
  };
}

beforeEach(() => {
  document.cookie =
    'jwt=' +
    jwtCookie({ sub: 'u-1', email: 'owner@example.com', tenant_id: 't-1', is_tenant_owner: true }) +
    '; path=/';
});

afterEach(() => {
  document.cookie = 'jwt=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT';
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('invitations page', () => {
  it('lists the invitations of the payload', async () => {
    stubControlPlane(routes());
    render(<InvitationsPage />);

    expect(await screen.findByText('a@example.com')).toBeTruthy();
    expect(screen.getByText('member')).toBeTruthy();
    expect(screen.queryByText('No pending invitations')).toBeNull();
  });

  it('adds the created invitation of the payload to the list', async () => {
    const sent = stubControlPlane(routes());
    render(<InvitationsPage />);
    await waitFor(() => expect(screen.queryByText('Loading invitations...')).toBeNull());

    fireEvent.change(screen.getByLabelText('Email Address'), { target: { value: 'b@example.com' } });
    fireEvent.change(screen.getByLabelText('Role'), { target: { value: 'admin' } });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Create Invitation' }));
    });

    await waitFor(() =>
      expect(sent.find((r) => r.method === 'POST' && r.path === INVITATIONS)?.body).toEqual({
        email: 'b@example.com',
        role: 'admin',
      }),
    );
    expect(await screen.findByText('b@example.com')).toBeTruthy();
  });

  it('revokes a listed invitation after the confirm', async () => {
    const sent = stubControlPlane(routes());
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    render(<InvitationsPage />);
    await screen.findByText('a@example.com');

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Revoke' }));
    });

    await waitFor(() =>
      expect(sent.some((r) => r.method === 'DELETE' && r.path === `${INVITATIONS}/inv-1`)).toBe(true),
    );
    await waitFor(() => expect(screen.queryByText('a@example.com')).toBeNull());
  });

  it('copies the invitation link', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    stubControlPlane(routes());
    render(<InvitationsPage />);
    await screen.findByText('a@example.com');

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Copy Link' }));
    });

    expect(writeText).toHaveBeenCalledWith(`${window.location.origin}/auth/webauthn?invitation=tok-1`);
  });
});
