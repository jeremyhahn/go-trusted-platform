import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';

import InvitationsPage from './page';

// session is the token the page reads; each case sets the role it needs.
const session = { isTenantOwner: true };

// One router object, as Next's useRouter returns: the page's effect depends
// on it, so a fresh object per render would rerun the list read.
const router = { push: vi.fn() };
vi.mock('next/navigation', () => ({ useRouter: () => router }));
vi.mock('@/utils/jwt', () => ({ getUserFromToken: () => session }));
vi.mock('@/utils/cookie', () => ({ getCookie: () => 'test' }));
vi.mock('@/utils/getBaseUrl', () => ({ getBaseUrl: () => '' }));

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  session.isTenantOwner = true;
});

describe('InvitationsPage owner gate', () => {
  it('a tenant owner gets the form while the invitation list is still loading', async () => {
    const fetchMock = vi.fn(() => new Promise<Response>(() => {}));
    vi.stubGlobal('fetch', fetchMock);

    render(<InvitationsPage />);

    expect(await screen.findByText('Create New Invitation')).toBeTruthy();
    expect(screen.queryByText('Access Denied')).toBeNull();
    expect(screen.getByText('Loading invitations...')).toBeTruthy();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('a non-owner gets Access Denied and no list read', async () => {
    session.isTenantOwner = false;
    const fetchMock = vi.fn(() => new Promise<Response>(() => {}));
    vi.stubGlobal('fetch', fetchMock);

    render(<InvitationsPage />);

    expect(await screen.findByText('Access Denied')).toBeTruthy();
    // Let the ownership microtask settle before checking no read went out.
    await Promise.resolve();
    expect(screen.queryByText('Create New Invitation')).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

// #2023 Codex round 2: the REST handlers answer through protorest.WriteSuccess
// with the {code, success, payload} envelope and protojson camelCase names, so
// the page must unwrap payload for the list and the create answer.
describe('InvitationsPage list envelope', () => {
  function json(status: number, body: unknown): Response {
    return new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  it('lists the invitations of the server envelope and links each to its detail page', async () => {
    const fetchMock = vi.fn(async () =>
      json(200, {
        code: 200,
        error: '',
        success: true,
        payload: {
          invitations: [
            {
              id: '7',
              token: 'tok-7',
              tenantId: 't-1',
              email: 'a@example.com',
              role: 'member',
              status: 'INVITATION_STATUS_PENDING',
              expiresAt: '2026-12-01T00:00:00Z',
              createdAt: '2026-11-01T00:00:00Z',
            },
          ],
        },
      })
    );
    vi.stubGlobal('fetch', fetchMock);

    render(<InvitationsPage />);

    expect(await screen.findByText('a@example.com')).toBeTruthy();
    // The page links to /admin/invitations/detail/?id=7; the app builds with
    // trailingSlash: true, but vitest does not load next.config, so next/link
    // drops the slash here. Either form reaches the detail page.
    expect(screen.getByTestId('view-invitation-7').getAttribute('href')).toMatch(
      /^\/admin\/invitations\/detail\/?\?id=7$/
    );
    expect(screen.queryByText('No pending invitations')).toBeNull();
    expect(screen.queryByText(/Invalid Date/)).toBeNull();
  });

  it('adds the created invitation of the server envelope to the list', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) =>
      init?.method === 'POST'
        ? json(201, {
            code: 201,
            success: true,
            payload: {
              invitation: {
                id: '8',
                token: 'tok-8',
                email: 'b@example.com',
                role: 'member',
                expiresAt: '2026-12-01T00:00:00Z',
              },
            },
          })
        : json(200, { code: 200, success: true, payload: { invitations: [] } })
    );
    vi.stubGlobal('fetch', fetchMock);

    render(<InvitationsPage />);
    expect(await screen.findByText('No pending invitations')).toBeTruthy();

    fireEvent.change(screen.getByLabelText('Email Address'), {
      target: { value: 'b@example.com' },
    });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Create Invitation' }));
    });

    expect(await screen.findByText('b@example.com')).toBeTruthy();
    expect(screen.getByTestId('view-invitation-8')).toBeTruthy();
  });
});
