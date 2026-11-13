import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';

import InvitationsPage from './page';

// session is the token the page reads; each case sets the role it needs.
const session = { isTenantOwner: true };

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn() }) }));
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
