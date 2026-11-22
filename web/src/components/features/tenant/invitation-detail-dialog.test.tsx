import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';

import { InvitationDetailDialog } from './invitation-detail-dialog';

const invitation = {
  id: '42',
  tenantId: '7',
  email: 'invitee@example.com',
  role: 'member',
  status: 'pending',
  token: 'tok-42',
  inviteUrl: 'https://control-plane.test/auth/webauthn?invitation=tok-42',
  expiresAt: '2026-12-01T00:00:00Z',
  createdAt: '2026-11-20T00:00:00Z',
};

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('InvitationDetailDialog', () => {
  it('InvitationDetailDialog shows the invitation GetInvitation returns', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/invitations/42': ok({ invitation }),
    });

    render(withControlPlane(<InvitationDetailDialog id="42" open onOpenChange={() => {}} />));

    expect(await screen.findByText('invitee@example.com')).toBeTruthy();
    expect(screen.getByText('member')).toBeTruthy();
    expect(screen.getByText('pending')).toBeTruthy();
    expect(screen.getByText(invitation.inviteUrl)).toBeTruthy();
    expect(sent.some((r) => r.method === 'GET' && r.path === '/api/v1/invitations/42')).toBe(true);
  });

  it("InvitationDetailDialog shows the server's refusal", async () => {
    stubControlPlane({
      'GET /api/v1/invitations/42': refused(403, 'not allowed to read this invitation'),
    });

    render(withControlPlane(<InvitationDetailDialog id="42" open onOpenChange={() => {}} />));

    expect(await screen.findByText(/not allowed to read this invitation/)).toBeTruthy();
  });
});
