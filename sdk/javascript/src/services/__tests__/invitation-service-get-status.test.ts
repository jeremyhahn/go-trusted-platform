/**
 * GetInvitation and GetInvitationByToken (#2056): the served routes write the
 * proto InvitationStatus enum by its protojson name ("INVITATION_STATUS_PENDING");
 * the SDK returns it as the lower-case InvitationStatus its type declares.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { InvitationService } from '../invitation-service.js';
import type { ApiClient } from '../../client/api-client.js';

function createMockApiClient(): ApiClient {
  return {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
    head: vi.fn(),
    options: vi.fn(),
    fetch: vi.fn(),
    baseUrl: 'https://api.example.com',
  } as unknown as ApiClient;
}

function servedInvitation(status: string) {
  return {
    id: '7',
    token: 'tok-1',
    tenantId: 't1',
    email: 'a@example.com',
    role: 'member',
    status,
    expiresAt: '2026-12-01T00:00:00Z',
    createdAt: '2026-11-20T00:00:00Z',
    invitedById: '42',
  };
}

function served(status: string) {
  return { success: true, data: { invitation: servedInvitation(status) } };
}

describe('InvitationService get and getByToken status', () => {
  let service: InvitationService;
  let client: ApiClient;

  beforeEach(() => {
    client = createMockApiClient();
    service = new InvitationService(client);
  });

  it('get reads /v1/invitations/{id} and returns the lower-case status', async () => {
    vi.mocked(client.get).mockResolvedValue(served('INVITATION_STATUS_PENDING'));
    const result = await service.get('7');
    expect(client.get).toHaveBeenCalledTimes(1);
    expect(client.get).toHaveBeenCalledWith('/v1/invitations/7');
    expect(result.success).toBe(true);
    expect(result.data?.invitation.status).toBe('pending');
    expect(result.data?.invitation).toEqual({ ...servedInvitation('pending') });
  });

  it('getByToken reads /v1/invitations/token/{token} and returns the lower-case status', async () => {
    vi.mocked(client.get).mockResolvedValue(served('INVITATION_STATUS_ACCEPTED'));
    const result = await service.getByToken('tok-1');
    expect(client.get).toHaveBeenCalledTimes(1);
    expect(client.get).toHaveBeenCalledWith('/v1/invitations/token/tok-1');
    expect(result.data?.invitation).toEqual({ ...servedInvitation('accepted') });
  });

  it.each([
    ['INVITATION_STATUS_EXPIRED', 'expired'],
    ['INVITATION_STATUS_REVOKED', 'revoked'],
    ['pending', 'pending'],
    ['INVITATION_STATUS_UNSPECIFIED', 'INVITATION_STATUS_UNSPECIFIED'],
  ])('get maps %s to %s', async (servedStatus, want) => {
    vi.mocked(client.get).mockResolvedValue(served(servedStatus));
    const result = await service.get('7');
    expect(result.data?.invitation.status).toBe(want);
  });

  it('returns an error reply unchanged from both methods', async () => {
    const reply = {
      success: false,
      error: { code: 'NOT_FOUND', message: 'invitation not found', status: 404 },
    };
    vi.mocked(client.get).mockResolvedValue(reply);
    expect(await service.get('7')).toEqual(reply);
    expect(await service.getByToken('tok-1')).toEqual(reply);
  });
});
