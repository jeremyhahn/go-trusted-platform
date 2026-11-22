/**
 * InvitationService.accept wire shape (#2056).
 *
 * The server answers POST /api/v1/invitations/accept with the proto
 * AcceptInvitationResponse { status, invitation, timestamp }; accept() hands
 * that body through unchanged.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { InvitationService } from '../invitation-service.js';
import type { ApiClient } from '../../client/api-client.js';
import type { Invitation } from '../../types/invitation.js';

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

const acceptedInvitation: Invitation = {
  id: '7',
  token: 'tok-1',
  tenantId: 'tenant-1',
  email: 'user@example.com',
  role: 'member',
  status: 'accepted',
  expiresAt: '2026-02-01T00:00:00Z',
  createdAt: '2025-12-01T00:00:00Z',
  acceptedAt: '2026-01-01T00:00:00Z',
  invitedById: 'admin-1',
};

describe('InvitationService.accept wire shape', () => {
  let service: InvitationService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new InvitationService(mockClient);
  });

  it('reads the served status and accepted invitation', async () => {
    const served = {
      status: { success: true, message: 'accepted' },
      invitation: acceptedInvitation,
      timestamp: '2026-01-01T00:00:00Z',
    };
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: served });

    const result = await service.accept({ token: 'tok-1', name: 'n' });

    expect(mockClient.post).toHaveBeenCalledTimes(1);
    expect(mockClient.post).toHaveBeenCalledWith('/v1/invitations/accept', {
      token: 'tok-1',
      name: 'n',
    });
    expect(result.data).toEqual(served);
    expect(result.data?.status.success).toBe(true);
    expect(result.data?.status.message).toBe('accepted');
    expect(result.data?.invitation.id).toBe('7');
  });
});
