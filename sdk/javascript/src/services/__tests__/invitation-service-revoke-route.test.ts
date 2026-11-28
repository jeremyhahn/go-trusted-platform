/**
 * InvitationService.revoke reaches the served revoke route (#2056).
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
  } as unknown as ApiClient;
}

describe('InvitationService.revoke', () => {
  let mockClient: ApiClient;
  let service: InvitationService;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new InvitationService(mockClient);
    vi.mocked(mockClient.post).mockResolvedValue({
      success: true,
      data: { status: { success: true, message: 'invitation revoked' } },
    });
  });

  it('posts to the revoke route and does not delete the invitation', async () => {
    await service.revoke('42');

    expect(mockClient.post).toHaveBeenCalledTimes(1);
    expect(mockClient.post).toHaveBeenCalledWith('/v1/invitations/42/revoke', {});
    expect(mockClient.delete).not.toHaveBeenCalled();
  });

  it('encodes the invitation id in the revoke path', async () => {
    await service.revoke('a/b');

    expect(mockClient.post).toHaveBeenCalledWith('/v1/invitations/a%2Fb/revoke', {});
  });
});
