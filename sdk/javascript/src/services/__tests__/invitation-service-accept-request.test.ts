/**
 * InvitationService.accept (#2056) against the served route
 * (pkg/webservice/v1/rest/invitation/router.go, handlers.go): the server
 * decodes the proto AcceptInvitationRequest { token, user_id } and refuses a
 * zero user ID, so the SDK sends the token and the accepting user's ID and
 * nothing else (no name, no password).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { InvitationService } from '../invitation-service.js';
import type { ApiClient } from '../../client/api-client.js';
import type { ApiResponse } from '../../types/api.js';
import type { AcceptInvitationRequest, AcceptInvitationResponse } from '../../types/invitation.js';

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

describe('InvitationService accept request', () => {
  let service: InvitationService;
  let client: ApiClient;

  beforeEach(() => {
    client = createMockApiClient();
    service = new InvitationService(client);
  });

  it('posts the token and userId to /v1/invitations/accept', async () => {
    vi.mocked(client.post).mockResolvedValue({ success: true, data: {} });
    await service.accept({ token: 'tok-1', userId: '42' });
    expect(client.post).toHaveBeenCalledTimes(1);
    expect(client.post).toHaveBeenCalledWith('/v1/invitations/accept', { token: 'tok-1', userId: '42' });
  });

  it('sends only token and userId, never a name or password', async () => {
    vi.mocked(client.post).mockResolvedValue({ success: true, data: {} });
    const request = {
      token: 'tok-1',
      userId: '9007199254740993',
      name: 'Ann',
      password: 'pw',
    } as unknown as AcceptInvitationRequest;
    await service.accept(request);
    expect(client.post).toHaveBeenCalledTimes(1);
    const [url, body] = vi.mocked(client.post).mock.calls[0] as [string, unknown];
    expect(url).toBe('/v1/invitations/accept');
    expect(Object.keys(body as object)).toEqual(['token', 'userId']);
    expect((body as { userId: unknown }).userId).toBe('9007199254740993');
  });

  it('returns a refusal from the server unchanged', async () => {
    const refused: ApiResponse<AcceptInvitationResponse> = {
      success: false,
      error: { code: 'INVALID_ARGUMENT', message: 'user ID is required', status: 400 },
    };
    vi.mocked(client.post).mockResolvedValue(refused);
    const result = await service.accept({ token: 'tok-1', userId: '42' });
    expect(result).toEqual(refused);
  });
});
