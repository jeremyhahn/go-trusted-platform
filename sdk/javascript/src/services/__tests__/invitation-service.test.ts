/**
 * InvitationService wire paths for the detail, token lookup and accept
 * operations the web invite page drives (#1753).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { InvitationService } from '../invitation-service.js';
import type { ApiClient } from '../../client/api-client.js';

function makeClient(): ApiClient {
  return {
    get: vi.fn().mockResolvedValue({ data: { invitation: { id: 'inv-1' } } }),
    post: vi.fn().mockResolvedValue({ data: { success: true } }),
    put: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
    head: vi.fn(),
    options: vi.fn(),
    fetch: vi.fn(),
  } as unknown as ApiClient;
}

describe('InvitationService', () => {
  let client: ApiClient;
  let service: InvitationService;

  beforeEach(() => {
    client = makeClient();
    service = new InvitationService(client);
  });

  it('get reads GET /v1/invitations/{id}', async () => {
    await service.get('inv-1');
    expect(client.get).toHaveBeenCalledWith('/v1/invitations/inv-1');
  });

  it('get escapes the id as one path segment', async () => {
    await service.get('a/b');
    expect(client.get).toHaveBeenCalledWith('/v1/invitations/a%2Fb');
  });

  it('getByToken reads GET /v1/invitations/token/{token}', async () => {
    await service.getByToken('tok+1/2');
    expect(client.get).toHaveBeenCalledWith('/v1/invitations/token/tok%2B1%2F2');
  });

  it('accept posts the request to /v1/invitations/accept', async () => {
    await service.accept({ token: 'tok-1', name: 'Ada' });
    expect(client.post).toHaveBeenCalledWith('/v1/invitations/accept', {
      token: 'tok-1',
      name: 'Ada',
    });
  });
});
