/**
 * Unit tests for the Invitation service client.
 *
 * Each method is pinned to its verb, path, query and body under
 * /v1/invitations, with a mocked transport; a transport error must reach
 * the caller unchanged.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { InvitationService } from './invitation-service.js';
import type { ApiClient } from '../client/api-client.js';

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
    baseUrl: '',
  } as unknown as ApiClient;
}

describe('InvitationService', () => {
  let service: InvitationService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new InvitationService(mockClient);
  });

  describe('create', () => {
    it('POSTs the request to /v1/invitations', async () => {
      const data = { invitation: { id: 'inv-1' }, token: 'tok-1' };
      vi.mocked(mockClient.post).mockResolvedValue({ success: true, data });

      const result = await service.create({ email: 'invitee-a', role: 'admin', expiresIn: 48 });

      expect(result.data).toEqual(data);
      expect(mockClient.post).toHaveBeenCalledTimes(1);
      expect(mockClient.post).toHaveBeenCalledWith('/v1/invitations', {
        email: 'invitee-a',
        role: 'admin',
        expiresIn: 48,
      });
    });

    it('propagates a transport error unchanged', async () => {
      const failure = new Error('400 Bad Request: email is required');
      vi.mocked(mockClient.post).mockRejectedValue(failure);

      await expect(service.create({ email: '', role: 'admin' })).rejects.toBe(failure);
    });
  });

  describe('get', () => {
    it('GETs /v1/invitations/{id} with no query', async () => {
      vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: { invitation: { id: 'inv-1' } } });

      await service.get('inv-1');

      expect(mockClient.get).toHaveBeenCalledWith('/v1/invitations/inv-1');
    });

    it('encodes the id as one path segment', async () => {
      vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: {} });

      await service.get('a/b?c');

      expect(mockClient.get).toHaveBeenCalledWith('/v1/invitations/a%2Fb%3Fc');
    });

    it('propagates a transport error unchanged', async () => {
      const failure = new Error('404 Not Found');
      vi.mocked(mockClient.get).mockRejectedValue(failure);

      await expect(service.get('missing')).rejects.toBe(failure);
    });
  });

  describe('getByToken', () => {
    it('GETs /v1/invitations/token/{token} with no query', async () => {
      vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: { invitation: { id: 'inv-1' } } });

      await service.getByToken('tok-1');

      expect(mockClient.get).toHaveBeenCalledWith('/v1/invitations/token/tok-1');
    });

    it('encodes the token as one path segment', async () => {
      vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: {} });

      await service.getByToken('x/y');

      expect(mockClient.get).toHaveBeenCalledWith('/v1/invitations/token/x%2Fy');
    });

    it('propagates a transport error unchanged', async () => {
      const failure = new Error('410 Gone: invitation expired');
      vi.mocked(mockClient.get).mockRejectedValue(failure);

      await expect(service.getByToken('old')).rejects.toBe(failure);
    });
  });

  describe('list', () => {
    it('GETs /v1/invitations with no query when no request is given', async () => {
      vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: { invitations: [] } });

      await service.list();

      expect(mockClient.get).toHaveBeenCalledWith('/v1/invitations');
    });

    it('maps page, pageSize, status and email to the query', async () => {
      vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: { invitations: [] } });

      await service.list({ page: 2, pageSize: 25, status: 'pending', email: 'invitee-a' });

      const url = vi.mocked(mockClient.get).mock.calls[0]?.[0] as string;
      const [path, query] = url.split('?');
      expect(path).toBe('/v1/invitations');
      const params = new URLSearchParams(query);
      expect(Object.fromEntries(params)).toEqual({
        page: '2',
        limit: '25',
        status: 'pending',
        email: 'invitee-a',
      });
    });

    it('leaves unset filters off the query', async () => {
      vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: { invitations: [] } });

      await service.list({ status: 'revoked' });

      expect(mockClient.get).toHaveBeenCalledWith('/v1/invitations?status=revoked');
    });

    it('propagates a transport error unchanged', async () => {
      const failure = new Error('503 Service Unavailable');
      vi.mocked(mockClient.get).mockRejectedValue(failure);

      await expect(service.list()).rejects.toBe(failure);
    });
  });

  describe('revoke', () => {
    it('DELETEs /v1/invitations/{id} with no body', async () => {
      vi.mocked(mockClient.delete).mockResolvedValue({ success: true, data: { success: true } });

      await service.revoke('inv-1');

      expect(mockClient.delete).toHaveBeenCalledWith('/v1/invitations/inv-1');
    });

    it('propagates a transport error unchanged', async () => {
      const failure = new Error('409 Conflict: already accepted');
      vi.mocked(mockClient.delete).mockRejectedValue(failure);

      await expect(service.revoke('inv-1')).rejects.toBe(failure);
    });
  });

  describe('accept', () => {
    it('POSTs the request to /v1/invitations/accept', async () => {
      const data = { user: { id: 'u-1' }, tenant: { id: 't-1' } };
      vi.mocked(mockClient.post).mockResolvedValue({ success: true, data });

      const result = await service.accept({ token: 'tok-1', name: 'Ann', password: 'pw' });

      expect(result.data).toEqual(data);
      expect(mockClient.post).toHaveBeenCalledWith('/v1/invitations/accept', {
        token: 'tok-1',
        name: 'Ann',
        password: 'pw',
      });
    });

    it('propagates a transport error unchanged', async () => {
      const failure = new Error('400 Bad Request: invalid token');
      vi.mocked(mockClient.post).mockRejectedValue(failure);

      await expect(service.accept({ token: 'bad' })).rejects.toBe(failure);
    });
  });

  describe('resend', () => {
    it('POSTs an empty body to /v1/invitations/{id}/resend', async () => {
      vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: { invitation: { id: 'inv-1' } } });

      await service.resend('inv-1');

      expect(mockClient.post).toHaveBeenCalledWith('/v1/invitations/inv-1/resend', {});
    });

    it('propagates a transport error unchanged', async () => {
      const failure = new Error('404 Not Found');
      vi.mocked(mockClient.post).mockRejectedValue(failure);

      await expect(service.resend('missing')).rejects.toBe(failure);
    });
  });
});
