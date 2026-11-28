/**
 * InvitationService.create wire body: the SDK expiry is in hours, the
 * server's CreateInvitationRequest reads expires_in_seconds
 * (protojson expiresInSeconds) and drops unknown fields, so create must
 * send the converted seconds and never expiresIn.
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

describe('InvitationService create expiry', () => {
  let client: ApiClient;
  let service: InvitationService;

  beforeEach(() => {
    client = createMockApiClient();
    service = new InvitationService(client);
    vi.mocked(client.post).mockResolvedValue({ success: true, data: {} });
  });

  it('sends a 72-hour expiry as expiresInSeconds 259200 and no expiresIn', async () => {
    await service.create({ email: 'a@example.com', role: 'member', expiresIn: 72 });
    expect(client.post).toHaveBeenCalledTimes(1);
    const [url, body] = vi.mocked(client.post).mock.calls[0] as [string, Record<string, unknown>];
    expect(url).toBe('/v1/invitations');
    expect(body.expiresInSeconds).toBe(259200);
    expect('expiresIn' in body).toBe(false);
    expect(Object.keys(body)).toEqual(['email', 'role', 'expiresInSeconds']);
  });

  it('sends no expiry field when expiresIn is omitted', async () => {
    await service.create({ email: 'a@example.com', role: 'member' });
    expect(client.post).toHaveBeenCalledTimes(1);
    const [, body] = vi.mocked(client.post).mock.calls[0] as [string, Record<string, unknown>];
    expect(Object.keys(body)).toEqual(['email', 'role']);
  });

  it.each([0, -1, Number.NaN])('rejects expiresIn %s without posting', async (expiresIn) => {
    await expect(
      service.create({ email: 'a@example.com', role: 'member', expiresIn }),
    ).rejects.toThrow();
    expect(client.post).not.toHaveBeenCalled();
  });
});
