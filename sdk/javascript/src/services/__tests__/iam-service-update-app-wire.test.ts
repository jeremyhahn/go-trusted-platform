/**
 * IAMService.updateApp wire shape (#2054): PUT /v1/iam/tenants/{tenantId}/apps/{clientId}
 * carries the snake_case UpdateAppRequest body the server decodes.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { IAMService } from '../iam-service.js';
import type { ApiClient } from '../../client/api-client.js';
import type { ApiResponse } from '../../types/api.js';
import type { IAMAppResponse } from '../../types/iam.js';

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

describe('IAMService.updateApp wire', () => {
  let client: ApiClient;
  let service: IAMService;

  beforeEach(() => {
    client = createMockApiClient();
    service = new IAMService(client);
  });

  it('puts the snake_case UpdateAppRequest body to the app path', async () => {
    vi.mocked(client.put).mockResolvedValue({ success: true, data: {} });
    await service.updateApp({
      tenantId: 't1',
      clientId: 'app-1',
      name: 'Console',
      redirectUris: ['https://app.example.com/cb'],
      grantTypes: ['authorization_code', 'refresh_token'],
      responseTypes: ['code'],
      resourcePrefix: 'console/',
    });
    expect(client.put).toHaveBeenCalledTimes(1);
    const url = vi.mocked(client.put).mock.calls[0]?.[0];
    const body = vi.mocked(client.put).mock.calls[0]?.[1];
    expect(url).toBe('/v1/iam/tenants/t1/apps/app-1');
    expect(body).toEqual({
      tenant_id: 't1',
      name: 'Console',
      redirect_uris: ['https://app.example.com/cb'],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      resource_prefix: 'console/',
    });
  });

  it('a rename sends only tenant_id and name', async () => {
    vi.mocked(client.put).mockResolvedValue({ success: true, data: {} });
    await service.updateApp({ tenantId: 't1', clientId: 'app-1', name: 'Renamed' });
    const body = vi.mocked(client.put).mock.calls[0]?.[1] as Record<string, unknown>;
    const defined = Object.entries(body)
      .filter(([, v]) => v !== undefined)
      .map(([k]) => k)
      .sort();
    expect(defined).toEqual(['name', 'tenant_id']);
    expect(body).not.toHaveProperty('clientId');
    expect(body).not.toHaveProperty('redirectUris');
    expect(body).not.toHaveProperty('grantTypes');
  });

  it('returns a refusal from put unchanged', async () => {
    const refused: ApiResponse<IAMAppResponse> = {
      success: false,
      error: { code: 'FORBIDDEN', message: 'foreign tenant', status: 403 },
    } as ApiResponse<IAMAppResponse>;
    vi.mocked(client.put).mockResolvedValue(refused);
    const result = await service.updateApp({ tenantId: 't1', clientId: 'app-1', name: 'Renamed' });
    expect(result).toEqual(refused);
  });
});
