/**
 * EABService.list query names.
 *
 * The served route GET /api/v1/eab/credentials reads profile_id, tenant_id,
 * status, page and page_size (pkg/webservice/v1/rest/eab/handlers.go), and
 * accepts the status as the full proto name EAB_CREDENTIAL_STATUS_*.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { EABService } from '../eab-service.js';
import type { ApiClient } from '../../client/api-client.js';
import type { EABCredentialStatus } from '../../types/eab.js';

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

describe('EABService.list query names', () => {
  let mockClient: ApiClient;
  let service: EABService;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new EABService(mockClient);
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: {} });
  });

  function calledUrl(): { path: string; params: URLSearchParams } {
    const [path = '', query = ''] = String(vi.mocked(mockClient.get).mock.calls[0]?.[0]).split('?');
    return { path, params: new URLSearchParams(query) };
  }

  it('sends profile_id, tenant_id, page and page_size', async () => {
    await service.list({ profileId: 7, tenantId: 't1', page: 2, pageSize: 25 });

    const { path, params } = calledUrl();
    expect(path).toBe('/v1/eab/credentials');
    expect(params.get('profile_id')).toBe('7');
    expect(params.get('tenant_id')).toBe('t1');
    expect(params.get('page')).toBe('2');
    expect(params.get('page_size')).toBe('25');
    expect(params.has('profileId')).toBe(false);
    expect(params.has('tenantId')).toBe(false);
    expect(params.has('limit')).toBe(false);
  });

  it.each([
    ['ACTIVE', 'EAB_CREDENTIAL_STATUS_ACTIVE'],
    ['REVOKED', 'EAB_CREDENTIAL_STATUS_REVOKED'],
    ['EXPIRED', 'EAB_CREDENTIAL_STATUS_EXPIRED'],
    ['USED', 'EAB_CREDENTIAL_STATUS_USED'],
  ] as Array<[EABCredentialStatus, string]>)('sends status %s as %s', async (status, protoName) => {
    await service.list({ status });

    const { params } = calledUrl();
    expect(params.get('status')).toBe(protoName);
  });

  it('sends no query when the caller passes no request', async () => {
    await service.list();

    expect(mockClient.get).toHaveBeenCalledWith('/v1/eab/credentials');
  });
});
