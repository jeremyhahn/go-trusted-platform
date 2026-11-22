/**
 * Unit tests for the EAB enrolment operations.
 *
 * `pkg/webservice/v1/rest/eab/router.go` serves GET /credentials/{id}/url,
 * POST /credentials/{id}/used and POST /credentials/cleanup. These tests pin
 * the routes and bodies the SDK sends for each.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { EABService } from '../eab-service.js';
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

describe('EABService enrolment operations', () => {
  let mockClient: ApiClient;
  let service: EABService;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new EABService(mockClient);
  });

  it('getEnrollmentURL calls the served /url route', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({
      success: true,
      data: { url: 'https://acme.example.com/enrol', expiresAt: '2026-11-22T00:00:00Z' },
    });

    await service.getEnrollmentURL(7);

    expect(mockClient.get).toHaveBeenCalledWith('/v1/eab/credentials/7/url');
  });

  it('getEnrollmentURL sends the optional path as a query parameter', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({
      success: true,
      data: { url: 'https://acme.example.com/acme/new', expiresAt: '2026-11-22T00:00:00Z' },
    });

    await service.getEnrollmentURL(7, '/acme/new');

    expect(mockClient.get).toHaveBeenCalledWith('/v1/eab/credentials/7/url?path=%2Facme%2Fnew');
  });

  it('markUsed posts to /credentials/{id}/used', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({
      success: true,
      data: { status: { success: true, message: 'ok' } },
    });

    const result = await service.markUsed(7);

    expect(vi.mocked(mockClient.post).mock.calls[0]?.[0]).toBe('/v1/eab/credentials/7/used');
    expect(result.success).toBe(true);
    expect(result.data?.status.success).toBe(true);
  });

  it('cleanupExpired posts an empty body to /credentials/cleanup', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({
      success: true,
      data: { deletedCount: 3, status: { success: true, message: 'ok' } },
    });

    const result = await service.cleanupExpired();

    expect(mockClient.post).toHaveBeenCalledWith('/v1/eab/credentials/cleanup', {});
    expect(result.success).toBe(true);
    expect(result.data?.deletedCount).toBe(3);
  });

  it('cleanupExpired sends the tenant when given', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({
      success: true,
      data: { deletedCount: 0, status: { success: true, message: 'ok' } },
    });

    await service.cleanupExpired('t1');

    expect(mockClient.post).toHaveBeenCalledWith('/v1/eab/credentials/cleanup', { tenantId: 't1' });
  });

  it('markUsed passes an error answer through unchanged', async () => {
    const answer = {
      success: false as const,
      error: { code: 'NOT_FOUND', message: 'no credential', status: 404 },
    };
    vi.mocked(mockClient.post).mockResolvedValue(answer);

    const result = await service.markUsed(7);

    expect(result).toEqual(answer);
  });
});
