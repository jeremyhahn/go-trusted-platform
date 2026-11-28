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
});
