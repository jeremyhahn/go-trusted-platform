/**
 * Unit tests for EAB credential ids above 2^53.
 *
 * The server mints EAB credential ids from UnixNano, a uint64 that protojson
 * writes as a decimal string. A JavaScript number above 2^53 loses digits, so
 * every id method must put the exact decimal string on the wire.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { EABService } from '../eab-service.js';
import type { ApiClient } from '../../client/api-client.js';

const ID = '1795456021769983013';

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

describe('EABService decimal credential ids', () => {
  let mockClient: ApiClient;
  let service: EABService;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new EABService(mockClient);
    const answer = { success: true, data: {} };
    vi.mocked(mockClient.get).mockResolvedValue(answer);
    vi.mocked(mockClient.post).mockResolvedValue(answer);
    vi.mocked(mockClient.delete).mockResolvedValue(answer);
  });

  function url(method: 'get' | 'post' | 'delete'): string {
    return String(vi.mocked(mockClient[method]).mock.calls[0]?.[0]);
  }

  it('get sends the exact decimal id', async () => {
    await service.get(ID);
    expect(url('get')).toBe(`/v1/eab/credentials/${ID}`);
  });

  it('revoke sends the exact decimal id', async () => {
    await service.revoke(ID);
    expect(url('post')).toContain(`/v1/eab/credentials/${ID}/`);
  });

  it('delete sends the exact decimal id', async () => {
    await service.delete(ID);
    expect(url('delete')).toBe(`/v1/eab/credentials/${ID}`);
  });

  it('getQRCode sends the exact decimal id', async () => {
    await service.getQRCode(ID);
    expect(url('get')).toContain(`/v1/eab/credentials/${ID}/qrcode`);
  });

  it('getEnrollmentURL sends the exact decimal id', async () => {
    await service.getEnrollmentURL(ID);
    expect(url('get')).toBe(`/v1/eab/credentials/${ID}/url`);
  });

  it('markUsed sends the exact decimal id', async () => {
    await service.markUsed(ID);
    expect(url('post')).toBe(`/v1/eab/credentials/${ID}/used`);
  });
});
