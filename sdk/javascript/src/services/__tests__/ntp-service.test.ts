/**
 * Unit tests for the NTP service routes (docs/ntp/api.md §4 REST bodies).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { NTPService } from '../ntp-service.js';
import { NTPService as IndexedNTPService } from '../index.js';
import { NTPService as RootNTPService } from '../../index.js';
import type { GetNTPStatusResponse, ListNTPSourcesResponse, StepNTPClockResponse } from '../../index.js';
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

describe('NTPService', () => {
  let service: NTPService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new NTPService(mockClient);
  });

  it('is exported from the services index', () => {
    expect(IndexedNTPService).toBe(NTPService);
  });

  it('is exported from the package root with its response types', () => {
    expect(RootNTPService).toBe(NTPService);
    const rooted = new RootNTPService(mockClient);
    expect(rooted).toBeInstanceOf(NTPService);
    const status: GetNTPStatusResponse | undefined = undefined;
    const sources: ListNTPSourcesResponse | undefined = undefined;
    const stepped: StepNTPClockResponse | undefined = undefined;
    expect([status, sources, stepped]).toEqual([undefined, undefined, undefined]);
  });

  it('getStatus gets /v1/ntp/status', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: { status: { synced: true } } });

    const result = await service.getStatus();

    expect(result.success).toBe(true);
    expect(mockClient.get).toHaveBeenCalledTimes(1);
    expect(mockClient.get).toHaveBeenCalledWith('/v1/ntp/status');
  });

  it('listSources gets /v1/ntp/sources', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: { sources: [] } });

    await service.listSources();

    expect(mockClient.get).toHaveBeenCalledWith('/v1/ntp/sources');
  });

  it('step posts /v1/ntp/step with no body', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: { status: { synced: true } } });

    await service.step();

    expect(mockClient.post).toHaveBeenCalledTimes(1);
    expect(vi.mocked(mockClient.post).mock.calls[0]?.[0]).toBe('/v1/ntp/step');
    expect(vi.mocked(mockClient.post).mock.calls[0]?.[1]).toBeUndefined();
  });

  it('propagates a transport error unchanged', async () => {
    const failure = new Error('409 Conflict: no reachable source');
    vi.mocked(mockClient.post).mockRejectedValue(failure);

    await expect(service.step()).rejects.toBe(failure);
  });
});
