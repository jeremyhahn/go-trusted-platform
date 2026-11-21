/**
 * TPMService.getEventLog (#2069): the server writes the proto uint64
 * event_count with protojson, so it arrives as a decimal string; the SDK
 * returns it as the number its type promises.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { TPMService } from '../tpm-service.js';
import { ApiClient } from '../../client/api-client.js';

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

describe('TPMService.getEventLog', () => {
  let service: TPMService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new TPMService(mockClient);
  });

  function serve(data: unknown): void {
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data } as never);
  }

  it('decodes the protojson decimal string event count to a number', async () => {
    serve({ eventLog: 'AAE=', format: 'tcg2', eventCount: '42', entries: [] });

    const res = await service.getEventLog();

    expect(mockClient.get).toHaveBeenCalledTimes(1);
    expect(String(vi.mocked(mockClient.get).mock.calls[0]?.[0])).toMatch(/\/v1\/tpm\/eventlog$/);
    expect(res.success).toBe(true);
    expect(res.data?.eventCount).toBe(42);
    expect(typeof res.data?.eventCount).toBe('number');
    expect(res.data?.eventLog).toBe('AAE=');
    expect(res.data?.format).toBe('tcg2');
    expect(res.data?.entries).toEqual([]);
  });

  it('decodes "0" to the number 0', async () => {
    serve({ eventLog: '', format: 'tcg2', eventCount: '0', entries: [] });

    const res = await service.getEventLog();

    expect(res.data?.eventCount).toBe(0);
    expect(typeof res.data?.eventCount).toBe('number');
  });

  it('keeps a number event count as it is', async () => {
    serve({ eventLog: 'AAE=', format: 'tcg2', eventCount: 7, entries: [] });

    const res = await service.getEventLog();

    expect(res.data?.eventCount).toBe(7);
  });

  it('leaves a missing event count undefined', async () => {
    serve({ eventLog: 'AAE=', format: 'tcg2', entries: [] });

    const res = await service.getEventLog();

    expect(res.data?.eventCount).toBeUndefined();
    expect(res.data?.entries).toEqual([]);
  });

  it('passes an error response through unchanged', async () => {
    const failure = {
      success: false,
      error: { code: 'UNAVAILABLE', message: 'TPM service not available', status: 503 },
    };
    vi.mocked(mockClient.get).mockResolvedValue(failure as never);

    const res = await service.getEventLog();

    expect(res).toEqual(failure);
  });
});
