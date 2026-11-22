/**
 * TPMService.getRandom sends only a byte count the TPM route serves as asked (#2069).
 *
 * The daemon reads numBytes 0 as 32 bytes and refuses more than 1024, and a
 * fraction, a negative or NaN fails the uint32 decode with an opaque 400, so
 * the SDK refuses any count outside 1-1024 before it posts.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { TPMService } from '../tpm-service.js';
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

describe('TPMService.getRandom byte count', () => {
  let service: TPMService;
  let client: ApiClient;
  const ok = { success: true, data: { randomBytes: 'AAEC' } };

  beforeEach(() => {
    client = createMockApiClient();
    vi.mocked(client.post).mockResolvedValue(ok);
    service = new TPMService(client);
  });

  it.each([1, 1024])('posts numBytes %d once and returns the response unchanged', async (n) => {
    const response = await service.getRandom({ numBytes: n });

    expect(client.post).toHaveBeenCalledTimes(1);
    const call = vi.mocked(client.post).mock.calls[0];
    expect(call?.[0]).toMatch(/\/v1\/tpm\/random$/);
    expect(call?.[1]).toEqual({ numBytes: n });
    expect(response).toBe(ok);
  });

  it.each([0, -1, 1025, 16.5, Number.NaN, Number.POSITIVE_INFINITY])(
    'refuses numBytes %s with a RangeError and sends nothing',
    async (n) => {
      const result = service.getRandom({ numBytes: n });

      await expect(result).rejects.toBeInstanceOf(RangeError);
      await expect(result).rejects.toThrow(/numBytes/);
      await expect(result).rejects.toThrow(/1024/);
      expect(client.post).not.toHaveBeenCalled();
    },
  );

  it('returns a server failure unchanged', async () => {
    const failure = {
      success: false,
      error: { code: 'UNAVAILABLE', message: 'TPM service not available', status: 503 },
    };
    vi.mocked(client.post).mockResolvedValue(failure);

    const response = await service.getRandom({ numBytes: 32 });

    expect(response).toBe(failure);
  });
});
