/**
 * TPMService certify (#2068): Certify posts its request body unchanged to
 * /v1/tpm/certify and hands back the server's answer, refusals included.
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

describe('TPMService certify', () => {
  let service: TPMService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: {} });
    service = new TPMService(mockClient);
  });

  function posted(): [unknown, unknown] {
    const call = vi.mocked(mockClient.post).mock.calls[0];
    return [call?.[0], call?.[1]];
  }

  it('certify posts the request unchanged to /certify', async () => {
    const request = { keyHandle: 0x81000009, keyPassword: 'pw', nonce: 'AAEC' };
    await service.certify(request);

    const [url, body] = posted();
    expect(url).toMatch(/\/v1\/tpm\/certify$/);
    expect(body).toEqual({ keyHandle: 0x81000009, keyPassword: 'pw', nonce: 'AAEC' });
  });

  it('certify returns the server answer', async () => {
    const answer = { certifyInfo: 'AQID', signature: 'BAUG', signatureAlgorithm: 'SHA256-RSASSA' };
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: answer });

    const result = await service.certify({ keyHandle: 0x81000009 });

    expect(result.success).toBe(true);
    expect(result.data).toEqual(answer);
  });

  it('certify passes a refusal through', async () => {
    const refusal = {
      success: false,
      error: { code: 'NOT_FOUND', message: 'certify: no key at handle 0x81000009' },
    };
    vi.mocked(mockClient.post).mockResolvedValue(refusal);

    const result = await service.certify({ keyHandle: 0x81000009 });

    expect(result).toEqual(refusal);
  });
});
