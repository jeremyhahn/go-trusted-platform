/**
 * TPMService PCR extend, credential and random operations (#1725): each
 * method posts its request body unchanged to its own route.
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

describe('TPMService operations', () => {
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

  it('extendPCR posts to /pcrs/extend', async () => {
    const request = { index: 16, hashAlg: 'SHA256', data: 'AAEC' };
    await service.extendPCR(request);

    const [url, body] = posted();
    expect(url).toMatch(/\/v1\/tpm\/pcrs\/extend$/);
    expect(body).toEqual(request);
  });

  it('makeCredential posts to /make-credential', async () => {
    const request = { akName: 'AAsAAQ==', secret: 'c2VjcmV0' };
    await service.makeCredential(request);

    const [url, body] = posted();
    expect(url).toMatch(/\/v1\/tpm\/make-credential$/);
    expect(body).toEqual(request);
  });

  it('activateCredential posts to /activate-credential', async () => {
    const request = { credentialBlob: 'YmxvYg==', encryptedSecret: 'ZW5j' };
    await service.activateCredential(request);

    const [url, body] = posted();
    expect(url).toMatch(/\/v1\/tpm\/activate-credential$/);
    expect(body).toEqual(request);
  });

  it('getRandom posts to /random', async () => {
    await service.getRandom({ numBytes: 32 });

    const [url, body] = posted();
    expect(url).toMatch(/\/v1\/tpm\/random$/);
    expect(body).toEqual({ numBytes: 32 });
  });
});
