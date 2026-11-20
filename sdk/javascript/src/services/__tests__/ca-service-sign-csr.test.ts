/**
 * Unit tests for CAService.signCSR: POST /v1/ca/sign-csr with the CSR in
 * PEM form and an optional validity, as the REST handler decodes it
 * (pkg/webservice/v1/rest/ca/handlers.go, SignCSR).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CAService } from '../ca-service.js';
import { ApiClient } from '../../client/api-client.js';

const NO_RETRY = { retry: { enabled: false } };
const CSR_PEM = '-----BEGIN CERTIFICATE REQUEST-----\nCSR\n-----END CERTIFICATE REQUEST-----';

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

describe('CAService.signCSR', () => {
  let service: CAService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new CAService(mockClient);
  });

  it('POSTs the CSR and validity to /v1/ca/sign-csr', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({
      success: true,
      data: { certificate: { serial: '0a1b2c' } },
    });

    const result = await service.signCSR({ csrPem: CSR_PEM, validDays: 30 });

    expect(result.success).toBe(true);
    expect(mockClient.post).toHaveBeenCalledTimes(1);
    expect(mockClient.post).toHaveBeenCalledWith('/v1/ca/sign-csr', { csrPem: CSR_PEM, validDays: 30 }, NO_RETRY);
  });

  it('propagates a scope refusal unchanged', async () => {
    const failure = new Error('403 Forbidden: token lacks scope ca:sign-csr');
    vi.mocked(mockClient.post).mockRejectedValue(failure);

    await expect(service.signCSR({ csrPem: CSR_PEM })).rejects.toBe(failure);
    expect(mockClient.post).toHaveBeenCalledWith('/v1/ca/sign-csr', { csrPem: CSR_PEM }, NO_RETRY);
  });
});

describe('CAService.signCSR without client retries', () => {
  it('surfaces a lost response with exactly one POST', async () => {
    // The server issues a certificate before it answers; a resend after a
    // lost response would issue a second certificate for the same CSR.
    const fetchImpl = vi
      .fn()
      .mockRejectedValueOnce(new TypeError('network error: response lost after the server acted'))
      .mockResolvedValue(
        new Response(JSON.stringify({ success: true, payload: { certificate: { serial: 'second' } } }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        })
      );
    const client = new ApiClient({
      baseUrl: 'https://platform.test/api/v1',
      fetch: fetchImpl as unknown as typeof fetch,
      retry: { maxRetries: 3, initialDelayMs: 1, maxDelayMs: 1 },
    });

    const result = await new CAService(client).signCSR({ csrPem: CSR_PEM });

    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(result.success).toBe(false);
    expect(result.error?.message).toMatch(/network error/);
  });
});
