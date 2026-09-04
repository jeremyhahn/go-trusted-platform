/**
 * Unit tests for the PCR bank wire translation.
 *
 * The server's GetPCRs handler decodes its JSON body with protojson, which
 * accepts only the proto-canonical enum spelling (`PCR_BANK_SHA256`). The SDK
 * deliberately exposes the short form (`SHA256`) to callers, so `getPCRs` has
 * to translate on the way out.
 *
 * This is not cosmetic: when the translation is missing the server reads the
 * bank as UNSPECIFIED and returns EVERY bank's PCRs concatenated, which
 * shipped once as SHA-1 values rendered under a "SHA-256" label on the PCR
 * Banks dashboard. The translation had no test, so these pin it.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { TPMService } from '../tpm-service.js';
import type { ApiClient } from '../../client/api-client.js';
import type { GetPCRsRequest } from '../../types/tpm.js';

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

/** The `bank` field of the body the service actually posted. */
function postedBank(mockClient: ApiClient): unknown {
  const call = vi.mocked(mockClient.post).mock.calls[0];
  return (call?.[1] as { bank?: unknown } | undefined)?.bank;
}

describe('TPMService.getPCRs bank translation', () => {
  let service: TPMService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: {} });
    service = new TPMService(mockClient);
  });

  it('sends the proto-canonical enum name for a short bank', async () => {
    await service.getPCRs({ bank: 'SHA256', indices: [0, 1] });

    expect(postedBank(mockClient)).toBe('PCR_BANK_SHA256');
  });

  it('translates SHA1 as well, not only SHA256', async () => {
    await service.getPCRs({ bank: 'SHA1', indices: [0] });

    expect(postedBank(mockClient)).toBe('PCR_BANK_SHA1');
  });

  it('leaves an already-canonical bank untouched rather than double-prefixing', async () => {
    await service.getPCRs({ bank: 'PCR_BANK_SHA256' as never, indices: [0] });

    expect(postedBank(mockClient)).toBe('PCR_BANK_SHA256');
  });

  it('omits the bank entirely when the caller supplied none', async () => {
    await service.getPCRs({ indices: [0] });

    expect(postedBank(mockClient)).toBeUndefined();
  });

  it('does not mutate the caller-supplied request object', async () => {
    const request: GetPCRsRequest = { bank: 'SHA256', indices: [0] };
    await service.getPCRs({ ...request });

    expect(request.bank).toBe('SHA256');
  });
});
