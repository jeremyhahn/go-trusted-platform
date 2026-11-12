/**
 * Unit tests for the vTPM bundle runtime routes of
 * pkg/webservice/v1/rest/vtpm/router.go: start, stop, quote, seal, unseal,
 * PCR extend and PCR read. Each test pins the verb, the path and the body.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { VTPMService } from '../vtpm-service.js';
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

describe('VTPMService bundle runtime', () => {
  let service: VTPMService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new VTPMService(mockClient);
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: {} });
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: {} });
  });

  it('startBundle POSTs /bundles/{id}/start', async () => {
    await service.startBundle('vm 1');
    expect(mockClient.post).toHaveBeenCalledWith('/v1/vtpm/bundles/vm%201/start', {});
  });

  it('stopBundle POSTs /bundles/{id}/stop', async () => {
    await service.stopBundle('vm-1');
    expect(mockClient.post).toHaveBeenCalledWith('/v1/vtpm/bundles/vm-1/stop', {});
  });

  it('quoteBundle POSTs the nonce and PCRs to /bundles/{id}/quote', async () => {
    await service.quoteBundle('vm-1', { nonce: 'bm9uY2U=', pcrs: [0, 7] });
    expect(mockClient.post).toHaveBeenCalledWith('/v1/vtpm/bundles/vm-1/quote', {
      nonce: 'bm9uY2U=',
      pcrs: [0, 7],
    });
  });

  it('sealBundle POSTs the data to /bundles/{id}/seal', async () => {
    await service.sealBundle('vm-1', { data: 'c2VjcmV0', pcrs: [7], auth_value: 'pw' });
    expect(mockClient.post).toHaveBeenCalledWith('/v1/vtpm/bundles/vm-1/seal', {
      data: 'c2VjcmV0',
      pcrs: [7],
      auth_value: 'pw',
    });
  });

  it('unsealBundle POSTs the sealed blob to /bundles/{id}/unseal', async () => {
    await service.unsealBundle('vm-1', { sealed_data: 'YmxvYg==' });
    expect(mockClient.post).toHaveBeenCalledWith('/v1/vtpm/bundles/vm-1/unseal', {
      sealed_data: 'YmxvYg==',
    });
  });

  it('extendBundlePCR POSTs the index and digest to /bundles/{id}/pcrs/extend', async () => {
    await service.extendBundlePCR('vm-1', { pcr_index: 16, data: 'AAAA' });
    expect(mockClient.post).toHaveBeenCalledWith('/v1/vtpm/bundles/vm-1/pcrs/extend', {
      pcr_index: 16,
      data: 'AAAA',
    });
  });

  it('readBundlePCR GETs /bundles/{id}/pcrs with the pcr_index query', async () => {
    await service.readBundlePCR('vm-1', 7);
    expect(mockClient.get).toHaveBeenCalledWith('/v1/vtpm/bundles/vm-1/pcrs?pcr_index=7');
    expect(mockClient.post).not.toHaveBeenCalled();
  });

  it('propagates a transport error unchanged', async () => {
    const failure = new Error('409 Conflict: vtpm: bundle not running');
    vi.mocked(mockClient.post).mockRejectedValue(failure);
    await expect(service.quoteBundle('vm-1', { nonce: 'AA==' })).rejects.toBe(failure);
  });
});
