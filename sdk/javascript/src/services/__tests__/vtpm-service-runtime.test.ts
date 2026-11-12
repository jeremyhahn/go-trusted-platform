/**
 * Unit tests for the vTPM bundle runtime routes of
 * pkg/webservice/v1/rest/vtpm/router.go: start, stop, quote, seal, unseal,
 * PCR extend and PCR read. Each test pins the verb, the path and the body.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { VTPMService } from '../vtpm-service.js';
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
    expect(mockClient.post).toHaveBeenCalledWith('/v1/vtpm/bundles/vm%201/start', {}, {
      retry: { enabled: false },
    });
  });

  it('stopBundle POSTs /bundles/{id}/stop', async () => {
    await service.stopBundle('vm-1');
    expect(mockClient.post).toHaveBeenCalledWith('/v1/vtpm/bundles/vm-1/stop', {}, {
      retry: { enabled: false },
    });
  });

  it('stopBundle marks a daemon stop reply stopped', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({
      success: true,
      data: { bundle_id: 'vm-1', action: 'stop', success: true },
    });
    const r = await service.stopBundle('vm-1');
    expect(r.data?.stopped).toBe(true);
  });

  it('stopBundle passes a webservice stop reply unchanged', async () => {
    const reply = { status: { success: true }, bundle_id: 'vm-1', stopped: false };
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: reply });
    const r = await service.stopBundle('vm-1');
    expect(r.data).toEqual(reply);
  });

  it('readBundlePCR falls back to /pcr/{index} on 404', async () => {
    vi.mocked(mockClient.get)
      .mockResolvedValueOnce({
        success: false,
        error: { code: 'NOT_FOUND', message: '404', status: 404 },
      } as never)
      .mockResolvedValueOnce({
        success: true,
        data: { bundle_id: 'vm-1', pcr_index: 7, value: '3q2+7w==' },
      } as never);
    const r = await service.readBundlePCR('vm-1', 7);
    expect(mockClient.get).toHaveBeenCalledTimes(2);
    expect(vi.mocked(mockClient.get).mock.calls[1][0]).toBe('/v1/vtpm/bundles/vm-1/pcr/7');
    expect(r.success).toBe(true);
    expect(r.data?.value).toBe('3q2+7w==');
  });

  it('readBundlePCR falls back on a thrown 404', async () => {
    vi.mocked(mockClient.get)
      .mockRejectedValueOnce(Object.assign(new Error('404 Not Found'), { status: 404 }))
      .mockResolvedValueOnce({
        success: true,
        data: { bundle_id: 'vm-1', pcr_index: 7, value: 'AA==' },
      } as never);
    const r = await service.readBundlePCR('vm-1', 7);
    expect(vi.mocked(mockClient.get).mock.calls[1][0]).toBe('/v1/vtpm/bundles/vm-1/pcr/7');
    expect(r.data?.value).toBe('AA==');
  });

  it('extendBundlePCR falls back to /pcr/{index}/extend on 404', async () => {
    vi.mocked(mockClient.post)
      .mockResolvedValueOnce({
        success: false,
        error: { code: 'NOT_FOUND', message: '404', status: 404 },
      } as never)
      .mockResolvedValueOnce({
        success: true,
        data: { bundle_id: 'vm-1', action: 'extend_pcr', success: true, message: 'ok' },
      } as never);
    const r = await service.extendBundlePCR('vm-1', { pcr_index: 16, data: 'AAAA' });
    expect(mockClient.post).toHaveBeenCalledTimes(2);
    expect(vi.mocked(mockClient.post).mock.calls[1]).toEqual([
      '/v1/vtpm/bundles/vm-1/pcr/16/extend',
      { data: 'AAAA' },
      { retry: { enabled: false } },
    ]);
    expect(r.success).toBe(true);
    expect(r.data).toEqual({
      status: { success: true, message: 'ok' },
      bundle_id: 'vm-1',
      pcr_index: 16,
      extended: true,
    });
  });

  it('returns the first result when both listeners answer 404', async () => {
    const first = { success: false, error: { code: 'NOT_FOUND', message: 'first', status: 404 } };
    vi.mocked(mockClient.get)
      .mockResolvedValueOnce(first as never)
      .mockResolvedValueOnce({
        success: false,
        error: { code: 'NOT_FOUND', message: 'second', status: 404 },
      } as never);
    const r = await service.readBundlePCR('vm-1', 7);
    expect(r).toBe(first);
  });

  it('no fallback on 409', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({
      success: false,
      error: { code: 'CONFLICT', message: 'not running', status: 409 },
    } as never);
    vi.mocked(mockClient.get).mockResolvedValue({
      success: false,
      error: { code: 'CONFLICT', message: 'not running', status: 409 },
    } as never);
    await service.extendBundlePCR('vm-1', { pcr_index: 16, data: 'AAAA' });
    await service.readBundlePCR('vm-1', 7);
    expect(mockClient.post).toHaveBeenCalledTimes(1);
    expect(mockClient.get).toHaveBeenCalledTimes(1);
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

  it('extendBundlePCR POSTs the index and data to /bundles/{id}/pcrs/extend', async () => {
    await service.extendBundlePCR('vm-1', { pcr_index: 16, data: 'AAAA' });
    expect(mockClient.post).toHaveBeenCalledWith(
      '/v1/vtpm/bundles/vm-1/pcrs/extend',
      { pcr_index: 16, data: 'AAAA' },
      { retry: { enabled: false } }
    );
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

describe('extendBundlePCR transport', () => {
  it('sends a PCR extend once when the response is lost', async () => {
    const fetchImpl = vi
      .fn()
      .mockRejectedValueOnce(new TypeError('Failed to fetch'))
      .mockResolvedValue(
        new Response(JSON.stringify({ pcr_index: 16, value: 'AAAA' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      );
    const client = new ApiClient({
      baseUrl: 'https://platform.test/api/v1',
      fetch: fetchImpl as unknown as typeof fetch,
      retry: { maxRetries: 3, initialDelayMs: 1, maxDelayMs: 1 },
    });

    let result: Awaited<ReturnType<VTPMService['extendBundlePCR']>> | undefined;
    let thrown: unknown;
    try {
      result = await new VTPMService(client).extendBundlePCR('vm-1', { pcr_index: 16, data: 'AAAA' });
    } catch (err) {
      thrown = err;
    }

    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(thrown !== undefined || result?.success === false).toBe(true);
  });

  for (const op of ['startBundle', 'stopBundle'] as const) {
    it(`sends ${op} once when the response is lost`, async () => {
      const fetchImpl = vi
        .fn()
        .mockRejectedValueOnce(new TypeError('Failed to fetch'))
        .mockResolvedValue(
          new Response(JSON.stringify({ status: 409, error: 'vtpm: already running' }), {
            status: 409,
            headers: { 'Content-Type': 'application/json' },
          })
        );
      const client = new ApiClient({
        baseUrl: 'https://platform.test/api/v1',
        fetch: fetchImpl as unknown as typeof fetch,
        retry: { maxRetries: 3, initialDelayMs: 1, maxDelayMs: 1 },
      });

      let result: { success: boolean } | undefined;
      let thrown: unknown;
      try {
        result = await new VTPMService(client)[op]('vm-1');
      } catch (err) {
        thrown = err;
      }

      expect(fetchImpl).toHaveBeenCalledTimes(1);
      expect(thrown !== undefined || result?.success === false).toBe(true);
    });
  }
});
