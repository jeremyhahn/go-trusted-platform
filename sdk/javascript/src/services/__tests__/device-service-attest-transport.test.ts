/**
 * Transport-level regression test for attestDevice (Codex round 1, PR #2364).
 *
 * The server consumes a single-use attestation challenge before it verifies
 * the evidence. If the response is lost after that, a client that replays the
 * request gets a 409 "challenge unknown or already used", which hides the
 * original outcome. attestDevice must therefore never retry, even though the
 * ApiClient retries network failures on other requests.
 */

import { describe, it, expect, vi } from 'vitest';
import { ApiClient } from '../../client/api-client';
import { DeviceService } from '../device-service';

const consumed409 = {
  code: 409,
  error: 'attestation challenge unknown or already used',
  success: false,
};

function lostThen409() {
  const fetchImpl = vi.fn<typeof fetch>();
  fetchImpl.mockRejectedValueOnce(new TypeError('fetch failed'));
  fetchImpl.mockImplementation(() =>
    Promise.resolve(
      new Response(JSON.stringify(consumed409), {
        status: 409,
        headers: { 'content-type': 'application/json' },
      })
    )
  );

  const client = new ApiClient({
    baseUrl: 'https://platform.test/api',
    fetch: fetchImpl,
    retry: { maxRetries: 3, initialDelayMs: 1, maxDelayMs: 1 },
  });

  return { fetchImpl, client, service: new DeviceService(client) };
}

function requestOf(call: unknown[]): { url: string; method: string } {
  const [input, init] = call as [RequestInfo | URL, RequestInit | undefined];
  if (input instanceof Request) {
    return { url: input.url, method: input.method };
  }
  return { url: String(input), method: (init?.method ?? 'GET').toUpperCase() };
}

describe('DeviceService attestDevice over a real ApiClient', () => {
  it('does not replay the evidence when the response is lost', async () => {
    const { fetchImpl, service } = lostThen409();

    const response = await service.attestDevice(7, { evidence: 'ZQ==', challenge_id: 'ch-1' });

    expect(response.success).toBe(false);
    expect(response.error?.message).toContain('fetch failed');
    expect(response.error?.status).not.toBe(409);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const sent = requestOf(fetchImpl.mock.calls[0]);
    expect(sent.url.endsWith('/devices/7/attest')).toBe(true);
    expect(sent.method).toBe('POST');
  });

  it('the same client does retry a plain POST on a lost response', async () => {
    const { fetchImpl, client } = lostThen409();

    const response = await client.post('/v1/devices/7/attest-probe', {});

    expect(fetchImpl.mock.calls.length).toBeGreaterThanOrEqual(2);
    expect(response.success).toBe(false);
    expect(response.error?.status).toBe(409);
  });

  it('does not replay without a challenge_id either', async () => {
    const { fetchImpl, service } = lostThen409();

    const response = await service.attestDevice(7, { evidence: 'ZQ==' });

    expect(response.success).toBe(false);
    expect(response.error?.message).toContain('fetch failed');
    expect(response.error?.status).not.toBe(409);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const sent = requestOf(fetchImpl.mock.calls[0]);
    expect(sent.url.endsWith('/devices/7/attest')).toBe(true);
    expect(sent.method).toBe('POST');
  });
});
