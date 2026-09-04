/**
 * Regression tests for #245.
 *
 * A non-ok JSON response whose body is not an object used to be read with
 * `json.code` / `json.message` directly. `Response.json()` returns `null` for
 * a body of literal `null`, so that threw a TypeError, which the transport
 * error handler caught and reported as `NETWORK_ERROR` with no status — an
 * authorization denial arriving as an apparently transient fault, on the
 * console that fronts CA signing, KMS, TPM and barrier unseal. Callers that
 * retry network errors would retry a decision the server made deliberately.
 *
 * A `null` body needs no hostile input: Go's `json.NewEncoder(w).Encode(x)`
 * emits exactly `null` for a nil pointer, slice or interface, so any error
 * path encoding a nil payload alongside a non-2xx status produces it.
 *
 * What must hold for every one of these bodies: the HTTP status reaches the
 * caller, and the code is derived from that status rather than from a
 * transport failure.
 */

import { describe, it, expect } from 'vitest';
import { ApiClient } from '../api-client.js';

/** Builds a client whose fetch returns one canned response body verbatim. */
function clientReturningRaw(status: number, rawBody: string): ApiClient {
  const fetchImpl = (() =>
    Promise.resolve(new Response(rawBody, {
      status,
      headers: { 'content-type': 'application/json' },
    }))) as unknown as typeof fetch;

  return new ApiClient({
    baseUrl: 'https://platform.test/api/v1',
    fetch: fetchImpl,
    retry: { maxRetries: 0 },
  });
}

describe('ApiClient, non-ok JSON body that is not an object (#245)', () => {
  it('reports a 403 with a null body as a 403, not as NETWORK_ERROR', async () => {
    const response = await clientReturningRaw(403, 'null').get('/anything');

    expect(response.error?.code).toBe('HTTP_403');
    expect(response.error?.status).toBe(403);
    // The specific regression: a deliberate denial must never be reported as
    // a transport fault, or retry logic will re-attempt it.
    expect(response.error?.code).not.toBe('NETWORK_ERROR');
    expect(response.error?.message).not.toContain('Cannot read properties');
  });

  it('reports a 503 with a null body as a 503, not as NETWORK_ERROR', async () => {
    const response = await clientReturningRaw(503, 'null').get('/anything');

    expect(response.error?.code).toBe('HTTP_503');
    expect(response.error?.status).toBe(503);
    expect(response.error?.code).not.toBe('NETWORK_ERROR');
  });

  it.each([
    ['array', '[1,2]'],
    ['string', '"boom"'],
    ['number', '42'],
    ['boolean', 'true'],
  ])('reports a 403 with a %s body as a 403', async (_label, rawBody) => {
    const response = await clientReturningRaw(403, rawBody).get('/anything');

    expect(response.error?.code).toBe('HTTP_403');
    expect(response.error?.status).toBe(403);
  });

  it('falls back to a readable message when there is no reason phrase', async () => {
    const response = await clientReturningRaw(403, 'null').get('/anything');

    // `statusText` is the empty string here, and `??` would have surfaced
    // that blank rather than falling through.
    expect(response.error?.message).toBe('An error occurred');
  });

  it('still prefers the platform envelope when the body IS an object', async () => {
    const response = await clientReturningRaw(
      403,
      JSON.stringify({ code: 'FORBIDDEN', error: 'admin role required', success: false })
    ).get('/anything');

    expect(response.error?.code).toBe('FORBIDDEN');
    expect(response.error?.status).toBe(403);
    expect(response.error?.message).toBe('admin role required');
  });

  it('unwraps a successful envelope unchanged', async () => {
    const response = await clientReturningRaw(
      200,
      JSON.stringify({ success: true, payload: { id: 'abc' } })
    ).get<{ id: string }>('/anything');

    expect(response.error).toBeUndefined();
    expect(response.data?.id).toBe('abc');
  });

  it('returns a null success body as null rather than throwing', async () => {
    const response = await clientReturningRaw(200, 'null').get('/anything');

    expect(response.error).toBeUndefined();
    expect(response.data).toBeNull();
  });
});
