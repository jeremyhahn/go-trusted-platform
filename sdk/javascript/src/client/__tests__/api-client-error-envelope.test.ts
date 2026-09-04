/**
 * Unit tests for the platform error-envelope mapping.
 *
 * The platform answers errors with `{code, error, success, service,
 * reason}` rather than the `{code, message, details}` shape the SDK
 * models. Callers receive `ApiResponse.error` — a plain object, not the
 * ApiError instance — so the HTTP status and the machine-readable
 * `reason` discriminator have to survive that translation, or callers
 * are left pattern-matching operator-facing prose.
 */

import { describe, it, expect } from 'vitest';
import { ApiClient } from '../api-client.js';
import { SERVICE_NOT_CONFIGURED, isServiceNotConfigured } from '../../errors/service-availability.js';

/** Builds a client whose fetch returns one canned JSON response. */
function clientReturning(status: number, body: unknown): ApiClient {
  const fetchImpl = (() =>
    Promise.resolve(new Response(JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json' },
    }))) as unknown as typeof fetch;

  return new ApiClient({
    baseUrl: 'https://platform.test/api/v1',
    fetch: fetchImpl,
    retry: { maxRetries: 0 },
  });
}

/** The exact body pkg/webservice/v1/service_registry.go writes. */
const registry503 = {
  code: 503,
  error: 'compute service not configured by daemon — REST surface is dark',
  success: false,
  service: 'compute',
  reason: SERVICE_NOT_CONFIGURED,
};

describe('ApiClient error envelope mapping', () => {
  it('carries status, reason and service through to ApiResponse.error', async () => {
    const client = clientReturning(503, registry503);

    const response = await client.get('/compute/vms');

    expect(response.success).toBe(false);
    expect(response.error?.status).toBe(503);
    expect(response.error?.message).toBe(registry503.error);
    expect(response.error?.details?.reason).toBe(SERVICE_NOT_CONFIGURED);
    expect(response.error?.details?.service).toBe('compute');
    expect(isServiceNotConfigured(response.error)).toBe(true);
  });

  it('leaves details undefined for an envelope with no reason or service', async () => {
    const client = clientReturning(503, {
      code: 503,
      error: 'compute backend temporarily unavailable',
      success: false,
    });

    const response = await client.get('/compute/vms');

    expect(response.error?.status).toBe(503);
    expect(response.error?.details).toBeUndefined();
    expect(isServiceNotConfigured(response.error)).toBe(false);
  });

  it('lets an explicit details object win over the lifted top-level fields', async () => {
    const client = clientReturning(400, {
      code: 400,
      error: 'validation failed',
      reason: 'IGNORED',
      details: { reason: 'FIELD_INVALID', fieldErrors: { name: ['required'] } },
    });

    const response = await client.get('/compute/vms');

    expect(response.error?.status).toBe(400);
    expect(response.error?.details?.reason).toBe('FIELD_INVALID');
    expect(response.error?.details?.fieldErrors).toEqual({ name: ['required'] });
  });

  it('reports the status on a non-JSON error response too', async () => {
    const fetchImpl = (() =>
      Promise.resolve(
        new Response('gateway exploded', {
          status: 502,
          headers: { 'content-type': 'text/plain' },
        })
      )) as unknown as typeof fetch;
    const client = new ApiClient({
      baseUrl: 'https://platform.test/api/v1',
      fetch: fetchImpl,
      retry: { maxRetries: 0 },
    });

    const response = await client.get('/compute/vms');

    expect(response.error?.status).toBe(502);
    expect(isServiceNotConfigured(response.error)).toBe(false);
  });
});
