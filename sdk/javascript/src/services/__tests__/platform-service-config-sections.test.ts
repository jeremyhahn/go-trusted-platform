/**
 * Unit tests for PlatformService.updateConfigSection (#2047).
 *
 * The daemon serves PlatformDaemon.UpdateConfig at
 * `PUT /api/v1/platform/config/sections/{section}` with a JSON body
 * `{values, persist}`; the reply payload is `{section, persisted, message}`
 * (pkg/webservice/v1/rest/platform/config_update_handlers.go). These tests
 * pin the URL, method and body the SDK sends and the parsed reply.
 */

import { describe, it, expect } from 'vitest';
import { ApiClient } from '../../client/api-client.js';
import { PlatformService } from '../platform-service.js';

interface Call {
  url: string;
  method: string | undefined;
  body: unknown;
}

/** A client whose fetch records each call and answers with one JSON body. */
function clientReturning(status: number, body: unknown): { client: ApiClient; calls: Call[] } {
  const calls: Call[] = [];
  const fetchImpl = ((url: RequestInfo | URL, init?: RequestInit) => {
    calls.push({
      url: String(url),
      method: init?.method,
      body: init?.body === undefined ? undefined : JSON.parse(String(init?.body)),
    });
    return Promise.resolve(new Response(JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json' },
    }));
  }) as unknown as typeof fetch;

  const client = new ApiClient({
    baseUrl: 'https://platform.test/api',
    fetch: fetchImpl,
    retry: { maxRetries: 0 },
  });
  return { client, calls };
}

const applied = { section: 'logging', persisted: false, message: 'configuration section applied' };

describe('PlatformService.updateConfigSection', () => {
  it('sends PUT /api/v1/platform/config/sections/{section}', async () => {
    const { client, calls } = clientReturning(200, { code: 200, error: '', success: true, payload: applied });

    const response = await new PlatformService(client).updateConfigSection('logging', { values: { level: 'debug' } });

    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe('https://platform.test/api/v1/platform/config/sections/logging');
    expect(calls[0]?.method).toBe('PUT');
    expect(calls[0]?.body).toEqual({ values: { level: 'debug' }, persist: false });
    expect(response.success).toBe(true);
    expect(response.data).toEqual(applied);
  });

  it('encodes the section', async () => {
    const { client, calls } = clientReturning(200, { code: 200, error: '', success: true, payload: applied });

    await new PlatformService(client).updateConfigSection('a/b', { values: { level: 'debug' } });

    expect(calls[0]?.url).toBe('https://platform.test/api/v1/platform/config/sections/a%2Fb');
  });

  it('passes persist and a refusal through', async () => {
    const refusal = { code: 400, error: 'platform: values is required', success: false };
    const { client, calls } = clientReturning(400, refusal);

    const response = await new PlatformService(client).updateConfigSection('logging', { values: {}, persist: true });

    expect(calls[0]?.body).toEqual({ values: {}, persist: true });
    expect(response.success).toBe(false);
  });
});
