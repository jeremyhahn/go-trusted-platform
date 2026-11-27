/**
 * Unit tests for the entity type listing (#2047).
 *
 * `PlatformService.listEntityTypes` reads `GET /api/v1/platform/entity-types`,
 * the REST route for `PlatformDaemon.ListEntityTypes`. The payload carries no
 * database path: pkg/webservice/v1/rest/platform drops it on purpose.
 */
import { describe, it, expect } from 'vitest';
import { ApiClient } from '../../client/api-client.js';
import { PlatformService } from '../platform-service.js';
import type { ListEntityTypesResponse } from '../../types/platform.js';

/** A client whose fetch records each URL and answers with one JSON body. */
function clientReturning(status: number, body: unknown): { client: ApiClient; urls: string[] } {
  const urls: string[] = [];
  const fetchImpl = ((url: RequestInfo | URL) => {
    urls.push(String(url));
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
  return { client, urls };
}

const payload: ListEntityTypesResponse = {
  entityTypes: [{ name: 'device', entityCount: 7, status: 'active' }],
  totalEntities: 7,
  activeTypes: 1,
};

describe('PlatformService.listEntityTypes', () => {
  it('reads GET /api/v1/platform/entity-types', async () => {
    const { client, urls } = clientReturning(200, { code: 200, error: '', success: true, payload });

    const response = await new PlatformService(client).listEntityTypes();

    expect(urls).toEqual(['https://platform.test/api/v1/platform/entity-types']);
    expect(response.success).toBe(true);
    expect(response.data).toEqual(payload);
  });

  it('passes a refusal through', async () => {
    const { client } = clientReturning(503, {
      code: 503,
      error: 'platform: entity type lister is not configured on this daemon',
      success: false,
    });

    const response = await new PlatformService(client).listEntityTypes();

    expect(response.success).toBe(false);
  });
});
