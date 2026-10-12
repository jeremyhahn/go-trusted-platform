/**
 * Unit tests for the TPM info lookup (#325).
 *
 * `PlatformService.getTPMInfo` used to call `GET /api/v1/platform/tpm`, a
 * route the daemon never served, and typed the reply as a `{tpm: {...}}`
 * wrapper the server never sends. Both entry points now read
 * `GET /api/v1/tpm/info`, whose payload is the flat proto `TPMInfoResponse`.
 * The body below is what pkg/webservice/v1/rest/tpm writes for it (pinned
 * server-side by handlers_info_test.go), so these tests assert the parsed
 * result a caller sees, not just the status code.
 */

import { describe, it, expect } from 'vitest';
import { ApiClient } from '../../client/api-client.js';
import { PlatformService } from '../platform-service.js';
import { TPMService } from '../tpm-service.js';
import type { ApiResponse } from '../../types/api.js';
import type { TPMInfoResponse } from '../../types/tpm.js';

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

const tpmInfo: TPMInfoResponse = {
  version: 'TPM_VERSION_2_0',
  manufacturer: { name: 'Infineon', id: 1229346816, model: 'SLB9670', firmwareVersion: '7.85' },
  capabilities: [],
  pcrBanks: ['PCR_BANK_SHA256'],
  maxNvramSize: 2048,
  isSimulator: false,
  fipsMode: false,
  properties: { info: 'Manufacturer: IFX' },
  nvIndexes: [{ handle: 29360130, type: 'ordinary', size: 1024, authRead: true, authWrite: false }],
};

const success200 = { code: 200, error: '', success: true, payload: tpmInfo };

const unavailable503 = { code: 503, error: 'tpm service is not available', success: false };

type InfoCall = (client: ApiClient) => Promise<ApiResponse<TPMInfoResponse>>;

const entryPoints: Array<[string, InfoCall]> = [
  ['PlatformService.getTPMInfo', (client) => new PlatformService(client).getTPMInfo()],
  ['TPMService.getInfo', (client) => new TPMService(client).getInfo()],
];

describe.each(entryPoints)('%s', (_name, call) => {
  it('reads GET /api/v1/tpm/info and returns the flat server payload', async () => {
    const { client, urls } = clientReturning(200, success200);

    const response = await call(client);

    expect(urls).toEqual(['https://platform.test/api/v1/tpm/info']);
    expect(response.success).toBe(true);
    expect(response.data).toEqual(tpmInfo);
    expect(response.data?.version).toBe('TPM_VERSION_2_0');
    expect(response.data?.manufacturer?.name).toBe('Infineon');
    expect(response.data?.pcrBanks).toEqual(['PCR_BANK_SHA256']);
    expect(response.data?.nvIndexes[0]?.handle).toBe(29360130);
    expect(response.data).not.toHaveProperty('tpm');
    expect(response.data).not.toHaveProperty('available');
  });

  it('keeps a null manufacturer, as sent when the fixed properties are unreadable', async () => {
    const { client } = clientReturning(200, { ...success200, payload: { ...tpmInfo, manufacturer: null } });

    const response = await call(client);

    expect(response.success).toBe(true);
    expect(response.data?.manufacturer).toBeNull();
  });

  it('reports an unavailable TPM as an unsuccessful response with no data', async () => {
    const { client } = clientReturning(503, unavailable503);

    const response = await call(client);

    expect(response.success).toBe(false);
    expect(response.data).toBeUndefined();
    expect(response.error?.status).toBe(503);
    expect(response.error?.message).toBe(unavailable503.error);
  });
});
