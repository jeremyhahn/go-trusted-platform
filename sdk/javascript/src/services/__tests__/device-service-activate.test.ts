/**
 * DeviceService.activateDevice drives POST /api/v1/device/activate-json.
 * The server (pkg/webservice/v1/device ActivationRequest/ActivationResponse)
 * decodes `serial` and `mac_address` and answers a flat
 * `{ status, vlan, transitioned_at }`. The tests run the real ApiClient over
 * a canned fetch so the route, the wire names and the mapped answer are all
 * asserted against what the Go handler reads and writes.
 */
import { describe, it, expect } from 'vitest';
import { DeviceService } from '../device-service.js';
import { ApiClient } from '../../client/api-client.js';

interface CapturedRequest {
  url: string;
  method: string;
  body: unknown;
}

/** A service over a real ApiClient whose fetch answers one canned JSON response. */
function serviceReturning(status: number, body: unknown): { service: DeviceService; requests: CapturedRequest[] } {
  const requests: CapturedRequest[] = [];
  const fetchImpl = ((url: string, init: RequestInit) => {
    requests.push({
      url,
      method: init.method ?? '',
      body: typeof init.body === 'string' ? JSON.parse(init.body) : init.body,
    });
    return Promise.resolve(
      new Response(JSON.stringify(body), {
        status,
        headers: { 'content-type': 'application/json' },
      })
    );
  }) as unknown as typeof fetch;
  const client = new ApiClient({
    baseUrl: 'https://platform.test/api',
    fetch: fetchImpl,
    retry: { maxRetries: 0 },
  });
  return { service: new DeviceService(client), requests };
}

const activated = { status: 'activated', vlan: 101, transitioned_at: '2026-01-01T00:00:00Z' };

describe('DeviceService.activateDevice', () => {
  it('posts serial and mac_address to /device/activate-json', async () => {
    const { service, requests } = serviceReturning(200, { code: 200, success: true, payload: activated });

    await service.activateDevice({ serial: 'SN-1', macAddress: '02:00:00:00:00:01' });

    expect(requests).toEqual([
      {
        url: 'https://platform.test/api/v1/device/activate-json',
        method: 'POST',
        body: { serial: 'SN-1', mac_address: '02:00:00:00:00:01' },
      },
    ]);
  });

  it('reads the flat activation answer', async () => {
    const { service } = serviceReturning(200, { code: 200, success: true, payload: activated });

    const res = await service.activateDevice({ serial: 'SN-1', macAddress: '02:00:00:00:00:01' });

    expect(res.success).toBe(true);
    expect(res.data?.status).toBe('activated');
    expect(res.data?.vlan).toBe(101);
    expect(res.data?.transitionedAt).toBe('2026-01-01T00:00:00Z');
  });
});
