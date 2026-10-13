/**
 * DeviceService.recordAttestCert drives POST /api/v1/devices/{id}/attest-cert/record
 * (docs/device/api.md §4.5). The tests run the real ApiClient over a canned
 * fetch so the route, the request body, the envelope unwrap and the verbatim
 * refusal text are all asserted against what the Go handler writes.
 */
import { describe, it, expect } from 'vitest';
import { DeviceService } from '../device-service.js';
import { ApiClient } from '../../client/api-client.js';
import type { RecordAttestCertResponse } from '../../types/device.js';

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

/** The payload exactly as pkg/webservice/v1/device RecordAttestCertResponse emits it. */
const recorded: RecordAttestCertResponse = {
  device_id: '42',
  serial: 'SN0042',
  model: 'SuperMicro X10',
  changed: true,
  source: 'reissued',
  source_detail: 'iak-SuperMicro X10-SN0042',
  reissued: true,
  subject: 'CN=iak-SuperMicro X10-SN0042,O=Example',
  certificate_serial: '1f2e3d',
  not_after: '9999-12-31T23:59:59Z',
  attest_cert: '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n',
};

const refusal =
  'device: attestation certificate refused for device 42; nothing recorded: ' +
  'device: no certificate on the record; ca[node-03]: lacks tcg-cap-verifiedTPMRestricted';

describe('DeviceService.recordAttestCert', () => {
  it('posts to /api/v1/devices/{id}/attest-cert/record and unwraps the recorded certificate', async () => {
    const { service, requests } = serviceReturning(200, { code: 200, success: true, payload: recorded });

    const result = await service.recordAttestCert(42, { reissue: true });

    expect(requests).toEqual([
      { url: 'https://platform.test/api/v1/devices/42/attest-cert/record', method: 'POST', body: { reissue: true } },
    ]);
    expect(result.success).toBe(true);
    expect(result.data).toEqual(recorded);
  });

  it('sends reissue: false when the caller does not opt in', async () => {
    const { service, requests } = serviceReturning(200, {
      code: 200,
      success: true,
      payload: { ...recorded, changed: false, source: 'device', reissued: false },
    });

    const result = await service.recordAttestCert('42');

    expect(requests[0]?.body).toEqual({ reissue: false });
    expect(result.data?.source).toBe('device');
    expect(result.data?.changed).toBe(false);
  });

  it('surfaces a refusal (400) with the control plane message verbatim and nothing recorded', async () => {
    const { service } = serviceReturning(400, { code: 400, error: refusal, success: false, payload: null });

    const result = await service.recordAttestCert(42, { reissue: true });

    expect(result.success).toBe(false);
    expect(result.data).toBeUndefined();
    expect(result.error?.status).toBe(400);
    expect(result.error?.message).toBe(refusal);
  });

  it('surfaces a transport failure rather than inventing a recorded certificate', async () => {
    const client = new ApiClient({
      baseUrl: 'https://platform.test/api',
      fetch: (() => Promise.reject(new TypeError('connection refused'))) as unknown as typeof fetch,
      retry: { maxRetries: 0 },
    });

    const result = await new DeviceService(client).recordAttestCert(42);

    expect(result.success).toBe(false);
    expect(result.data).toBeUndefined();
  });
});
