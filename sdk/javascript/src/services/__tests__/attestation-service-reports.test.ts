/**
 * The four report routes the console re-exports (#428): list, get, refresh,
 * callers. Each is asserted against the path and method the server mounts
 * (pkg/webservice/v1/rest/attestation/reports_router.go, caller_gate.go).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AttestationService } from '../attestation-service.js';
import type { ApiClient } from '../../client/api-client.js';
import type { ApiResponse } from '../../types/api.js';
import type { DeviceReport, RefreshDeviceReportResponse } from '../../types/attestation.js';

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

describe('AttestationService device reports', () => {
  let service: AttestationService;
  let client: ApiClient;

  beforeEach(() => {
    client = createMockApiClient();
    service = new AttestationService(client);
  });

  it('lists the fleet from /v1/attestation/reports', async () => {
    vi.mocked(client.get).mockResolvedValue({ success: true, data: { reports: [], count: 0 } });
    const result = await service.listDeviceReports();
    expect(client.get).toHaveBeenCalledWith('/v1/attestation/reports');
    expect(result.data?.count).toBe(0);
  });

  it('gets one device from /v1/attestation/reports/{device_id} with the id encoded', async () => {
    const report = { device_id: '9007199254740993', verified: false } as DeviceReport;
    vi.mocked(client.get).mockResolvedValue({ success: true, data: report });
    const result = await service.getDeviceReport('9007199254740993');
    expect(client.get).toHaveBeenCalledWith('/v1/attestation/reports/9007199254740993');
    expect(result.data?.device_id).toBe('9007199254740993');
  });

  it('passes a 404 through unchanged so the caller can classify never-collected', async () => {
    const notFound: ApiResponse<DeviceReport> = {
      success: false,
      error: { code: 'NOT_FOUND', message: 'no report has been collected for device 7', status: 404 },
    };
    vi.mocked(client.get).mockResolvedValue(notFound);
    const result = await service.getDeviceReport('7');
    expect(result.success).toBe(false);
    expect(result.error?.status).toBe(404);
  });

  it('refreshes with a POST to /reports/{device_id}/refresh and returns the 202 envelope', async () => {
    const accepted: RefreshDeviceReportResponse = { device_id: '7', enqueued: true, note: 'collection enqueued' };
    vi.mocked(client.post).mockResolvedValue({ success: true, data: accepted });
    const result = await service.refreshDeviceReport('7');
    expect(client.post).toHaveBeenCalledWith('/v1/attestation/reports/7/refresh', {});
    expect(result.data?.enqueued).toBe(true);
  });

  it('describes the caller policy from /v1/attestation/callers', async () => {
    vi.mocked(client.get).mockResolvedValue({ success: true, data: { strategy: 'any-attested', identities: [], list_valid: true, anchors_configured: false, attested_peers_available: false, admits_nobody: true } });
    const result = await service.describeCallers();
    expect(client.get).toHaveBeenCalledWith('/v1/attestation/callers');
    expect(result.data?.admits_nobody).toBe(true);
  });

  it('surfaces a transport failure on refresh rather than claiming an enqueue', async () => {
    vi.mocked(client.post).mockRejectedValue(new Error('connection refused'));
    await expect(service.refreshDeviceReport('7')).rejects.toThrow('connection refused');
  });
});
