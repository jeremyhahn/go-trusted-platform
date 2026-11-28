import { describe, it, expect, vi, beforeEach } from 'vitest';
import { PlatformService } from './platform-service.js';
import type { ApiClient } from '../client/api-client.js';

function createMockClient(): ApiClient {
  return {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
    head: vi.fn(),
    options: vi.fn(),
    fetch: vi.fn(),
  } as unknown as ApiClient;
}

describe('PlatformService', () => {
  let client: ApiClient;
  let service: PlatformService;
  const ok = { success: true, data: { value: 'ok' } };
  const failure = new Error('transport down');

  beforeEach(() => {
    client = createMockClient();
    vi.mocked(client.get).mockResolvedValue(ok);
    vi.mocked(client.post).mockResolvedValue(ok);
    service = new PlatformService(client);
  });

  function expectOnlyGet(path: string): void {
    expect(client.get).toHaveBeenCalledTimes(1);
    expect(client.get).toHaveBeenCalledWith(path);
    expect(client.post).not.toHaveBeenCalled();
  }

  describe('getVersion', () => {
    it('sends GET /v1/platform/version with no query and returns the response', async () => {
      await expect(service.getVersion()).resolves.toBe(ok);
      expectOnlyGet('/v1/platform/version');
    });

    it('propagates a transport error', async () => {
      vi.mocked(client.get).mockRejectedValue(failure);
      await expect(service.getVersion()).rejects.toBe(failure);
    });
  });

  describe('getSystemInfo', () => {
    it('sends GET /v1/platform/system with no query and returns the response', async () => {
      await expect(service.getSystemInfo()).resolves.toBe(ok);
      expectOnlyGet('/v1/platform/system');
    });

    it('propagates a transport error', async () => {
      vi.mocked(client.get).mockRejectedValue(failure);
      await expect(service.getSystemInfo()).rejects.toBe(failure);
    });
  });

  describe('getTPMInfo', () => {
    it('sends GET /v1/tpm/info, outside the platform base path', async () => {
      await expect(service.getTPMInfo()).resolves.toBe(ok);
      expectOnlyGet('/v1/tpm/info');
    });

    it('propagates a transport error', async () => {
      vi.mocked(client.get).mockRejectedValue(failure);
      await expect(service.getTPMInfo()).rejects.toBe(failure);
    });
  });

  describe('getHealth', () => {
    it('sends GET /v1/platform/health with no query when called without a request', async () => {
      await expect(service.getHealth()).resolves.toBe(ok);
      expectOnlyGet('/v1/platform/health');
    });

    it('omits the query when includeServices is unset', async () => {
      await service.getHealth({});
      expectOnlyGet('/v1/platform/health');
    });

    it('sends includeServices=true in the query', async () => {
      await service.getHealth({ includeServices: true });
      expectOnlyGet('/v1/platform/health?includeServices=true');
    });

    it('sends includeServices=false in the query', async () => {
      await service.getHealth({ includeServices: false });
      expectOnlyGet('/v1/platform/health?includeServices=false');
    });

    it('propagates a transport error', async () => {
      vi.mocked(client.get).mockRejectedValue(failure);
      await expect(service.getHealth({ includeServices: true })).rejects.toBe(failure);
    });
  });

  describe('getConfig', () => {
    it('sends GET /v1/platform/config with no query when called without a request', async () => {
      await expect(service.getConfig()).resolves.toBe(ok);
      expectOnlyGet('/v1/platform/config');
    });

    // The server reads `redact` (config_handlers.go), not includeSensitive.
    it('sends redact=false when includeSensitive is true', async () => {
      await service.getConfig({ includeSensitive: true });
      expectOnlyGet('/v1/platform/config?redact=false');
    });

    it('sends no redact parameter when includeSensitive is false', async () => {
      await service.getConfig({ includeSensitive: false });
      expectOnlyGet('/v1/platform/config');
    });

    it('propagates a transport error', async () => {
      vi.mocked(client.get).mockRejectedValue(failure);
      await expect(service.getConfig()).rejects.toBe(failure);
    });
  });

  describe('reloadConfig', () => {
    it('sends POST /v1/platform/config/reload with an empty body and no query', async () => {
      await expect(service.reloadConfig()).resolves.toBe(ok);
      expect(client.post).toHaveBeenCalledTimes(1);
      expect(client.post).toHaveBeenCalledWith('/v1/platform/config/reload', {});
      expect(client.get).not.toHaveBeenCalled();
    });

    it('propagates a transport error', async () => {
      vi.mocked(client.post).mockRejectedValue(failure);
      await expect(service.reloadConfig()).rejects.toBe(failure);
    });
  });

  describe('getMetrics', () => {
    it('sends GET /v1/platform/metrics with no query when called without a request', async () => {
      await expect(service.getMetrics()).resolves.toBe(ok);
      expectOnlyGet('/v1/platform/metrics');
    });

    it('sends includeHistory=true in the query', async () => {
      await service.getMetrics({ includeHistory: true });
      expectOnlyGet('/v1/platform/metrics?includeHistory=true');
    });

    it('sends includeHistory=false in the query', async () => {
      await service.getMetrics({ includeHistory: false });
      expectOnlyGet('/v1/platform/metrics?includeHistory=false');
    });

    it('propagates a transport error', async () => {
      vi.mocked(client.get).mockRejectedValue(failure);
      await expect(service.getMetrics()).rejects.toBe(failure);
    });
  });
});

// StatusResponse and ServicesListResponse (pkg/api/daemon/rest_service.go)
// carry time.Time, so the daemon sends an RFC 3339 string; the SDK types
// promise Unix seconds, and the service converts.
describe('PlatformService daemon timestamps', () => {
  const rfc3339 = '2026-11-20T10:15:30.5Z';
  const unixSeconds = Date.UTC(2026, 10, 20, 10, 15, 30) / 1000;

  function setup(data: unknown): { client: ApiClient; service: PlatformService } {
    const client = createMockClient();
    vi.mocked(client.get).mockResolvedValue({ success: true, data });
    return { client, service: new PlatformService(client, { routeLayout: 'daemon' }) };
  }

  it('getStatus returns the daemon timestamp as Unix seconds', async () => {
    const { service } = setup({ status: 'running', timestamp: rfc3339 });
    const res = await service.getStatus();
    expect(res.data?.timestamp).toBe(unixSeconds);
    expect(res.data?.status).toBe('running');
  });

  it('listServices returns the daemon timestamp as Unix seconds', async () => {
    const { service } = setup({ services: [], count: 0, timestamp: rfc3339 });
    const res = await service.listServices();
    expect(res.data?.timestamp).toBe(unixSeconds);
  });

  it('keeps a numeric timestamp as it is', async () => {
    const { service } = setup({ status: 'running', timestamp: 1700000000 });
    const res = await service.getStatus();
    expect(res.data?.timestamp).toBe(1700000000);
  });
});

// The daemon REST listener registers /api/v1/status and /api/v1/services
// (pkg/api/daemon/rest_service.go); the webservice listener serves the same
// operations under /api/v1/platform. The route layout picks one.
describe('PlatformService route layout', () => {
  const ok = { success: true, data: {} };

  function setup(layout?: 'webservice' | 'daemon'): { client: ApiClient; service: PlatformService } {
    const client = createMockClient();
    vi.mocked(client.get).mockResolvedValue(ok);
    vi.mocked(client.post).mockResolvedValue(ok);
    const service = layout === undefined
      ? new PlatformService(client)
      : new PlatformService(client, { routeLayout: layout });
    return { client, service };
  }

  const cases = [
    ['webservice', '/v1/platform'],
    ['daemon', '/v1'],
  ] as const;

  it.each(cases)('under %s, getStatus sends GET %s/status', async (layout, base) => {
    const { client, service } = setup(layout);
    await service.getStatus();
    expect(client.get).toHaveBeenCalledWith(`${base}/status`);
  });

  it.each(cases)('under %s, listServices sends GET %s/services', async (layout, base) => {
    const { client, service } = setup(layout);
    await service.listServices();
    expect(client.get).toHaveBeenCalledWith(`${base}/services`);
  });

  it.each(cases)('under %s, getServiceStatus sends GET %s/services/{service}', async (layout, base) => {
    const { client, service } = setup(layout);
    await service.getServiceStatus('a b');
    expect(client.get).toHaveBeenCalledWith(`${base}/services/a%20b`);
  });

  it.each([
    ['webservice', '/v1/platform', 'startService', 'start'],
    ['webservice', '/v1/platform', 'stopService', 'stop'],
    ['webservice', '/v1/platform', 'restartService', 'restart'],
    ['daemon', '/v1', 'startService', 'start'],
    ['daemon', '/v1', 'stopService', 'stop'],
    ['daemon', '/v1', 'restartService', 'restart'],
  ] as const)('under %s, posts to %s/services/{service}/%s', async (layout, base, method, action) => {
    const { client, service } = setup(layout);
    await service[method]('kms');
    expect(client.post).toHaveBeenCalledTimes(1);
    expect(vi.mocked(client.post).mock.calls[0]?.[0]).toBe(`${base}/services/kms/${action}`);
  });

  it('defaults to the webservice layout', async () => {
    const { client, service } = setup();
    await service.listServices();
    await service.getStatus();
    expect(client.get).toHaveBeenCalledWith('/v1/platform/services');
    expect(client.get).toHaveBeenCalledWith('/v1/platform/status');
  });

  it('keeps the other platform routes under /v1/platform with the daemon layout', async () => {
    const { client, service } = setup('daemon');
    await service.getVersion();
    expect(client.get).toHaveBeenCalledWith('/v1/platform/version');
  });
});
