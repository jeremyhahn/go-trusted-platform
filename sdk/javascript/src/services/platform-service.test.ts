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

    it('sends includeSensitive=true in the query', async () => {
      await service.getConfig({ includeSensitive: true });
      expectOnlyGet('/v1/platform/config?includeSensitive=true');
    });

    it('sends includeSensitive=false in the query', async () => {
      await service.getConfig({ includeSensitive: false });
      expectOnlyGet('/v1/platform/config?includeSensitive=false');
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
