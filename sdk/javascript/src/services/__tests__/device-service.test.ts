/**
 * Unit tests for DeviceService template routes.
 *
 * Template creation is the one device operation that does not live under
 * the service's plural base path: `POST /v1/devices/templates` is the
 * bootstrap seeder's route (docs/device/api.md §4.1), so createTemplate
 * must post to the singular `/v1/device/templates` while the other template
 * operations keep the plural aliases.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { DeviceService } from '../device-service.js';
import type { ApiClient } from '../../client/api-client.js';
import type { ApiResponse } from '../../types/api.js';
import type { DeviceTemplate, CreateDeviceTemplateRequest } from '../../types/device.js';

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

describe('DeviceService templates', () => {
  let service: DeviceService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new DeviceService(mockClient);
  });

  describe('createTemplate', () => {
    const request: CreateDeviceTemplateRequest = {
      name: 'gw-default',
      description: 'gateway default',
      role: 'GATEWAY',
      config: { domain: 'example.com' },
    };

    it('posts the unchanged request to the singular CRUD path, not the seeder route', async () => {
      const mockResponse: ApiResponse<DeviceTemplate> = {
        success: true,
        data: { id: '42', name: 'gw-default', role: 'GATEWAY' } as unknown as DeviceTemplate,
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.createTemplate(request);

      expect(result.success).toBe(true);
      expect(result.data?.name).toBe('gw-default');
      expect(mockClient.post).toHaveBeenCalledTimes(1);
      expect(mockClient.post).toHaveBeenCalledWith('/v1/device/templates', request);
      const [path] = vi.mocked(mockClient.post).mock.calls[0];
      expect(path).not.toBe('/v1/devices/templates');
    });

    it('propagates a transport error unchanged', async () => {
      const failure = new Error('400 Bad Request: device: unknown role "compute"');
      vi.mocked(mockClient.post).mockRejectedValue(failure);

      await expect(service.createTemplate(request)).rejects.toBe(failure);
      expect(mockClient.post).toHaveBeenCalledWith('/v1/device/templates', request);
    });
  });

  describe('plural aliases that are still CRUD routes', () => {
    it('lists templates from the plural path', async () => {
      vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: [] });

      await service.listTemplates();

      expect(mockClient.get).toHaveBeenCalledWith('/v1/devices/templates');
    });

    it('gets a template by id from the plural path', async () => {
      vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: {} });

      await service.getTemplate(42);

      expect(mockClient.get).toHaveBeenCalledWith('/v1/devices/templates/42');
    });
  });
});
