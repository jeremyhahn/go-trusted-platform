/**
 * Unit tests for VTPMService (#1786).
 *
 * Every public method is driven against a mocked ApiClient; each test pins
 * the HTTP verb, the path (with encoded segments), the query string and the
 * body the service hands to the transport, and each method passes a
 * transport failure through unchanged.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { VTPMService } from '../vtpm-service.js';
import type { ApiClient } from '../../client/api-client.js';
import type {
  CloneTemplateRequest,
  CreateBundleRequest,
  CreateTemplateRequest,
} from '../../types/vtpm.js';

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
    baseUrl: 'https://api.example.com',
  } as unknown as ApiClient;
}

const ok = { success: true, data: {} };

describe('VTPMService', () => {
  let mockClient: ApiClient;
  let service: VTPMService;

  beforeEach(() => {
    mockClient = createMockClient();
    service = new VTPMService(mockClient);
  });

  describe('createBundle', () => {
    it('posts the request to /v1/vtpm/bundles', async () => {
      vi.mocked(mockClient.post).mockResolvedValue(ok);
      const request: CreateBundleRequest = {
        options: {
          mode: 'PRE_ASSIGNED',
          hostname: 'vm-1',
          ekAlgorithm: 'ECC',
          secureBootEnabled: true,
          labels: { env: 'prod' },
          deviceProfileId: '42',
        },
      };

      const result = await service.createBundle(request);

      expect(result).toBe(ok);
      expect(mockClient.post).toHaveBeenCalledTimes(1);
      expect(mockClient.post).toHaveBeenCalledWith('/v1/vtpm/bundles', request);
    });
  });

  describe('getBundle', () => {
    it('gets /v1/vtpm/bundles/{id} with the id encoded', async () => {
      vi.mocked(mockClient.get).mockResolvedValue(ok);

      await service.getBundle('vm/1 a');

      expect(mockClient.get).toHaveBeenCalledWith('/v1/vtpm/bundles/vm%2F1%20a');
    });
  });

  describe('deleteBundle', () => {
    it('deletes /v1/vtpm/bundles/{id}', async () => {
      vi.mocked(mockClient.delete).mockResolvedValue(ok);

      await service.deleteBundle('b-1');

      expect(mockClient.delete).toHaveBeenCalledWith('/v1/vtpm/bundles/b-1');
      expect(mockClient.get).not.toHaveBeenCalled();
    });
  });

  describe('listBundles', () => {
    it('gets /v1/vtpm/bundles without a query when no request is given', async () => {
      vi.mocked(mockClient.get).mockResolvedValue(ok);

      await service.listBundles();

      expect(mockClient.get).toHaveBeenCalledWith('/v1/vtpm/bundles');
    });

    it('gets /v1/vtpm/bundles without a query when the options are empty', async () => {
      vi.mocked(mockClient.get).mockResolvedValue(ok);

      await service.listBundles({ options: {} });

      expect(mockClient.get).toHaveBeenCalledWith('/v1/vtpm/bundles');
    });

    it('maps offset and limit to page and limit, and mode, labels and deviceProfileId to filters', async () => {
      vi.mocked(mockClient.get).mockResolvedValue(ok);

      await service.listBundles({
        options: {
          mode: 'TEMPLATE',
          labels: { env: 'prod', tier: 'a b' },
          limit: 10,
          offset: 20,
          deviceProfileId: '42',
        },
      });

      expect(mockClient.get).toHaveBeenCalledWith(
        '/v1/vtpm/bundles?page=3&limit=10&mode=TEMPLATE&label_env=prod&label_tier=a+b&device_profile_id=42'
      );
    });

    it('pages by a default limit of 10 when only an offset is given', async () => {
      vi.mocked(mockClient.get).mockResolvedValue(ok);

      await service.listBundles({ options: { offset: 25 } });

      expect(mockClient.get).toHaveBeenCalledWith('/v1/vtpm/bundles?page=3');
    });

    it('sends only the limit when no offset is given', async () => {
      vi.mocked(mockClient.get).mockResolvedValue(ok);

      await service.listBundles({ options: { limit: 5 } });

      expect(mockClient.get).toHaveBeenCalledWith('/v1/vtpm/bundles?limit=5');
    });
  });

  describe('validateBundle', () => {
    it('posts an empty body to /v1/vtpm/bundles/{id}/validate', async () => {
      vi.mocked(mockClient.post).mockResolvedValue(ok);

      await service.validateBundle('b/1');

      expect(mockClient.post).toHaveBeenCalledWith('/v1/vtpm/bundles/b%2F1/validate', {});
    });
  });

  describe('getBundlePath', () => {
    it('gets /v1/vtpm/bundles/{id}/path', async () => {
      vi.mocked(mockClient.get).mockResolvedValue(ok);

      await service.getBundlePath('b-1');

      expect(mockClient.get).toHaveBeenCalledWith('/v1/vtpm/bundles/b-1/path');
    });
  });

  describe('getTPMSocketPath', () => {
    it('gets /v1/vtpm/bundles/{id}/tpm-socket', async () => {
      vi.mocked(mockClient.get).mockResolvedValue(ok);

      await service.getTPMSocketPath('b-1');

      expect(mockClient.get).toHaveBeenCalledWith('/v1/vtpm/bundles/b-1/tpm-socket');
    });
  });

  describe('getNVRAMPath', () => {
    it('gets /v1/vtpm/bundles/{id}/nvram', async () => {
      vi.mocked(mockClient.get).mockResolvedValue(ok);

      await service.getNVRAMPath('b-1');

      expect(mockClient.get).toHaveBeenCalledWith('/v1/vtpm/bundles/b-1/nvram');
    });
  });

  describe('createTemplate', () => {
    it('posts the request to /v1/vtpm/templates', async () => {
      vi.mocked(mockClient.post).mockResolvedValue(ok);
      const request: CreateTemplateRequest = {
        options: { id: 't-1', description: 'base', ekAlgorithm: 'RSA', secureBootEnabled: false },
      };

      await service.createTemplate(request);

      expect(mockClient.post).toHaveBeenCalledWith('/v1/vtpm/templates', request);
    });
  });

  describe('getTemplate', () => {
    it('gets /v1/vtpm/templates/{id} with the id encoded', async () => {
      vi.mocked(mockClient.get).mockResolvedValue(ok);

      await service.getTemplate('t/1');

      expect(mockClient.get).toHaveBeenCalledWith('/v1/vtpm/templates/t%2F1');
    });
  });

  describe('deleteTemplate', () => {
    it('deletes /v1/vtpm/templates/{id}', async () => {
      vi.mocked(mockClient.delete).mockResolvedValue(ok);

      await service.deleteTemplate('t-1');

      expect(mockClient.delete).toHaveBeenCalledWith('/v1/vtpm/templates/t-1');
    });
  });

  describe('listTemplates', () => {
    it('gets /v1/vtpm/templates without a query', async () => {
      vi.mocked(mockClient.get).mockResolvedValue(ok);

      await service.listTemplates();

      expect(mockClient.get).toHaveBeenCalledWith('/v1/vtpm/templates');
    });
  });

  describe('cloneTemplate', () => {
    it('posts hostname and labels to /v1/vtpm/templates/{templateId}/clone', async () => {
      vi.mocked(mockClient.post).mockResolvedValue(ok);
      const request: CloneTemplateRequest = {
        options: { templateId: 't/1', hostname: 'vm-2', labels: { env: 'dev' } },
      };

      await service.cloneTemplate(request);

      expect(mockClient.post).toHaveBeenCalledWith('/v1/vtpm/templates/t%2F1/clone', {
        hostname: 'vm-2',
        labels: { env: 'dev' },
      });
    });

    it('does not send the templateId in the body', async () => {
      vi.mocked(mockClient.post).mockResolvedValue(ok);

      await service.cloneTemplate({ options: { templateId: 't-1', hostname: 'vm-3' } });

      const body = vi.mocked(mockClient.post).mock.calls[0]?.[1] as Record<string, unknown>;
      expect(body).toEqual({ hostname: 'vm-3', labels: undefined });
      expect(body).not.toHaveProperty('templateId');
    });
  });

  describe('transport errors', () => {
    type Verb = 'get' | 'post' | 'delete';
    const cases: Array<[string, Verb, (s: VTPMService) => Promise<unknown>]> = [
      ['createBundle', 'post', (s) => s.createBundle({ options: { hostname: 'vm-1' } })],
      ['getBundle', 'get', (s) => s.getBundle('b-1')],
      ['deleteBundle', 'delete', (s) => s.deleteBundle('b-1')],
      ['listBundles', 'get', (s) => s.listBundles()],
      ['validateBundle', 'post', (s) => s.validateBundle('b-1')],
      ['getBundlePath', 'get', (s) => s.getBundlePath('b-1')],
      ['getTPMSocketPath', 'get', (s) => s.getTPMSocketPath('b-1')],
      ['getNVRAMPath', 'get', (s) => s.getNVRAMPath('b-1')],
      ['createTemplate', 'post', (s) => s.createTemplate({ options: { id: 't-1' } })],
      ['getTemplate', 'get', (s) => s.getTemplate('t-1')],
      ['deleteTemplate', 'delete', (s) => s.deleteTemplate('t-1')],
      ['listTemplates', 'get', (s) => s.listTemplates()],
      ['cloneTemplate', 'post', (s) => s.cloneTemplate({ options: { templateId: 't-1', hostname: 'vm-1' } })],
    ];

    it.each(cases)('%s passes a %s failure through', async (_name, verb, call) => {
      const failure = new Error('transport down');
      vi.mocked(mockClient[verb]).mockRejectedValue(failure);

      await expect(call(service)).rejects.toBe(failure);
      expect(mockClient[verb]).toHaveBeenCalledTimes(1);
    });
  });
});
