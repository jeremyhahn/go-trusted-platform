/**
 * Unit tests for the vTPM create request bodies.
 *
 * `pkg/webservice/v1/rest/vtpm/handlers.go` decodes a flat snake_case body
 * with unknown fields refused, and parses the mode and EK algorithm from the
 * strings in pkg/vtpm/types.go. These tests pin that body for every enum value.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { VTPMService, InvalidDeviceProfileIdError } from '../vtpm-service.js';
import type { ApiClient } from '../../client/api-client.js';
import type { BundleMode, EKAlgorithm } from '../../types/vtpm.js';

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

const modes: Array<[BundleMode, Record<string, string>]> = [
  ['UNSPECIFIED', {}],
  ['TEMPLATE', { mode: 'template' }],
  ['PRE_ASSIGNED', { mode: 'pre-assigned' }],
];

const ekAlgorithms: Array<[EKAlgorithm, Record<string, string>]> = [
  ['UNSPECIFIED', {}],
  ['RSA', { ek_algorithm: 'RSA' }],
  ['ECC', { ek_algorithm: 'ECC' }],
];

describe('VTPMService create request bodies', () => {
  let service: VTPMService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new VTPMService(mockClient);
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: {} });
  });

  it.each(modes)('createBundle sends mode %s as %o', async (mode, wire) => {
    await service.createBundle({ options: { mode, hostname: 'h1' } });

    expect(mockClient.post).toHaveBeenCalledWith('/v1/vtpm/bundles', JSON.stringify({ ...wire, hostname: 'h1' }));
  });

  it.each(ekAlgorithms)('createBundle sends EK algorithm %s as %o', async (ekAlgorithm, wire) => {
    await service.createBundle({ options: { ekAlgorithm } });

    expect(mockClient.post).toHaveBeenCalledWith('/v1/vtpm/bundles', JSON.stringify(wire));
  });

  it('createBundle sends every option flat and snake_case', async () => {
    await service.createBundle({
      options: {
        mode: 'PRE_ASSIGNED',
        hostname: 'h1',
        ekAlgorithm: 'ECC',
        secureBootEnabled: true,
        labels: { env: 'prod' },
        templateId: 't1',
        deviceProfileId: '9',
      },
    });

    expect(mockClient.post).toHaveBeenCalledWith(
      '/v1/vtpm/bundles',
      '{"mode":"pre-assigned","hostname":"h1","ek_algorithm":"ECC","secure_boot_enabled":true,' +
        '"labels":{"env":"prod"},"template_id":"t1","device_profile_id":9}'
    );
  });

  it.each([
    ['9007199254740993', '{"device_profile_id":9007199254740993}'],
    ['18446744073709551615', '{"device_profile_id":18446744073709551615}'],
    ['007', '{"device_profile_id":7}'],
    ['0', '{"device_profile_id":0}'],
  ])('createBundle sends device profile id %j as the exact digits of a JSON number', async (deviceProfileId, body) => {
    await service.createBundle({ options: { deviceProfileId } });

    expect(mockClient.post).toHaveBeenCalledWith('/v1/vtpm/bundles', body);
  });

  it('createBundle keeps a uint64 device profile id exact beside other options', async () => {
    await service.createBundle({ options: { hostname: 'h1', deviceProfileId: '18446744073709551615' } });

    expect(mockClient.post).toHaveBeenCalledWith(
      '/v1/vtpm/bundles',
      '{"hostname":"h1","device_profile_id":18446744073709551615}'
    );
  });

  it.each(['abc', '-1', '1.5', '', '1e3', '18446744073709551616', '99999999999999999999'])(
    'createBundle refuses device profile id %j without sending',
    async (deviceProfileId) => {
      await expect(service.createBundle({ options: { deviceProfileId } })).rejects.toBeInstanceOf(
        InvalidDeviceProfileIdError
      );
      expect(mockClient.post).not.toHaveBeenCalled();
    }
  );

  it.each(ekAlgorithms)('createTemplate sends EK algorithm %s as %o', async (ekAlgorithm, wire) => {
    await service.createTemplate({ options: { id: 't1', ekAlgorithm } });

    expect(mockClient.post).toHaveBeenCalledWith('/v1/vtpm/templates', { id: 't1', ...wire });
  });

  it('createTemplate sends every option flat and snake_case', async () => {
    await service.createTemplate({
      options: { id: 't1', description: 'base', ekAlgorithm: 'RSA', secureBootEnabled: false },
    });

    expect(mockClient.post).toHaveBeenCalledWith('/v1/vtpm/templates', {
      id: 't1',
      description: 'base',
      ek_algorithm: 'RSA',
      secure_boot_enabled: false,
    });
  });
});
