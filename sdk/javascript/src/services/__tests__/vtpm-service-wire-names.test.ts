/**
 * Unit tests for the vTPM create request bodies.
 *
 * `pkg/webservice/v1/rest/vtpm/handlers.go` decodes a flat snake_case body
 * with unknown fields refused, and parses the mode and EK algorithm from the
 * strings in pkg/vtpm/types.go. These tests pin that body for every enum value,
 * and decode the bundle / template the handler writes back through ApiClient.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { VTPMService, InvalidDeviceProfileIdError } from '../vtpm-service.js';
import { ApiClient } from '../../client/api-client.js';
import type {
  BundleMode,
  CreateBundleResponse,
  CreateTemplateResponse,
  EKAlgorithm,
} from '../../types/vtpm.js';

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

/** An ApiClient whose fetch answers every request with `envelope` as JSON. */
function apiClientAnswering(envelope: unknown): { client: ApiClient; requests: Request[] } {
  const requests: Request[] = [];
  const fetchImpl = ((input: RequestInfo | URL, init?: RequestInit) => {
    requests.push(new Request(input, init));
    return Promise.resolve(
      new Response(JSON.stringify(envelope), { status: 200, headers: { 'content-type': 'application/json' } })
    );
  }) as typeof fetch;
  const client = new ApiClient({ baseUrl: 'https://platform.test', fetch: fetchImpl, retry: { maxRetries: 0 } });
  return { client, requests };
}

describe('VTPMService create responses decoded through ApiClient', () => {
  // The restwire.WebServiceResponse envelope Success200 writes around
  // h.bundleToResponse / h.templateToResponse (pkg/webservice/v1/rest/vtpm).
  const bundlePayload = {
    id: 'test-bundle-123',
    mode: 'pre-assigned',
    manifest: {
      version: '1',
      id: 'test-bundle-123',
      mode: 'pre-assigned',
      hostname: 'h1',
      created_at: '2026-01-01T00:00:00Z',
      ek_algorithm: 'ECC',
      ek_handle: 2164326401,
      secure_boot_enabled: true,
      device_profile_id: 9,
    },
    tpm_state: { state_dir: '/var/lib/vtpm/bundles/test-bundle-123/tpm', permall_file: 'tpm2-00.permall' },
    ovmf_state: { nvram_file: 'OVMF_VARS.fd' },
    created_at: '2026-01-01T00:00:00Z',
  };
  const templatePayload = {
    id: 'test-template',
    description: 'base',
    tpm_state_dir: '/var/lib/vtpm/templates/test-template/tpm',
    nvram_path: '/var/lib/vtpm/templates/test-template/ovmf/OVMF_VARS.fd',
    ek_algorithm: 'RSA',
    secure_boot_enabled: false,
    created_at: '2026-01-01T00:00:00Z',
  };

  it('createBundle returns the created bundle, its generated ID readable as data.id', async () => {
    const { client, requests } = apiClientAnswering({ code: 200, error: '', success: true, payload: bundlePayload });

    const response = await new VTPMService(client).createBundle({ options: { hostname: 'h1', deviceProfileId: '9' } });

    expect(requests.map((r) => `${r.method} ${r.url}`)).toEqual(['POST https://platform.test/v1/vtpm/bundles']);
    expect(response.error).toBeUndefined();
    const bundle: CreateBundleResponse | undefined = response.data;
    expect(bundle?.id).toBe('test-bundle-123');
    expect(bundle?.manifest?.ek_algorithm).toBe('ECC');
    expect(bundle?.tpm_state?.state_dir).toBe('/var/lib/vtpm/bundles/test-bundle-123/tpm');
    expect(bundle).toEqual(bundlePayload);
  });

  it('createTemplate returns the created template, its ID readable as data.id', async () => {
    const { client, requests } = apiClientAnswering({ code: 200, error: '', success: true, payload: templatePayload });

    const response = await new VTPMService(client).createTemplate({ options: { id: 'test-template' } });

    expect(requests.map((r) => `${r.method} ${r.url}`)).toEqual(['POST https://platform.test/v1/vtpm/templates']);
    expect(response.error).toBeUndefined();
    const template: CreateTemplateResponse | undefined = response.data;
    expect(template?.id).toBe('test-template');
    expect(template?.nvram_path).toBe('/var/lib/vtpm/templates/test-template/ovmf/OVMF_VARS.fd');
    expect(template).toEqual(templatePayload);
  });

  it('createBundle reports a daemon refusal as the error, with no bundle', async () => {
    const fetchImpl = (() =>
      Promise.resolve(
        new Response(JSON.stringify({ code: 400, error: 'hostname is required', success: false, payload: null }), {
          status: 400,
          headers: { 'content-type': 'application/json' },
        })
      )) as typeof fetch;
    const client = new ApiClient({ baseUrl: 'https://platform.test', fetch: fetchImpl, retry: { maxRetries: 0 } });

    const response = await new VTPMService(client).createBundle({ options: {} });

    expect(response.data).toBeUndefined();
    expect(response.error?.status).toBe(400);
    expect(response.error?.message).toBe('hostname is required');
  });
});
