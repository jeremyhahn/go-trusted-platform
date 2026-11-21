/**
 * IAMService createPolicy and updatePolicy send the snake_case policy body
 * the REST handlers decode (#2054).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { IAMService } from '../iam-service.js';
import type { ApiClient } from '../../client/api-client.js';

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
  } as unknown as ApiClient;
}

describe('IAMService policy write wire', () => {
  let mockClient: ApiClient;
  let service: IAMService;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new IAMService(mockClient);
  });

  it('createPolicy posts the snake_case body with spec_yaml', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: {} });

    await service.createPolicy({
      tenantId: 't1',
      name: 'p1',
      description: 'd',
      priority: 5,
      specYaml: 'rules: []',
      labels: { a: 'b' },
    });

    expect(mockClient.post).toHaveBeenCalledTimes(1);
    const [url, body] = vi.mocked(mockClient.post).mock.calls[0] ?? [];
    expect(url).toBe('/v1/iam/tenants/t1/policies');
    expect(body).toEqual({
      tenant_id: 't1',
      name: 'p1',
      description: 'd',
      priority: 5,
      spec_yaml: 'rules: []',
      labels: { a: 'b' },
    });
  });

  it('updatePolicy puts the snake_case body with spec_yaml and no camelCase keys', async () => {
    vi.mocked(mockClient.put).mockResolvedValue({ success: true, data: {} });

    await service.updatePolicy({
      tenantId: 't1',
      policyName: 'p1',
      specYaml: 'rules: []',
      priority: 2,
    });

    expect(mockClient.put).toHaveBeenCalledTimes(1);
    const [url, body] = vi.mocked(mockClient.put).mock.calls[0] ?? [];
    expect(url).toBe('/v1/iam/tenants/t1/policies/p1');
    expect(JSON.parse(JSON.stringify(body))).toEqual({
      tenant_id: 't1',
      spec_yaml: 'rules: []',
      priority: 2,
    });
  });
});
