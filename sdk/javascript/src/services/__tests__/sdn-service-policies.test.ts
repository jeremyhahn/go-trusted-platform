/**
 * Unit tests for the SDNService policy methods.
 *
 * The routes are served by pkg/webservice/v1/rest/sdn (registerPolicyRoutes)
 * under `/api/v1/sdn/policies`; the handler decodes protojson bodies, so the
 * request fields are the proto messages' camelCase JSON names.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { SDNService } from '../sdn-service.js';
import type { ApiClient } from '../../client/api-client.js';
import type {
  ApplyPolicyRequest,
  ApplyPolicyResponse,
  GetPolicyResponse,
  ListPoliciesResponse,
} from '../../types/sdn-policies.js';

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

describe('SDNService policies', () => {
  let service: SDNService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new SDNService(mockClient);
  });

  it('applies a policy on POST /v1/sdn/policies', async () => {
    const data: ApplyPolicyResponse = { policy: { id: 'p1' } };
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data });
    const request: ApplyPolicyRequest = {
      policyId: 'p1',
      config: {
        name: 'deny-ssh',
        priority: 10,
        enabled: true,
        rules: [{ ruleId: 'r1', priority: 1, match: { destinationPort: 22, protocol: 'tcp' } }],
      },
    };

    const result = await service.applyPolicy(request);

    expect(mockClient.post).toHaveBeenCalledTimes(1);
    expect(mockClient.post).toHaveBeenCalledWith('/v1/sdn/policies', {
      policyId: 'p1',
      config: {
        name: 'deny-ssh',
        priority: 10,
        enabled: true,
        rules: [{ ruleId: 'r1', priority: 1, match: { destinationPort: 22, protocol: 'tcp' } }],
      },
    });
    expect(result.data?.policy?.id).toBe('p1');
  });

  it('lists policies on GET /v1/sdn/policies', async () => {
    const data: ListPoliciesResponse = { policies: [{ id: 'p1' }] };
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data });

    const result = await service.listPolicies();

    expect(mockClient.get).toHaveBeenCalledTimes(1);
    expect(mockClient.get).toHaveBeenCalledWith('/v1/sdn/policies');
    expect(result.data?.policies[0]?.id).toBe('p1');
  });

  it('narrows the list by type and target_id', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: {} });

    await service.listPolicies({ type: 'acl', targetId: 'br-int' });

    const url = vi.mocked(mockClient.get).mock.calls[0]?.[0] ?? '';
    const [path = '', query = ''] = url.split('?');
    expect(path).toBe('/v1/sdn/policies');
    expect(Object.fromEntries(new URLSearchParams(query))).toEqual({
      type: 'acl',
      target_id: 'br-int',
    });
  });

  it('gets one policy on GET /v1/sdn/policies/{id} with the id path-encoded', async () => {
    const data: GetPolicyResponse = { policy: { id: 'a/b' } };
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data });

    const result = await service.getPolicy('a/b');

    expect(mockClient.get).toHaveBeenCalledWith('/v1/sdn/policies/a%2Fb');
    expect(result.data?.policy?.id).toBe('a/b');
  });
});
