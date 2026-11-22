/**
 * Wire tests for IAMService.validatePolicy and IAMService.testPolicy.
 *
 * The server decodes ValidatePolicyRequest as {tenant_id, spec_yaml} and
 * TestPolicyRequest as {tenant_id, subject_id, roles, groups, action,
 * resource, context, attributes} (pkg/webservice/v1/rest/iam/types.go). The
 * API client does no case conversion, so the SDK must send snake_case keys.
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
    baseUrl: 'https://api.example.com',
  } as unknown as ApiClient;
}

describe('IAMService policy validate/test wire', () => {
  let mockClient: ApiClient;
  let service: IAMService;

  beforeEach(() => {
    mockClient = createMockApiClient();
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: {} });
    service = new IAMService(mockClient);
  });

  it('validatePolicy posts {tenant_id, spec_yaml}', async () => {
    await service.validatePolicy({ tenantId: 't1', specYaml: 'a: b' });
    expect(mockClient.post).toHaveBeenCalledTimes(1);
    expect(mockClient.post).toHaveBeenCalledWith('/v1/iam/tenants/t1/policies/validate', {
      tenant_id: 't1',
      spec_yaml: 'a: b',
    });
  });

  it('validatePolicy encodes the tenant in the path', async () => {
    await service.validatePolicy({ tenantId: 't/1', specYaml: 'a: b' });
    expect(mockClient.post).toHaveBeenCalledWith('/v1/iam/tenants/t%2F1/policies/validate', {
      tenant_id: 't/1',
      spec_yaml: 'a: b',
    });
  });

  it('testPolicy posts the snake_case test request', async () => {
    await service.testPolicy({
      tenantId: 't1',
      subjectId: 'u1',
      roles: ['r'],
      groups: ['g'],
      action: 'read',
      resource: '/x',
      context: { k: 'v' },
      attributes: { a: 'b' },
    });
    expect(mockClient.post).toHaveBeenCalledTimes(1);
    expect(mockClient.post).toHaveBeenCalledWith('/v1/iam/tenants/t1/policies/test', {
      tenant_id: 't1',
      subject_id: 'u1',
      roles: ['r'],
      groups: ['g'],
      action: 'read',
      resource: '/x',
      context: { k: 'v' },
      attributes: { a: 'b' },
    });
  });
});
