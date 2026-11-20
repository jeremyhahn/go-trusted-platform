import { describe, it, expect, vi, beforeEach } from 'vitest';
import { SDNService } from './sdn-service.js';
import type { ApiClient } from '../client/api-client.js';
import type { ApplyPolicyRequest, SDNPolicyRuleAction } from '../types/sdn.js';

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

function policyWithAction(action: SDNPolicyRuleAction): ApplyPolicyRequest {
  return {
    config: {
      name: 'p1',
      targets: [{ type: 'POLICY_TARGET_TYPE_BRIDGE', id: 'br0' }],
      rules: [{ ruleId: 'r1', priority: 100, action }],
    },
  } as unknown as ApplyPolicyRequest;
}

// The daemon turns RATE_LIMIT and MIRROR rules into a plain `normal` forward
// (pkg/api/daemon/sdn_service.go), so a policy carrying one would be reported
// active while limiting or mirroring nothing: the SDK refuses it unsent.
describe('SDNService.applyPolicy rule actions', () => {
  let client: ApiClient;
  let service: SDNService;

  beforeEach(() => {
    client = createMockClient();
    vi.mocked(client.post).mockResolvedValue({ success: true, data: {} });
    service = new SDNService(client);
  });

  it.each(['POLICY_RULE_ACTION_RATE_LIMIT', 'POLICY_RULE_ACTION_MIRROR'] as const)(
    'refuses a %s rule before any request',
    async (action) => {
      await expect(service.applyPolicy(policyWithAction(action))).rejects.toThrow(RangeError);
      await expect(service.applyPolicy(policyWithAction(action))).rejects.toThrow(action);
      expect(client.post).not.toHaveBeenCalled();
      expect(client.get).not.toHaveBeenCalled();
    }
  );

  it('still sends a DENY (drop) rule', async () => {
    await service.applyPolicy(policyWithAction('POLICY_RULE_ACTION_DENY'));
    expect(client.post).toHaveBeenCalledTimes(1);
  });
});
