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

// policyRuleMatch (pkg/api/daemon/sdn_service.go) builds the flow from the
// protocol, addresses, ports and VLAN only: an interface, direction, dscp or
// application constraint is dropped, so an ALLOW scoped to one interface
// would open the whole bridge. The SDK refuses such a match unsent.
describe('SDNService.applyPolicy match fields', () => {
  let client: ApiClient;
  let service: SDNService;

  function policyWithMatch(match: Record<string, unknown>): ApplyPolicyRequest {
    return {
      config: {
        name: 'p1',
        targets: [{ type: 'POLICY_TARGET_TYPE_BRIDGE', id: 'br0' }],
        rules: [{ ruleId: 'r1', priority: 100, action: 'POLICY_RULE_ACTION_ALLOW', match }],
      },
    } as unknown as ApplyPolicyRequest;
  }

  beforeEach(() => {
    client = createMockClient();
    vi.mocked(client.post).mockResolvedValue({ success: true, data: {} });
    service = new SDNService(client);
  });

  it.each([
    ['interface', 'eth0'],
    ['direction', 'ingress'],
    ['dscp', 46],
    ['application', 'ssh'],
  ] as const)('refuses a %s match before any request', async (field, value) => {
    const request = policyWithMatch({ protocol: 'tcp', destinationPort: 22, [field]: value });
    await expect(service.applyPolicy(request)).rejects.toThrow(RangeError);
    await expect(service.applyPolicy(request)).rejects.toThrow(field);
    expect(client.post).not.toHaveBeenCalled();
  });

  it('still sends a match on protocol, addresses, ports and VLAN', async () => {
    await service.applyPolicy(
      policyWithMatch({
        protocol: 'tcp',
        sourceIp: '10.0.0.1',
        destinationIp: '10.0.0.2',
        sourcePort: 1024,
        destinationPort: 22,
        vlanId: 10,
        interface: '',
        dscp: 0,
      })
    );
    expect(client.post).toHaveBeenCalledTimes(1);
  });
});
