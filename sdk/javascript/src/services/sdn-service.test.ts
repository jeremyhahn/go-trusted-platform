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

// ApplyPolicy (pkg/api/daemon/sdn_service.go) installs flows from the target
// type and bridge ID only, so a target zone or direction does not narrow the
// flows; and it installs every rule before merely recording config.enabled,
// so a disabled policy is active at once. The SDK refuses both unsent.
describe('SDNService.applyPolicy target scope and enabled flag', () => {
  let client: ApiClient;
  let service: SDNService;

  function policy(
    target: Record<string, unknown>,
    extra: Record<string, unknown> = {}
  ): ApplyPolicyRequest {
    return {
      config: {
        name: 'p1',
        targets: [{ type: 'POLICY_TARGET_TYPE_BRIDGE', id: 'br0', ...target }],
        rules: [{ ruleId: 'r1', priority: 100, action: 'POLICY_RULE_ACTION_ALLOW' }],
        ...extra,
      },
    } as unknown as ApplyPolicyRequest;
  }

  beforeEach(() => {
    client = createMockClient();
    vi.mocked(client.post).mockResolvedValue({ success: true, data: {} });
    service = new SDNService(client);
  });

  it.each([
    ['zone', 'dmz'],
    ['direction', 'ingress'],
  ] as const)('refuses a target %s before any request', async (field, value) => {
    const request = policy({ [field]: value });
    await expect(service.applyPolicy(request)).rejects.toThrow(RangeError);
    await expect(service.applyPolicy(request)).rejects.toThrow(`target ${field}`);
    expect(client.post).not.toHaveBeenCalled();
    expect(client.get).not.toHaveBeenCalled();
  });

  it('refuses a disabled policy before any request', async () => {
    const request = policy({}, { enabled: false });
    await expect(service.applyPolicy(request)).rejects.toThrow(RangeError);
    await expect(service.applyPolicy(request)).rejects.toThrow('enabled');
    expect(client.post).not.toHaveBeenCalled();
    expect(client.get).not.toHaveBeenCalled();
  });

  it('still sends an enabled policy with an unscoped bridge target', async () => {
    await service.applyPolicy(policy({ zone: '', direction: '' }, { enabled: true }));
    expect(client.post).toHaveBeenCalledTimes(1);
  });

  it('sends a policy that leaves enabled unset as enabled, since the daemon installs it', async () => {
    await service.applyPolicy(policy({}));
    expect(client.post).toHaveBeenCalledTimes(1);
    const body = vi.mocked(client.post).mock.calls[0]?.[1] as ApplyPolicyRequest;
    expect(body.config.enabled).toBe(true);
    expect(body.config.name).toBe('p1');
  });
});

// policyRuleToFlowMod (pkg/api/daemon/sdn_service.go) never reads the rule's
// log flag, so a rule asking to be logged would be installed and log nothing.
// The SDK refuses log: true unsent.
describe('SDNService.applyPolicy rule logging', () => {
  let client: ApiClient;
  let service: SDNService;

  function policyWithLog(log?: boolean): ApplyPolicyRequest {
    const request = policyWithAction('POLICY_RULE_ACTION_ALLOW');
    if (log !== undefined) {
      Object.assign(request.config.rules?.[0] ?? {}, { log });
    }
    return request;
  }

  beforeEach(() => {
    client = createMockClient();
    vi.mocked(client.post).mockResolvedValue({ success: true, data: {} });
    service = new SDNService(client);
  });

  it('refuses a rule with log: true before any request', async () => {
    const request = policyWithLog(true);
    await expect(service.applyPolicy(request)).rejects.toThrow(RangeError);
    await expect(service.applyPolicy(request)).rejects.toThrow('log');
    expect(client.post).not.toHaveBeenCalled();
    expect(client.get).not.toHaveBeenCalled();
  });

  it('still sends a rule with log: false', async () => {
    await service.applyPolicy(policyWithLog(false));
    expect(client.post).toHaveBeenCalledTimes(1);
  });

  it('still sends a rule that leaves log unset', async () => {
    await service.applyPolicy(policyWithLog());
    expect(client.post).toHaveBeenCalledTimes(1);
  });
});
