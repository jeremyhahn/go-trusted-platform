import type { ReactNode } from 'react';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { type Answer, ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import SDNBridgeDetailClient from './sdn-bridge-detail-client';

// #1755 Codex round 2: a refused SDK call (ApiResponse.success false) is a
// failure, never a success toast, and the port certificate travels as the
// base64 of the PEM bytes (AuthenticatePortRequest.certificate is bytes).

const push = vi.fn();

vi.mock('next/navigation', () => ({
  useParams: () => ({ bridge: 'br-1' }),
  usePathname: () => '/networking/sdn/br-1',
  useRouter: () => ({ push, back: vi.fn(), replace: vi.fn() }),
}));

vi.mock('@/components/ui/dialog', () => ({
  Dialog: ({ open, children }: { open: boolean; children: ReactNode }) =>
    open ? <div role="dialog">{children}</div> : null,
  DialogContent: ({ children }: { children: ReactNode }) => <>{children}</>,
  DialogHeader: ({ children }: { children: ReactNode }) => <>{children}</>,
  DialogFooter: ({ children }: { children: ReactNode }) => <>{children}</>,
  DialogTitle: ({ children }: { children: ReactNode }) => <>{children}</>,
  DialogDescription: ({ children }: { children: ReactNode }) => <>{children}</>,
}));

const SDN = '/api/v1/sdn';
const AUTH_PATH = `${SDN}/bridges/br-1/ports/p-1/auth`;
const PEM = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----';

async function renderPage(extra: Record<string, Answer>) {
  const sent = stubControlPlane({
    [`GET ${SDN}/bridges/br-1`]: ok({
      bridge: { id: 'br-1', config: { name: 'br-int' }, status: 'BRIDGE_STATUS_UP' },
    }),
    [`GET ${SDN}/bridges/br-1/ports`]: ok({
      ports: [
        {
          id: 'p-1',
          bridgeId: 'br-1',
          config: { name: 'eth1' },
          status: 'PORT_STATUS_UP',
          auth: { authenticated: false },
        },
      ],
    }),
    [`GET ${SDN}/policies`]: ok({ policies: [] }),
    [`GET ${SDN}/bridges/br-1/ports/p-1/state`]: ok({}),
    [`GET ${SDN}/bridges/br-1/ports/p-1/stats`]: ok({}),
    ...extra,
  });
  render(withControlPlane(<SDNBridgeDetailClient />));
  await screen.findByRole('heading', { level: 1, name: 'br-int' });
  return sent;
}

async function authenticate(pem: string) {
  fireEvent.click(await screen.findByRole('button', { name: 'Manage port eth1' }));
  fireEvent.change(await screen.findByLabelText('Certificate (PEM)'), { target: { value: pem } });
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Authenticate Port' }));
  });
}

function toasts() {
  return screen.queryAllByTestId('toast');
}

describe('SDNBridgeDetailClient refused calls and certificate encoding', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    push.mockReset();
  });

  it('a refused bridge delete shows the failure and stays on the page', async () => {
    await renderPage({ [`DELETE ${SDN}/bridges/br-1`]: refused(500, 'bridge busy') });

    fireEvent.click(screen.getByRole('button', { name: 'Delete Bridge' }));
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Confirm Delete' }));
    });

    await waitFor(() => {
      // The toast store is module-wide: pick this action's toast by its title.
      const failed = toasts().find((t) => t.textContent?.startsWith('Bridge deleted failed'));
      expect(failed?.getAttribute('data-variant')).toBe('destructive');
      expect(failed?.textContent).toContain('bridge busy');
    });
    expect(toasts().some((t) => t.getAttribute('data-variant') === 'success')).toBe(false);
    expect(push).not.toHaveBeenCalled();
  });

  it('a refused port authentication is not reported as success', async () => {
    await renderPage({ [`POST ${AUTH_PATH}`]: refused(412, 'port authentication is not enforced') });

    await authenticate(PEM);

    await waitFor(() => {
      // The toast store is module-wide: pick this action's toast by its title.
      const failed = toasts().find((t) => t.textContent?.startsWith('Port authenticated failed'));
      expect(failed?.getAttribute('data-variant')).toBe('destructive');
      expect(failed?.textContent).toContain('port authentication is not enforced');
    });
    expect(toasts().some((t) => t.textContent?.startsWith('Port authenticated:'))).toBe(false);
  });

  it('the certificate is sent as base64 of the PEM bytes', async () => {
    const sent = await renderPage({ [`POST ${AUTH_PATH}`]: ok({}) });

    await authenticate(PEM);

    await waitFor(() => expect(sent.some((r) => r.method === 'POST' && r.path === AUTH_PATH)).toBe(true));
    const body = sent.find((r) => r.method === 'POST' && r.path === AUTH_PATH)?.body as {
      certificate: string;
      format: string;
    };
    expect(atob(body.certificate)).toBe(PEM);
    expect(body.format).toBe('PEM');
  });
});

// #1755 Codex round 3: a refused read is a failure, not an absent resource,
// and the port panel only shows the answer for the port that is selected.
describe('SDNBridgeDetailClient read failures and port identity', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    push.mockReset();
  });

  it('a refused bridge read is a failure, not a missing bridge', async () => {
    stubControlPlane({
      [`GET ${SDN}/bridges/br-1`]: refused(403, 'forbidden'),
      [`GET ${SDN}/bridges/br-1/ports`]: ok({ ports: [] }),
      [`GET ${SDN}/policies`]: ok({ policies: [] }),
    });
    render(withControlPlane(<SDNBridgeDetailClient />));

    expect((await screen.findByTestId('sdn-bridge-error')).textContent).toContain('forbidden');
    expect(screen.queryByText('Bridge not found')).toBeNull();
    expect(screen.getByRole('button', { name: 'Retry bridge' })).toBeTruthy();
  });

  it('refused port and policy lists are failures, not empty lists', async () => {
    await renderPage({
      [`GET ${SDN}/bridges/br-1/ports`]: refused(503, 'service unavailable'),
      [`GET ${SDN}/policies`]: refused(503, 'service unavailable'),
    });

    // The SDK retries a 503 with backoff (3 retries from 1 s): the failure shows once they are spent.
    const wait = { timeout: 15000 };
    expect((await screen.findByTestId('sdn-ports-error', {}, wait)).textContent).toContain('service unavailable');
    expect((await screen.findByTestId('sdn-policies-error', {}, wait)).textContent).toContain('service unavailable');
    expect(screen.queryByText('No ports found')).toBeNull();
    expect(screen.queryByText('No policies found')).toBeNull();
    expect(screen.getByRole('button', { name: 'Retry ports' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Retry policies' })).toBeTruthy();
  }, 20000);

  it("switching ports never shows the previous port's state", async () => {
    const port = (id: string, name: string) => ({
      id,
      bridgeId: 'br-1',
      config: { name },
      status: 'PORT_STATUS_UP',
      auth: { authenticated: false },
    });
    stubControlPlane({
      [`GET ${SDN}/bridges/br-1`]: ok({
        bridge: { id: 'br-1', config: { name: 'br-int' }, status: 'BRIDGE_STATUS_UP' },
      }),
      [`GET ${SDN}/bridges/br-1/ports`]: ok({ ports: [port('p-1', 'eth1'), port('p-2', 'eth2')] }),
      [`GET ${SDN}/policies`]: ok({ policies: [] }),
      [`GET ${SDN}/bridges/br-1/ports/p-1/state`]: ok({ port: { id: 'p-1', status: 'PORT_STATUS_DOWN' } }),
      [`GET ${SDN}/bridges/br-1/ports/p-1/stats`]: ok({ stats: { packetsReceived: 111 } }),
      [`GET ${SDN}/bridges/br-1/ports/p-2/state`]: ok({ port: { id: 'p-2', status: 'PORT_STATUS_UP' } }),
      [`GET ${SDN}/bridges/br-1/ports/p-2/stats`]: ok({ stats: { packetsReceived: 222 } }),
    });
    const stubbed = globalThis.fetch;
    let release: () => void = () => {};
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = new URL(input instanceof Request ? input.url : String(input)).pathname;
      if (path.endsWith('/ports/p-1/state') || path.endsWith('/ports/p-1/stats')) await held;
      return stubbed(input, init);
    });

    render(withControlPlane(<SDNBridgeDetailClient />));
    await screen.findByRole('heading', { level: 1, name: 'br-int' });

    fireEvent.click(await screen.findByRole('button', { name: 'Manage port eth1' }));
    fireEvent.click(screen.getByRole('button', { name: 'Manage port eth2' }));

    await waitFor(() => expect(screen.getByTestId('port-state').textContent).toContain('PORT_STATUS_UP'));
    await waitFor(() => expect(screen.getByTestId('port-stats').textContent).toContain('222'));

    await act(async () => {
      release();
      await held;
      await new Promise((resolve) => setTimeout(resolve, 20));
    });

    expect(screen.getByTestId('port-state').textContent).toContain('PORT_STATUS_UP');
    expect(screen.queryByText(/PORT_STATUS_DOWN/)).toBeNull();
    expect(screen.getByTestId('port-stats').textContent).not.toContain('111');
  });
});

// #1755 Codex round 4: Apply Policy binds a rule and this bridge as the
// target (ApplyPolicy installs flows per bridge target times rules), and the
// policy dialog only shows the answer for the policy it was opened for.
describe('SDNBridgeDetailClient policy apply and policy identity', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    push.mockReset();
  });

  // #2024 Codex P1: the backend installs "normal" for RATE_LIMIT and MIRROR,
  // so the action select must not offer them.
  it('apply policy offers only the actions the backend enforces', async () => {
    await renderPage({});

    fireEvent.click(screen.getByRole('button', { name: 'Apply Policy' }));
    const select = screen.getByLabelText('Action *') as HTMLSelectElement;
    const values = Array.from(select.options).map((o) => o.value);
    expect(values).not.toContain('POLICY_RULE_ACTION_RATE_LIMIT');
    expect(values).not.toContain('POLICY_RULE_ACTION_MIRROR');
    // #2024 Codex round 2 P1: the form has no redirect destination, and a
    // REDIRECT rule without one installs no actions (a drop).
    expect(values).not.toContain('POLICY_RULE_ACTION_REDIRECT');
    for (const v of [
      'POLICY_RULE_ACTION_ALLOW',
      'POLICY_RULE_ACTION_DENY',
      'POLICY_RULE_ACTION_LOG',
    ]) {
      expect(values).toContain(v);
    }
  });

  it('apply policy submits a rule and a bridge target', async () => {
    const sent = await renderPage({ [`POST ${SDN}/policies`]: ok({ policy: { id: 'pol-9' } }) });

    fireEvent.click(screen.getByRole('button', { name: 'Apply Policy' }));
    fireEvent.change(screen.getByLabelText('Name *'), { target: { value: 'deny-telnet' } });
    expect((screen.getByRole('button', { name: 'Apply' }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(screen.getByLabelText('Action *'), { target: { value: 'POLICY_RULE_ACTION_DENY' } });
    fireEvent.change(screen.getByLabelText('Protocol'), { target: { value: 'tcp' } });
    fireEvent.change(screen.getByLabelText('Destination port'), { target: { value: '23' } });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Apply' }));
    });

    await waitFor(() => expect(sent.some((r) => r.method === 'POST' && r.path === `${SDN}/policies`)).toBe(true));
    const body = sent.find((r) => r.method === 'POST' && r.path === `${SDN}/policies`)?.body as {
      config: {
        name: string;
        rules: { ruleId: string; priority: number; action: string; match: Record<string, unknown> }[];
        targets: { type: string; id: string }[];
      };
    };
    expect(body.config.name).toBe('deny-telnet');
    expect(body.config.rules.length).toBe(1);
    expect(body.config.rules[0].action).toBe('POLICY_RULE_ACTION_DENY');
    expect(body.config.rules[0].priority).toBe(100);
    expect(body.config.rules[0].match).toEqual({ protocol: 'tcp', destinationPort: 23 });
    expect(body.config.targets[0]).toEqual({ type: 'POLICY_TARGET_TYPE_BRIDGE', id: 'br-1' });
  });

  // A destination port matches only under tcp or udp: OpenFlow rejects a port
  // match with any or icmp, so the form refuses it (#2024 Codex round 4, P1).
  async function fillPortRule(protocol: string) {
    const sent = await renderPage({ [`POST ${SDN}/policies`]: ok({ policy: { id: 'pol-9' } }) });
    fireEvent.click(screen.getByRole('button', { name: 'Apply Policy' }));
    fireEvent.change(screen.getByLabelText('Name *'), { target: { value: 'port-rule' } });
    fireEvent.change(screen.getByLabelText('Action *'), { target: { value: 'POLICY_RULE_ACTION_DENY' } });
    fireEvent.change(screen.getByLabelText('Protocol'), { target: { value: protocol } });
    fireEvent.change(screen.getByLabelText('Destination port'), { target: { value: '23' } });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Apply' }));
    });
    return sent;
  }

  for (const protocol of ['any', 'icmp']) {
    it(`a destination port with protocol ${protocol} is refused`, async () => {
      const sent = await fillPortRule(protocol);
      expect(screen.getByTestId('rule-port-error').textContent).toMatch(/rule-1.*tcp or udp/i);
      expect(sent.some((r) => r.method === 'POST' && r.path === `${SDN}/policies`)).toBe(false);
    });
  }

  for (const protocol of ['tcp', 'udp']) {
    it(`a destination port with protocol ${protocol} is submitted`, async () => {
      const sent = await fillPortRule(protocol);
      await waitFor(() => expect(sent.some((r) => r.method === 'POST' && r.path === `${SDN}/policies`)).toBe(true));
      const body = sent.find((r) => r.method === 'POST' && r.path === `${SDN}/policies`)?.body as {
        config: { rules: { match: Record<string, unknown> }[] };
      };
      expect(body.config.rules[0].match).toEqual({ protocol, destinationPort: 23 });
    });
  }

  // Port 0 is sent as destinationPort 0, which the backend reads as "no port
  // match": the rule would cover every tcp port. The form takes 1-65535 only
  // (#2024 Codex round 5, P1).
  async function fillTcpPort(port: string) {
    const sent = await renderPage({ [`POST ${SDN}/policies`]: ok({ policy: { id: 'pol-9' } }) });
    fireEvent.click(screen.getByRole('button', { name: 'Apply Policy' }));
    fireEvent.change(screen.getByLabelText('Name *'), { target: { value: 'port-rule' } });
    fireEvent.change(screen.getByLabelText('Action *'), { target: { value: 'POLICY_RULE_ACTION_ALLOW' } });
    fireEvent.change(screen.getByLabelText('Protocol'), { target: { value: 'tcp' } });
    fireEvent.change(screen.getByLabelText('Destination port'), { target: { value: port } });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Apply' }));
    });
    return sent;
  }

  it('destination port 0 is refused and nothing is sent', async () => {
    const sent = await fillTcpPort('0');
    expect(screen.getByTestId('rule-port-error').textContent).toMatch(/1.*65535/);
    expect((screen.getByRole('button', { name: 'Apply' }) as HTMLButtonElement).disabled).toBe(true);
    expect(sent.some((r) => r.method === 'POST' && r.path === `${SDN}/policies`)).toBe(false);
  });

  for (const port of [1, 65535]) {
    it(`destination port ${port} is submitted`, async () => {
      const sent = await fillTcpPort(String(port));
      await waitFor(() => expect(sent.some((r) => r.method === 'POST' && r.path === `${SDN}/policies`)).toBe(true));
      const body = sent.find((r) => r.method === 'POST' && r.path === `${SDN}/policies`)?.body as {
        config: { rules: { match: Record<string, unknown> }[] };
      };
      expect(body.config.rules[0].match).toEqual({ protocol: 'tcp', destinationPort: port });
    });
  }

  // A policy applied from a bridge that did not load targets nothing the
  // server can resolve, so the page offers no apply (#2024 Codex round 5, P1).
  for (const [what, answer] of [
    ['a refused bridge read', refused(403, 'forbidden')],
    ['a missing bridge', refused(404, 'bridge not found')],
  ] as const) {
    it(`${what} leaves Apply Policy disabled`, async () => {
      stubControlPlane({
        [`GET ${SDN}/bridges/br-1`]: answer,
        [`GET ${SDN}/bridges/br-1/ports`]: ok({ ports: [] }),
        [`GET ${SDN}/policies`]: ok({ policies: [] }),
      });
      render(withControlPlane(<SDNBridgeDetailClient />));
      await waitFor(() => expect(screen.queryByText('Loading bridge')).toBeNull());
      expect((screen.getByRole('button', { name: 'Apply Policy' }) as HTMLButtonElement).disabled).toBe(true);
    });
  }

  // OpenFlow OFPFCAdd replaces a flow with the same match and priority, so a
  // second, differently named policy for the same traffic would silently take
  // over the first one's flow while both stay ACTIVE (#2024 Codex, P1).
  const denyTelnet = {
    id: 'pol-deny',
    config: {
      name: 'deny-telnet',
      enabled: true,
      priority: 100,
      rules: [
        {
          ruleId: 'rule-1',
          priority: 100,
          action: 'POLICY_RULE_ACTION_DENY',
          match: { protocol: 'tcp', destinationPort: 23 },
        },
      ],
      targets: [{ type: 'POLICY_TARGET_TYPE_BRIDGE', id: 'br-1' }],
    },
    status: 'POLICY_STATUS_ACTIVE',
  };

  async function fillSecondPolicy(rule: { priority: string; port: string }, existing: unknown[] = [denyTelnet]) {
    const sent = await renderPage({
      [`GET ${SDN}/policies`]: ok({ policies: existing }),
      [`POST ${SDN}/policies`]: ok({ policy: { id: 'pol-9' } }),
    });
    await screen.findByRole('button', { name: 'View policy deny-telnet' });
    fireEvent.click(screen.getByRole('button', { name: 'Apply Policy' }));
    fireEvent.change(screen.getByLabelText('Name *'), { target: { value: 'allow-telnet' } });
    fireEvent.change(screen.getByLabelText('Action *'), { target: { value: 'POLICY_RULE_ACTION_ALLOW' } });
    fireEvent.change(screen.getByLabelText('Priority'), { target: { value: rule.priority } });
    fireEvent.change(screen.getByLabelText('Protocol'), { target: { value: 'tcp' } });
    fireEvent.change(screen.getByLabelText('Destination port'), { target: { value: rule.port } });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Apply' }));
    });
    return sent;
  }

  it('a policy sharing another policy\'s match and priority is refused and nothing is sent', async () => {
    const sent = await fillSecondPolicy({ priority: '100', port: '23' });
    expect(screen.getByTestId('policy-conflict-error').textContent).toContain('deny-telnet');
    expect((screen.getByRole('button', { name: 'Apply' }) as HTMLButtonElement).disabled).toBe(true);
    expect(sent.some((r) => r.method === 'POST' && r.path === `${SDN}/policies`)).toBe(false);
  });

  for (const [what, rule, existing] of [
    ['a different priority', { priority: '200', port: '23' }, [denyTelnet]],
    ['a different match', { priority: '100', port: '22' }, [denyTelnet]],
    [
      'a policy on another bridge',
      { priority: '100', port: '23' },
      [{ ...denyTelnet, config: { ...denyTelnet.config, targets: [{ type: 'POLICY_TARGET_TYPE_BRIDGE', id: 'br-2' }] } }],
    ],
  ] as const) {
    it(`${what} is not a conflict and is sent`, async () => {
      const sent = await fillSecondPolicy(rule, [...existing]);
      await waitFor(() => expect(sent.some((r) => r.method === 'POST' && r.path === `${SDN}/policies`)).toBe(true));
      expect(screen.queryByTestId('policy-conflict-error')).toBeNull();
    });
  }

  // The daemon installs a rule with priority 0 at its policy's priority
  // (policyRuleToFlowMod) and resolves a bridge target by id or name
  // (findBridgeName), so both still displace the flow (#2024 Codex R13).
  for (const [what, existing] of [
    [
      'a recorded rule priority 0 conflicts at the policy priority',
      { ...denyTelnet, config: { ...denyTelnet.config, priority: 100, rules: [{ ...denyTelnet.config.rules[0], priority: 0 }] } },
    ],
    [
      'a policy that targets this bridge by name is a conflict',
      { ...denyTelnet, config: { ...denyTelnet.config, targets: [{ type: 'POLICY_TARGET_TYPE_BRIDGE', id: 'br-int' }] } },
    ],
  ] as const) {
    it(`${what}`, async () => {
      const sent = await fillSecondPolicy({ priority: '100', port: '23' }, [existing]);
      expect(screen.getByTestId('policy-conflict-error').textContent).toContain('deny-telnet');
      expect((screen.getByRole('button', { name: 'Apply' }) as HTMLButtonElement).disabled).toBe(true);
      expect(sent.some((r) => r.method === 'POST' && r.path === `${SDN}/policies`)).toBe(false);
    });
  }

  it('a recorded rule priority 0 under another policy priority is not a conflict', async () => {
    const existing = {
      ...denyTelnet,
      config: { ...denyTelnet.config, priority: 200, rules: [{ ...denyTelnet.config.rules[0], priority: 0 }] },
    };
    const sent = await fillSecondPolicy({ priority: '100', port: '23' }, [existing]);
    await waitFor(() => expect(sent.some((r) => r.method === 'POST' && r.path === `${SDN}/policies`)).toBe(true));
    expect(screen.queryByTestId('policy-conflict-error')).toBeNull();
  });

  // #2024 Codex round 3 P1: an empty policy list while the read is pending or
  // refused is not "no conflict"; Apply waits for a loaded policy list.
  function holdPolicyList(): () => void {
    const real = globalThis.fetch;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = new URL(input instanceof Request ? input.url : String(input));
        if ((init?.method ?? 'GET').toUpperCase() === 'GET' && url.pathname === `${SDN}/policies`) {
          await gate;
        }
        return real(input, init);
      })
    );
    return release;
  }

  function fillAllowTelnet() {
    fireEvent.click(screen.getByRole('button', { name: 'Apply Policy' }));
    fireEvent.change(screen.getByLabelText('Name *'), { target: { value: 'allow-telnet' } });
    fireEvent.change(screen.getByLabelText('Action *'), { target: { value: 'POLICY_RULE_ACTION_ALLOW' } });
    fireEvent.change(screen.getByLabelText('Protocol'), { target: { value: 'tcp' } });
    fireEvent.change(screen.getByLabelText('Destination port'), { target: { value: '23' } });
  }

  it('a pending policy list read blocks Apply until the list loads', async () => {
    const sent = stubControlPlane({
      [`GET ${SDN}/bridges/br-1`]: ok({
        bridge: { id: 'br-1', config: { name: 'br-int' }, status: 'BRIDGE_STATUS_UP' },
      }),
      [`GET ${SDN}/bridges/br-1/ports`]: ok({ ports: [] }),
      [`GET ${SDN}/policies`]: ok({ policies: [] }),
      [`POST ${SDN}/policies`]: ok({ policy: { id: 'pol-9' } }),
    });
    const release = holdPolicyList();
    render(withControlPlane(<SDNBridgeDetailClient />));
    await screen.findByRole('heading', { level: 1, name: 'br-int' });
    fillAllowTelnet();

    const apply = screen.getByRole('button', { name: 'Apply' }) as HTMLButtonElement;
    expect(apply.disabled).toBe(true);
    expect(screen.getByTestId('policy-list-not-loaded').textContent).toContain('policy list');
    await act(async () => {
      fireEvent.click(apply);
    });
    expect(sent.some((r) => r.method === 'POST' && r.path === `${SDN}/policies`)).toBe(false);

    await act(async () => {
      release();
    });
    await waitFor(() =>
      expect((screen.getByRole('button', { name: 'Apply' }) as HTMLButtonElement).disabled).toBe(false)
    );
    expect(screen.queryByTestId('policy-list-not-loaded')).toBeNull();
  });

  it('a refused policy list read blocks Apply and nothing is sent', async () => {
    const sent = await renderPage({
      [`GET ${SDN}/policies`]: refused(403, 'policy list forbidden'),
      [`POST ${SDN}/policies`]: ok({ policy: { id: 'pol-9' } }),
    });
    await screen.findByTestId('sdn-policies-error');
    fillAllowTelnet();

    const apply = screen.getByRole('button', { name: 'Apply' }) as HTMLButtonElement;
    expect(apply.disabled).toBe(true);
    expect(screen.getByTestId('policy-list-not-loaded').textContent).toContain('policy list');
    await act(async () => {
      fireEvent.click(apply);
    });
    expect(sent.some((r) => r.method === 'POST' && r.path === `${SDN}/policies`)).toBe(false);
  });

  it('switching to icmp clears an entered destination port', async () => {
    await renderPage({});
    fireEvent.click(screen.getByRole('button', { name: 'Apply Policy' }));
    fireEvent.change(screen.getByLabelText('Protocol'), { target: { value: 'tcp' } });
    fireEvent.change(screen.getByLabelText('Destination port'), { target: { value: '23' } });
    fireEvent.change(screen.getByLabelText('Protocol'), { target: { value: 'icmp' } });
    expect((screen.getByLabelText('Destination port') as HTMLInputElement).value).toBe('');
  });

  it('a refused policy read after viewing another policy shows the error, not the old policy', async () => {
    await renderPage({
      [`GET ${SDN}/policies`]: ok({
        policies: [
          { id: 'pol-a', config: { name: 'allow-a' }, status: 'POLICY_STATUS_ACTIVE' },
          { id: 'pol-b', config: { name: 'allow-b' }, status: 'POLICY_STATUS_ACTIVE' },
        ],
      }),
      [`GET ${SDN}/policies/pol-a`]: ok({
        policy: {
          id: 'pol-a',
          config: { name: 'policy-a-detail', rules: [{ ruleId: 'r1' }, { ruleId: 'r2' }] },
          hitCount: '7',
        },
      }),
      [`GET ${SDN}/policies/pol-b`]: refused(403, 'policy read forbidden'),
    });

    fireEvent.click(await screen.findByRole('button', { name: 'View policy allow-a' }));
    await waitFor(() => expect(screen.getByTestId('policy-detail').textContent).toContain('Rules: 2'));

    fireEvent.click(screen.getByRole('button', { name: 'View policy allow-b' }));
    expect((await screen.findByTestId('policy-detail-error')).textContent).toContain('policy read forbidden');
    expect(screen.queryByText(/policy-a-detail/)).toBeNull();
    expect(screen.queryByText('Rules: 2')).toBeNull();
    expect(screen.queryByTestId('policy-detail')).toBeNull();
  });
});
