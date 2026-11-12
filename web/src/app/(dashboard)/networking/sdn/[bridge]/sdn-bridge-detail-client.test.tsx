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
