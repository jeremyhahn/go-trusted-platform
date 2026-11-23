import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';

import ClusterPage from './page';

const { off } = vi.hoisted(() => ({ off: new Set<string>() }));
vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({
    loading: false,
    error: undefined,
    capability: (op: string) => (off.has(op) ? { enabled: false, reason: 'not-configured: cluster' } : { enabled: true }),
  }),
}));

const BOOTSTRAP_OP = 'POST /api/v1/cluster/bootstrap';
const JOIN_OP = 'POST /api/v1/cluster/join';
const LEAVE_OP = 'POST /api/v1/cluster/leave';
const gated = (op: string) => document.querySelector(`[data-capability-op="${op}"]`) as HTMLButtonElement | null;

const STATUS = '/api/v1/cluster/status';
const NODES = '/api/v1/cluster/nodes';
const BOOTSTRAP = '/api/v1/cluster/bootstrap';
const JOIN = '/api/v1/cluster/join';
const LEAVE = '/api/v1/cluster/leave';

const statusOK: Answer = {
  status: 200,
  body: {
    cluster: { id: 'c1', name: 'lab', state: 2, leader_id: 'n1', total_nodes: 2, healthy_nodes: 1, term: 7 },
    local_node: { id: 'n1', name: 'alpha' },
  },
};

const noNodes: Answer = { status: 200, body: { nodes: [], total: 0 } };
const ok: Answer = { status: 200, body: { status: { success: true } } };

function reads(sent: { method: string; path: string }[], method: string, path: string): number {
  return sent.filter((r) => r.method === method && r.path === path).length;
}

function type(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

async function findToast(text: string, variant?: string): Promise<HTMLElement> {
  let found: HTMLElement | undefined;
  await waitFor(() => {
    found = screen
      .getAllByTestId('toast')
      .find((t) => t.textContent?.includes(text) && (!variant || t.getAttribute('data-variant') === variant));
    expect(found).toBeTruthy();
  });
  return found as HTMLElement;
}

// hold wraps the fetch stubControlPlane installed: the one method and path
// waits until release() is called; every other request goes straight through.
function hold(method: string, path: string): () => void {
  const inner = globalThis.fetch;
  let release: () => void = () => {};
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(input instanceof Request ? input.url : String(input));
      const m = (init?.method ?? 'GET').toUpperCase();
      if (m === method && url.pathname === path) await gate;
      return inner(input, init);
    })
  );
  return () => release();
}

function fillAll() {
  type('Cluster name', 'lab');
  type('Node name', 'alpha');
  type('Join node name', 'beta');
  type('Seed addresses', '192.0.2.11:7946');
}

async function ready() {
  render(withControlPlane(<ClusterPage />));
  await screen.findByRole('button', { name: 'Bootstrap' });
  await waitFor(() => expect((screen.getByLabelText('Node ID') as HTMLInputElement).value).toBe('n1'));
  fillAll();
}

describe('ClusterPage overlapping writes', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    off.clear();
  });

  it('disables Join and Leave while a bootstrap is pending', async () => {
    const sent = stubControlPlane({
      [`GET ${STATUS}`]: statusOK,
      [`GET ${NODES}`]: noNodes,
      [`POST ${BOOTSTRAP}`]: ok,
      [`POST ${JOIN}`]: ok,
    });
    const release = hold('POST', BOOTSTRAP);
    await ready();

    fireEvent.click(screen.getByRole('button', { name: 'Bootstrap' }));
    await waitFor(() => expect(gated(BOOTSTRAP_OP)?.disabled).toBe(true));
    expect(gated(JOIN_OP)?.disabled).toBe(true);
    expect(gated(LEAVE_OP)?.disabled).toBe(true);
    fireEvent.click(screen.getByRole('button', { name: 'Join' }));
    expect(reads(sent, 'POST', JOIN)).toBe(0);

    release();
    expect(await findToast('Cluster bootstrapped')).toBeTruthy();
    await waitFor(() => expect(gated(JOIN_OP)?.disabled).toBe(false));
    expect(reads(sent, 'POST', JOIN)).toBe(0);
  });

  it('disables Bootstrap and Join while a join is pending', async () => {
    const sent = stubControlPlane({
      [`GET ${STATUS}`]: statusOK,
      [`GET ${NODES}`]: noNodes,
      [`POST ${BOOTSTRAP}`]: ok,
      [`POST ${JOIN}`]: ok,
    });
    const release = hold('POST', JOIN);
    await ready();

    fireEvent.click(screen.getByRole('button', { name: 'Join' }));
    await waitFor(() => expect(gated(JOIN_OP)?.disabled).toBe(true));
    expect(gated(BOOTSTRAP_OP)?.disabled).toBe(true);
    expect(gated(LEAVE_OP)?.disabled).toBe(true);
    fireEvent.click(screen.getByRole('button', { name: 'Bootstrap' }));
    expect(reads(sent, 'POST', BOOTSTRAP)).toBe(0);

    release();
    expect(await findToast('Node joined: beta')).toBeTruthy();
    await waitFor(() => expect(gated(BOOTSTRAP_OP)?.disabled).toBe(false));
    expect(reads(sent, 'POST', BOOTSTRAP)).toBe(0);
  });

  it('keeps the other writes disabled while a leave is pending', async () => {
    const sent = stubControlPlane({
      [`GET ${STATUS}`]: statusOK,
      [`GET ${NODES}`]: noNodes,
      [`POST ${LEAVE}`]: ok,
    });
    const release = hold('POST', LEAVE);
    await ready();

    fireEvent.click(screen.getByRole('button', { name: 'Leave' }));
    const dialog = await screen.findByRole('dialog');
    const confirm = (await within(dialog).findByRole('button', { name: 'Leave cluster' })) as HTMLButtonElement;
    fireEvent.click(confirm);

    await waitFor(() => expect(confirm.disabled).toBe(true));
    expect(gated(BOOTSTRAP_OP)?.disabled).toBe(true);
    expect(gated(JOIN_OP)?.disabled).toBe(true);
    fireEvent.click(confirm);

    release();
    expect(await findToast('Node left: n1')).toBeTruthy();
    expect(reads(sent, 'POST', LEAVE)).toBe(1);
  });
});
