import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';

import ClusterPage from './page';

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

describe('ClusterPage writes', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('bootstraps a cluster', async () => {
    const sent = stubControlPlane({
      [`GET ${STATUS}`]: statusOK,
      [`GET ${NODES}`]: noNodes,
      [`POST ${BOOTSTRAP}`]: {
        status: 200,
        body: {
          status: { success: true, message: 'bootstrapped lab' },
          cluster: { id: 'c1', name: 'lab', state: 1 },
          node: { id: 'n1' },
        },
      },
    });
    render(withControlPlane(<ClusterPage />));

    const button = await screen.findByRole('button', { name: 'Bootstrap' });
    type('Cluster name', 'lab');
    type('Node name', 'alpha');
    expect(screen.queryByLabelText('Bind address')).toBeNull();
    expect(screen.queryByLabelText('Bind port')).toBeNull();
    fireEvent.click(button);

    expect(await findToast('Cluster bootstrapped: bootstrapped lab')).toBeTruthy();
    const post = sent.find((r) => r.method === 'POST' && r.path === BOOTSTRAP);
    expect(post?.body).toEqual({ cluster_name: 'lab', node_name: 'alpha' });
    await waitFor(() => expect(reads(sent, 'GET', STATUS)).toBe(2));
  });

  it('joins with its seeds', async () => {
    const sent = stubControlPlane({
      [`GET ${STATUS}`]: statusOK,
      [`GET ${NODES}`]: noNodes,
      [`POST ${JOIN}`]: { status: 200, body: { status: { success: true }, node: { id: 'n2' } } },
    });
    render(withControlPlane(<ClusterPage />));

    const button = await screen.findByRole('button', { name: 'Join' });
    type('Join node name', 'beta');
    type('Seed addresses', '192.0.2.11:7946,\n192.0.2.12:7946');
    expect(screen.queryByLabelText('Join bind address')).toBeNull();
    expect(screen.queryByLabelText('Join bind port')).toBeNull();
    fireEvent.click(button);

    expect(await findToast('Node joined: beta')).toBeTruthy();
    const post = sent.find((r) => r.method === 'POST' && r.path === JOIN);
    expect(post?.body).toEqual({ node_name: 'beta', seed_addresses: ['192.0.2.11:7946', '192.0.2.12:7946'] });
  });

  it('leaves only after the confirm', async () => {
    const sent = stubControlPlane({
      [`GET ${STATUS}`]: statusOK,
      [`GET ${NODES}`]: noNodes,
      [`POST ${LEAVE}`]: { status: 200, body: { status: { success: true } } },
    });
    render(withControlPlane(<ClusterPage />));

    await waitFor(() => expect((screen.getByLabelText('Node ID') as HTMLInputElement).value).toBe('n1'));
    expect(screen.queryByLabelText('Force')).toBeNull();

    fireEvent.click(await screen.findByRole('button', { name: 'Leave' }));
    fireEvent.click(await within(await screen.findByRole('dialog')).findByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(reads(sent, 'POST', LEAVE)).toBe(0);

    fireEvent.click(await screen.findByRole('button', { name: 'Leave' }));
    fireEvent.click(await within(await screen.findByRole('dialog')).findByRole('button', { name: 'Leave cluster' }));

    expect(await findToast('Node left: n1')).toBeTruthy();
    expect(reads(sent, 'POST', LEAVE)).toBe(1);
    expect(sent.find((r) => r.method === 'POST' && r.path === LEAVE)?.body).toEqual({ node_id: 'n1' });
  });

  it('keeps the leave dialog open on a refusal', async () => {
    stubControlPlane({
      [`GET ${STATUS}`]: statusOK,
      [`GET ${NODES}`]: noNodes,
      [`POST ${LEAVE}`]: { status: 409, body: { error: 'node n1 is the leader' } },
    });
    render(withControlPlane(<ClusterPage />));

    await waitFor(() => expect((screen.getByLabelText('Node ID') as HTMLInputElement).value).toBe('n1'));
    fireEvent.click(screen.getByRole('button', { name: 'Leave' }));
    fireEvent.click(await within(await screen.findByRole('dialog')).findByRole('button', { name: 'Leave cluster' }));

    expect(await findToast('node n1 is the leader', 'destructive')).toBeTruthy();
    expect(within(screen.getByRole('dialog')).getByRole('heading', { name: 'Leave cluster' })).toBeTruthy();
  });

  it('toasts a refused bootstrap and an unsuccessful status', async () => {
    const routes: Record<string, Answer> = {
      [`GET ${STATUS}`]: statusOK,
      [`GET ${NODES}`]: noNodes,
      [`POST ${BOOTSTRAP}`]: { status: 409, body: { error: 'cluster already bootstrapped' } },
    };
    stubControlPlane(routes);
    render(withControlPlane(<ClusterPage />));

    const button = await screen.findByRole('button', { name: 'Bootstrap' });
    type('Cluster name', 'lab');
    type('Node name', 'alpha');
    fireEvent.click(button);
    expect(await findToast('cluster already bootstrapped', 'destructive')).toBeTruthy();

    routes[`POST ${BOOTSTRAP}`] = { status: 200, body: { status: { success: false, message: 'bind address in use' } } };
    await waitFor(() => expect((screen.getByRole('button', { name: 'Bootstrap' }) as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(screen.getByRole('button', { name: 'Bootstrap' }));
    expect(await findToast('bind address in use', 'destructive')).toBeTruthy();
  });

  it('parses seeds', async () => {
    // Loaded here, not at the top, so the page tests above run (and fail) before the card exists.
    const card = './cluster-membership-card';
    const { parseSeedAddresses }: typeof import('./cluster-membership-card') = await import(
      /* @vite-ignore */ card
    );
    expect(parseSeedAddresses(' 192.0.2.11:7946, \n\n192.0.2.12:7946 ')).toEqual(['192.0.2.11:7946', '192.0.2.12:7946']);
  });
});
