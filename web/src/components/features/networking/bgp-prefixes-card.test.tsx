import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { BGPPrefixesCard } from './bgp-prefixes-card';

// The server offers every op here; bgp-cards.capability.test.tsx covers the gate.
vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({ loading: false, error: undefined, capability: () => ({ enabled: true }) }),
}));

// The card runs on the real SDK GatewayService through useBGPPrefixes; fetch is the only stub.
const LIST = 'GET /api/v1/gateway/bgp/prefixes';
const ANNOUNCE = 'POST /api/v1/gateway/bgp/prefixes';
const WITHDRAW = 'DELETE /api/v1/gateway/bgp/prefixes';
const PATH = '/api/v1/gateway/bgp/prefixes';

function stub(extra: Record<string, Answer> = {}) {
  return stubControlPlane({
    [LIST]: ok({
      prefixes: [{ prefix: '198.51.100.0/24', nextHop: '192.0.2.1', announcedAt: '2026-11-21T10:00:00Z' }],
    }),
    ...extra,
  });
}

async function renderLoaded() {
  render(withControlPlane(<BGPPrefixesCard />));
  await waitFor(() => expect(screen.getAllByTestId('bgp-prefix-row')).toHaveLength(1));
}

async function click(el: HTMLElement) {
  await act(async () => {
    fireEvent.click(el);
  });
}

function type(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

describe('BGPPrefixesCard', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('lists the announced prefixes', async () => {
    stub();
    await renderLoaded();
    const row = screen.getByTestId('bgp-prefix-row');
    for (const text of ['198.51.100.0/24', '192.0.2.1', '2026-11-21T10:00:00Z']) {
      expect(within(row).getByText(text)).toBeTruthy();
    }
  });

  it('announces a trimmed prefix with a next hop and re-reads', async () => {
    const sent = stub({ [ANNOUNCE]: ok({ status: { success: true, message: 'prefix announced successfully' } }) });
    await renderLoaded();
    type('Prefix', ' 198.51.100.128/25 ');
    type('Next hop', ' 192.0.2.1 ');
    await click(screen.getByRole('button', { name: 'Announce' }));

    const toast = await screen.findByText('Prefix announced: 198.51.100.128/25');
    expect(toast.getAttribute('data-variant')).toBe('success');
    expect(sent.find((s) => s.method === 'POST')?.body).toEqual({ prefix: '198.51.100.128/25', nextHop: '192.0.2.1' });
    expect((screen.getByLabelText('Prefix') as HTMLInputElement).value).toBe('');
    expect((screen.getByLabelText('Next hop') as HTMLInputElement).value).toBe('');
    await waitFor(() => expect(sent.filter((s) => s.method === 'GET' && s.path === PATH)).toHaveLength(2));
  });

  it('announces an IPv6 prefix without a next hop', async () => {
    const sent = stub({ [ANNOUNCE]: ok({ status: { success: true, message: 'prefix announced successfully' } }) });
    await renderLoaded();
    type('Prefix', '2001:db8::/48');
    await click(screen.getByRole('button', { name: 'Announce' }));

    await waitFor(() => expect(sent.find((s) => s.method === 'POST')?.body).toEqual({ prefix: '2001:db8::/48' }));
  });

  it('keeps Announce disabled for a non-CIDR prefix', async () => {
    const sent = stub();
    await renderLoaded();
    const announce = screen.getByRole('button', { name: 'Announce' }) as HTMLButtonElement;
    expect(announce.disabled).toBe(true);
    type('Prefix', '198.51.100.0');
    expect(screen.getByTestId('bgp-prefix-invalid').textContent).toBe('Not a CIDR prefix');
    expect(announce.disabled).toBe(true);
    await click(announce);
    expect(sent.filter((s) => s.method === 'POST')).toHaveLength(0);
  });

  it('shows the announce refusal verbatim', async () => {
    stub({ [ANNOUNCE]: refused(400, 'invalid next_hop: bogus') });
    await renderLoaded();
    type('Prefix', '198.51.100.0/24');
    type('Next hop', 'bogus');
    await click(screen.getByRole('button', { name: 'Announce' }));

    const toast = await screen.findByText('Announce failed: invalid next_hop: bogus');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
  });

  it('asks before withdrawing and sends nothing on Cancel', async () => {
    const sent = stub();
    await renderLoaded();
    await click(screen.getByRole('button', { name: 'Withdraw 198.51.100.0/24' }));

    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText('Withdraw 198.51.100.0/24?')).toBeTruthy();
    await click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(sent.filter((s) => s.method === 'DELETE')).toHaveLength(0);
  });

  it('withdraws after the confirm', async () => {
    const sent = stub({ [WITHDRAW]: ok({ status: { success: true, message: 'withdrawn' } }) });
    await renderLoaded();
    await click(screen.getByRole('button', { name: 'Withdraw 198.51.100.0/24' }));
    const dialog = await screen.findByRole('dialog');
    await click(within(dialog).getByRole('button', { name: 'Confirm' }));

    const toast = await screen.findByText('Prefix withdrawn: 198.51.100.0/24');
    expect(toast.getAttribute('data-variant')).toBe('success');
    const deletes = sent.filter((s) => s.method === 'DELETE');
    expect(deletes).toHaveLength(1);
    expect(deletes[0].path).toBe(PATH);
    const call = vi
      .mocked(fetch)
      .mock.calls.find(([, init]) => (init?.method ?? 'GET').toUpperCase() === 'DELETE');
    expect(call).toBeTruthy();
    const input = call![0];
    const url = new URL(input instanceof Request ? input.url : String(input));
    expect(url.searchParams.get('prefix')).toBe('198.51.100.0/24');
  });
});
