import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import GatewayIPAMPage from './page';

// Every op is offered here so these cases keep testing the writes; the gate
// itself (it fails closed) is tested in page.capability-gate.test.tsx.
vi.mock('@/hooks/use-capabilities', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/hooks/use-capabilities')>()),
  useCapabilities: () => ({ loading: false, error: undefined, capability: () => ({ enabled: true }) }),
}));

const PATH = '/api/v1/gateway/ipam/allocations';

const A1 = { ip: '10.0.0.10', poolId: 'pool-a', hostname: 'node-a', allocatedAt: '2026-11-20T00:00:00Z' };
const A2 = { ip: '10.0.0.11', poolId: 'pool-a', allocatedAt: '2026-11-21T00:00:00Z' };

const allocated: Answer = {
  status: 201,
  body: { code: 201, success: true, payload: { status: { success: true, message: 'allocated' }, allocation: A2 } },
};

const urls = () =>
  vi.mocked(fetch).mock.calls.map(([input]) => String(input instanceof Request ? input.url : input));

const toasts = () => screen.queryAllByTestId('toast').map((t) => t.textContent);

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('GatewayIPAMPage', () => {
  it('lists the allocations', async () => {
    stubControlPlane({ [`GET ${PATH}`]: ok({ allocations: [A1, A2] }) });
    render(withControlPlane(<GatewayIPAMPage />));

    expect(await screen.findByText('10.0.0.10')).toBeTruthy();
    expect(screen.getByText('node-a')).toBeTruthy();
    expect(screen.getByText('10.0.0.11')).toBeTruthy();
  });

  it('filters by pool', async () => {
    stubControlPlane({ [`GET ${PATH}`]: ok({ allocations: [A1] }) });
    render(withControlPlane(<GatewayIPAMPage />));

    fireEvent.change(screen.getByLabelText('Pool'), { target: { value: 'pool-a' } });
    fireEvent.click(screen.getByRole('button', { name: 'Filter' }));

    await waitFor(() => expect(urls().some((u) => u.endsWith(`${PATH}?poolId=pool-a`))).toBe(true));
  });

  it('allocates an IP and lists again', async () => {
    const routes: Record<string, Answer> = {
      [`GET ${PATH}`]: ok({ allocations: [A1] }),
      [`POST ${PATH}`]: allocated,
    };
    const sent = stubControlPlane(routes);
    render(withControlPlane(<GatewayIPAMPage />));
    await screen.findByText('10.0.0.10');

    routes[`GET ${PATH}`] = ok({ allocations: [A1, A2] });
    fireEvent.change(screen.getByLabelText('Pool ID'), { target: { value: 'pool-a' } });
    fireEvent.change(screen.getByLabelText('Hostname'), { target: { value: 'node-b' } });
    fireEvent.click(screen.getByRole('button', { name: 'Allocate' }));

    await waitFor(() => expect(toasts()).toContain('IP allocated: 10.0.0.11'));
    expect(sent).toContainEqual({ method: 'POST', path: PATH, body: { poolId: 'pool-a', hostname: 'node-b' } });
    expect(await screen.findByText('10.0.0.11')).toBeTruthy();
  });

  it('shows a refused allocate', async () => {
    stubControlPlane({
      [`GET ${PATH}`]: ok({ allocations: [] }),
      [`POST ${PATH}`]: refused(409, 'pool pool-z exhausted'),
    });
    render(withControlPlane(<GatewayIPAMPage />));

    fireEvent.change(screen.getByLabelText('Pool ID'), { target: { value: 'pool-z' } });
    fireEvent.click(screen.getByRole('button', { name: 'Allocate' }));

    const text = 'Allocation refused: HTTP 409: pool pool-z exhausted';
    await waitFor(() => expect(toasts()).toContain(text));
    const toast = screen.getAllByTestId('toast').find((t) => t.textContent === text);
    expect(toast?.getAttribute('data-variant')).toBe('destructive');
  });

  it('releases after the confirm, and Cancel sends nothing', async () => {
    const routes: Record<string, Answer> = {
      [`GET ${PATH}`]: ok({ allocations: [A1] }),
      [`DELETE ${PATH}`]: ok({ status: { success: true, message: 'released' } }),
    };
    const sent = stubControlPlane(routes);
    render(withControlPlane(<GatewayIPAMPage />));

    fireEvent.click(await screen.findByRole('button', { name: 'Release 10.0.0.10' }));
    let dialog = await screen.findByRole('dialog');
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(sent.some((s) => s.method === 'DELETE')).toBe(false);

    routes[`GET ${PATH}`] = ok({ allocations: [] });
    fireEvent.click(screen.getByRole('button', { name: 'Release 10.0.0.10' }));
    dialog = await screen.findByRole('dialog');
    fireEvent.click(within(dialog).getByRole('button', { name: 'Release' }));

    await waitFor(() => expect(urls().some((u) => u.endsWith('?ip=10.0.0.10'))).toBe(true));
    await waitFor(() => expect(toasts()).toContain('IP released: 10.0.0.10'));
    expect(await screen.findByText('No allocations')).toBeTruthy();
  });
});
