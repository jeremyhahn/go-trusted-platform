import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { useState, type ReactNode } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { GatewayRoute } from '@/types/infrastructure';

import { GatewayRoutesTable } from './gateway-routes-table';

// The routes table lists the gateway's routes. Delete and toggle are
// placeholders until the gateway service grows deleteRoute/updateRoute:
// they resolve at once, so the tests pin the success path and, through a
// fake useMutation that can be told to fail, the error toasts.

const toast = vi.fn();
let failWith: Error | undefined;
const mutationArgs: unknown[] = [];

vi.mock('@/hooks', () => ({
  useGateway: () => ({}),
  useToast: () => ({ toast }),
  useMutation: <V, R>(
    fn: (v: V) => Promise<R>,
    opts?: { onSuccess?: (r: R) => void; onError?: (e: Error) => void },
  ) => {
    // eslint-disable-next-line react-hooks/rules-of-hooks
    const [isLoading, setLoading] = useState(false);
    return {
      isLoading,
      mutate: async (v: V) => {
        mutationArgs.push(v);
        if (failWith) {
          opts?.onError?.(failWith);
          return;
        }
        setLoading(true);
        const r = await fn(v);
        setLoading(false);
        opts?.onSuccess?.(r);
      },
    };
  },
}));

vi.mock('@/components/ui/dropdown-menu', () => ({
  DropdownMenu: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DropdownMenuTrigger: ({ children }: { children: ReactNode }) => <>{children}</>,
  DropdownMenuContent: ({ children }: { children: ReactNode }) => <div role="menu">{children}</div>,
  DropdownMenuLabel: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DropdownMenuSeparator: () => <hr />,
  DropdownMenuItem: ({ children, onClick }: { children: ReactNode; onClick?: () => void }) => (
    <button type="button" role="menuitem" onClick={onClick}>
      {children}
    </button>
  ),
}));

function route(overrides: Partial<GatewayRoute> = {}): GatewayRoute {
  return {
    id: 'rt1',
    path: '/api/v1/users',
    method: 'GET',
    backend: 'users-svc:8080',
    rateLimit: 100,
    rateLimitWindow: '10s',
    authRequired: true,
    status: 'active',
    requestsTotal: 1234567,
    requestsPerSecond: 3.14159,
    avgLatencyMs: 42.6,
    ...overrides,
  } as GatewayRoute;
}

function rowOf(text: string): HTMLElement {
  return screen.getByText(text).closest('tr') as HTMLElement;
}

beforeEach(() => {
  toast.mockReset();
  failWith = undefined;
  mutationArgs.length = 0;
});

afterEach(() => {
  cleanup();
});

describe('GatewayRoutesTable', () => {
  it('shows the empty state across all nine columns when there are no routes', () => {
    render(<GatewayRoutesTable routes={[]} onRefresh={vi.fn()} />);
    expect(screen.getByText('No routes found').getAttribute('colspan')).toBe('9');
    for (const h of [
      'Path', 'Method', 'Backend', 'Rate Limit', 'Auth', 'Status', 'Requests', 'Avg Latency', 'Actions',
    ]) {
      expect(screen.getByRole('columnheader', { name: h })).toBeTruthy();
    }
    expect(screen.queryByRole('menuitem')).toBeNull();
  });

  it('renders the route cells, counters and latency', () => {
    render(<GatewayRoutesTable routes={[route()]} onRefresh={vi.fn()} />);
    const row = within(rowOf('/api/v1/users'));
    expect(row.getByText('GET')).toBeTruthy();
    expect(row.getByText('users-svc:8080')).toBeTruthy();
    expect(row.getByText('100/10s')).toBeTruthy();
    expect(row.getByText('Required').className).toContain('bg-green-500/10');
    expect(row.getByText('active').className).toContain('bg-green-500/10');
    expect(row.getByText((1234567).toLocaleString(), { exact: false })).toBeTruthy();
    expect(row.getByText('(3.14/s)')).toBeTruthy();
    expect(row.getByText('43ms')).toBeTruthy();
  });

  it('defaults the rate-limit window to 1m', () => {
    render(<GatewayRoutesTable routes={[route({ rateLimitWindow: undefined })]} onRefresh={vi.fn()} />);
    expect(within(rowOf('/api/v1/users')).getByText('100/1m')).toBeTruthy();
  });

  it.each([
    ['missing', undefined],
    ['zero', 0],
  ])('renders a dash for a %s rate limit', (_label, rateLimit) => {
    render(<GatewayRoutesTable routes={[route({ rateLimit })]} onRefresh={vi.fn()} />);
    const row = within(rowOf('/api/v1/users'));
    expect(row.getByText('-')).toBeTruthy();
    expect(row.queryByText(/\/10s/)).toBeNull();
  });

  it('shows None for an open route, grey for an inactive one, and zero counters', () => {
    render(
      <GatewayRoutesTable
        routes={[
          route({
            authRequired: false,
            status: 'inactive',
            requestsTotal: 0,
            requestsPerSecond: 0,
            avgLatencyMs: 0,
          } as Partial<GatewayRoute>),
        ]}
        onRefresh={vi.fn()}
      />,
    );
    const row = within(rowOf('/api/v1/users'));
    expect(row.getByText('None').className).toContain('bg-gray-500/10');
    expect(row.getByText('inactive').className).toContain('bg-gray-500/10');
    expect(row.getByText('(0.00/s)')).toBeTruthy();
    expect(row.getByText('0ms')).toBeTruthy();
  });

  it('offers Disable for an active route and Enable otherwise', () => {
    render(
      <GatewayRoutesTable
        routes={[
          route(),
          route({ id: 'rt2', path: '/off', status: 'inactive' } as Partial<GatewayRoute>),
        ]}
        onRefresh={vi.fn()}
      />,
    );
    expect(within(rowOf('/api/v1/users')).getByRole('menuitem', { name: 'Disable' })).toBeTruthy();
    expect(within(rowOf('/off')).getByRole('menuitem', { name: 'Enable' })).toBeTruthy();
  });

  it('offers Edit only when onEdit is given and passes the route', () => {
    const onEdit = vi.fn();
    const r = route();
    const { rerender } = render(<GatewayRoutesTable routes={[r]} onRefresh={vi.fn()} />);
    expect(screen.queryByRole('menuitem', { name: 'Edit' })).toBeNull();
    rerender(<GatewayRoutesTable routes={[r]} onRefresh={vi.fn()} onEdit={onEdit} />);
    fireEvent.click(screen.getByRole('menuitem', { name: 'Edit' }));
    expect(onEdit).toHaveBeenCalledWith(r);
  });

  it('deletes by route id, toasts and refreshes', async () => {
    const onRefresh = vi.fn();
    render(<GatewayRoutesTable routes={[route()]} onRefresh={onRefresh} />);
    fireEvent.click(screen.getByRole('menuitem', { name: 'Delete' }));
    await waitFor(() => expect(onRefresh).toHaveBeenCalledTimes(1));
    expect(mutationArgs).toEqual(['rt1']);
    expect(toast).toHaveBeenCalledWith({ title: 'Success', description: 'Route deleted successfully' });
  });

  it('toggles with the whole route, toasts and refreshes', async () => {
    const onRefresh = vi.fn();
    const r = route();
    render(<GatewayRoutesTable routes={[r]} onRefresh={onRefresh} />);
    fireEvent.click(screen.getByRole('menuitem', { name: 'Disable' }));
    await waitFor(() => expect(onRefresh).toHaveBeenCalledTimes(1));
    expect(mutationArgs).toEqual([r]);
    expect(toast).toHaveBeenCalledWith({ title: 'Success', description: 'Route status updated successfully' });
  });

  it('toasts a failed delete and does not refresh', () => {
    failWith = new Error('route in use');
    const onRefresh = vi.fn();
    render(<GatewayRoutesTable routes={[route()]} onRefresh={onRefresh} />);
    fireEvent.click(screen.getByRole('menuitem', { name: 'Delete' }));
    expect(toast).toHaveBeenCalledWith({
      title: 'Error',
      description: 'Failed to delete route: route in use',
      variant: 'destructive',
    });
    expect(onRefresh).not.toHaveBeenCalled();
  });

  it('toasts a failed toggle and does not refresh', () => {
    failWith = new Error('forbidden');
    const onRefresh = vi.fn();
    render(<GatewayRoutesTable routes={[route()]} onRefresh={onRefresh} />);
    fireEvent.click(screen.getByRole('menuitem', { name: 'Disable' }));
    expect(toast).toHaveBeenCalledWith({
      title: 'Error',
      description: 'Failed to toggle route: forbidden',
      variant: 'destructive',
    });
    expect(onRefresh).not.toHaveBeenCalled();
  });
});
