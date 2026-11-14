import type { ReactNode } from 'react';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import type { Container } from '@/types/infrastructure';
import { ContainerTable } from './container-table';

// Opening a Radix menu in jsdom is slow, so the row menu renders its items
// inline, as in device-table.test.tsx. The items' onClick are the table's own.
vi.mock('@/components/ui/dropdown-menu', () => ({
  DropdownMenu: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DropdownMenuTrigger: ({ children }: { children: ReactNode }) => <>{children}</>,
  DropdownMenuContent: ({ children }: { children: ReactNode }) => <div role="menu">{children}</div>,
  DropdownMenuLabel: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DropdownMenuSeparator: () => <hr />,
  DropdownMenuItem: ({ children, onClick }: { children: ReactNode; onClick?: () => void }) => (
    <div role="menuitem" onClick={onClick}>
      {children}
    </div>
  ),
}));

function container(overrides: Partial<Container> = {}): Container {
  return {
    id: 'c-1',
    name: 'web',
    image: 'nginx:latest',
    status: 'running',
    ports: [],
    createdAt: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
    ...overrides,
  };
}

function mount(containers: Container[], extra: { onLogs?: (c: Container) => void; onShell?: (c: Container) => void } = {}) {
  const onRefresh = vi.fn();
  render(withControlPlane(<ContainerTable containers={containers} onRefresh={onRefresh} {...extra} />));
  return { onRefresh };
}

async function choose(item: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('menuitem', { name: item }));
  });
}

describe('ContainerTable', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('shows the empty row without containers', () => {
    stubControlPlane({});
    mount([]);

    expect(screen.getByText('No containers found')).toBeDefined();
    expect(screen.queryByRole('menu')).toBeNull();
  });

  it('renders a row per container with its image, status, ports and age', () => {
    stubControlPlane({});
    mount([
      container({
        ports: [
          { host: 8080, container: 80, protocol: 'tcp' },
          { host: 5353, container: 53, protocol: 'udp' },
        ],
      }),
      container({ id: 'c-2', name: 'db', image: 'postgres:16', status: 'error' }),
    ]);

    const rows = screen.getAllByRole('row');
    expect(rows).toHaveLength(3);
    const web = within(rows[1]);
    expect(web.getByText('web')).toBeDefined();
    expect(web.getByText('nginx:latest')).toBeDefined();
    expect(web.getByText('running').className).toContain('text-green-500');
    expect(web.getByText('8080:80/tcp, 5353:53/udp')).toBeDefined();
    expect(web.getByText('about 2 hours ago')).toBeDefined();
    const db = within(rows[2]);
    expect(db.getByText('error').className).toContain('text-red-500');
    expect(db.getByText('-')).toBeDefined();
  });

  it('gives each status its colour', () => {
    stubControlPlane({});
    mount([
      container({ id: '1', status: 'stopped' }),
      container({ id: '2', status: 'creating' }),
    ]);

    expect(screen.getByText('stopped').className).toContain('text-gray-500');
    expect(screen.getByText('creating').className).toContain('text-blue-500');
  });

  it('offers Stop, Logs and Shell for a running container, not Start', () => {
    stubControlPlane({});
    const onLogs = vi.fn();
    const onShell = vi.fn();
    const c = container();
    mount([c], { onLogs, onShell });

    expect(screen.queryByRole('menuitem', { name: 'Start' })).toBeNull();
    expect(screen.getByRole('menuitem', { name: 'Stop' })).toBeDefined();
    fireEvent.click(screen.getByRole('menuitem', { name: 'Logs' }));
    fireEvent.click(screen.getByRole('menuitem', { name: 'Shell' }));
    expect(onLogs).toHaveBeenCalledWith(c);
    expect(onShell).toHaveBeenCalledWith(c);
  });

  it('hides Logs and Shell without their handlers', () => {
    stubControlPlane({});
    mount([container()]);

    expect(screen.queryByRole('menuitem', { name: 'Logs' })).toBeNull();
    expect(screen.queryByRole('menuitem', { name: 'Shell' })).toBeNull();
  });

  it('offers Start and no Stop, Logs or Shell for a stopped container', () => {
    stubControlPlane({});
    mount([container({ status: 'stopped' })], { onLogs: vi.fn(), onShell: vi.fn() });

    expect(screen.getByRole('menuitem', { name: 'Start' })).toBeDefined();
    expect(screen.queryByRole('menuitem', { name: 'Stop' })).toBeNull();
    expect(screen.queryByRole('menuitem', { name: 'Logs' })).toBeNull();
    expect(screen.getByRole('menuitem', { name: 'Delete' })).toBeDefined();
  });

  it('starts through POST /containers/{id}/start and refreshes', async () => {
    const sent = stubControlPlane({ 'POST /api/v1/compute/containers/c-1/start': ok({}) });
    const { onRefresh } = mount([container({ status: 'stopped' })]);

    await choose('Start');

    await waitFor(() => expect(onRefresh).toHaveBeenCalledTimes(1));
    expect(sent).toEqual([{ method: 'POST', path: '/api/v1/compute/containers/c-1/start', body: {} }]);
    expect(screen.getByText('Success: Container started successfully')).toBeDefined();
    expect((screen.getAllByRole('button')[0] as HTMLButtonElement).disabled).toBe(false);
  });

  it('stops through POST /containers/{id}/stop and refreshes', async () => {
    const sent = stubControlPlane({ 'POST /api/v1/compute/containers/c-1/stop': ok({}) });
    const { onRefresh } = mount([container()]);

    await choose('Stop');

    await waitFor(() => expect(onRefresh).toHaveBeenCalledTimes(1));
    expect(sent.map((r) => `${r.method} ${r.path}`)).toEqual(['POST /api/v1/compute/containers/c-1/stop']);
    expect(screen.getByText('Success: Container stopped successfully')).toBeDefined();
  });

  it('deletes through DELETE /containers/{id} and refreshes', async () => {
    const sent = stubControlPlane({ 'DELETE /api/v1/compute/containers/c-1': ok({}) });
    const { onRefresh } = mount([container()]);

    await choose('Delete');

    await waitFor(() => expect(onRefresh).toHaveBeenCalledTimes(1));
    expect(sent.map((r) => `${r.method} ${r.path}`)).toEqual(['DELETE /api/v1/compute/containers/c-1']);
    expect(screen.getByText('Success: Container deleted successfully')).toBeDefined();
  });

  it.each([
    ['Start', 'stopped', 'POST /api/v1/compute/containers/c-1/start', 'Failed to start container: no such image'],
    ['Stop', 'running', 'POST /api/v1/compute/containers/c-1/stop', 'Failed to stop container: no such image'],
    ['Delete', 'running', 'DELETE /api/v1/compute/containers/c-1', 'Failed to delete container: no such image'],
  ] as const)('shows a refused %s as a destructive toast and does not refresh', async (item, status, route, message) => {
    stubControlPlane({ [route]: refused(500, 'no such image') });
    const { onRefresh } = mount([container({ status })]);

    await choose(item);

    const toast = await screen.findByText(`Error: ${message}`);
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(onRefresh).not.toHaveBeenCalled();
    expect((screen.getAllByRole('button')[0] as HTMLButtonElement).disabled).toBe(false);
  });
});
