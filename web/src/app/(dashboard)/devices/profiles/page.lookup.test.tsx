import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import type { ReactNode } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';

// The device profiles page finds one profile through the real SDK client
// (DeviceService.findProfileBySerial -> GET /device/profiles/serial/{serial}
// and DeviceService.findProfileByMACAddress -> GET /device/profiles/mac/{mac},
// #2048). Only the Radix select and dropdown are stubbed; fetch is the
// control-plane stub.

vi.mock('next/navigation', () => ({
  usePathname: () => '/devices/profiles',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

// Radix Select does not open in jsdom; a native select keeps both the
// controlled filter and the uncontrolled named form field testable.
vi.mock('@/components/ui/select', () => ({
  Select: ({
    value,
    defaultValue,
    name,
    onValueChange,
    children,
  }: {
    value?: string;
    defaultValue?: string;
    name?: string;
    onValueChange?: (v: string) => void;
    children: ReactNode;
  }) =>
    value !== undefined ? (
      <select data-testid="select" value={value} onChange={(e) => onValueChange?.(e.target.value)}>
        {children}
      </select>
    ) : (
      <select data-testid="form-select" name={name} defaultValue={defaultValue}>
        {children}
      </select>
    ),
  SelectTrigger: () => null,
  SelectValue: () => null,
  SelectContent: ({ children }: { children: ReactNode }) => <>{children}</>,
  SelectItem: ({ value, children }: { value: string; children: ReactNode }) => <option value={value}>{children}</option>,
}));

// Radix DropdownMenu needs pointer events jsdom lacks; render items inline.
vi.mock('@/components/ui/dropdown-menu', () => ({
  DropdownMenu: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DropdownMenuTrigger: ({ children }: { children: ReactNode }) => <>{children}</>,
  DropdownMenuContent: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DropdownMenuLabel: ({ children }: { children: ReactNode }) => <span>{children}</span>,
  DropdownMenuSeparator: () => null,
  DropdownMenuItem: ({ children, onClick }: { children: ReactNode; onClick?: () => void }) => (
    <button type="button" onClick={onClick}>
      {children}
    </button>
  ),
}));

import DeviceProfilesPage from './page';

function profilesList(n: number) {
  return Array.from({ length: n }, (_, k) => {
    const i = k + 1;
    return { id: String(i), name: 'profile-' + i, role: 'server' };
  });
}

function routes(n: number, total: number, count: ReturnType<typeof ok>) {
  return {
    'GET /api/v1/device/profiles': ok({
      profiles: profilesList(n),
      pagination: { page: 1, page_size: 25, total, total_pages: 1, has_more: false },
    }),
    'GET /api/v1/device/profiles/count': count,
  };
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const SERIAL_PATH = '/api/v1/device/profiles/serial/SN-001';
const MAC_PATH = '/api/v1/device/profiles/mac/aa%3Abb%3Acc%3Add%3Aee%3Aff';

function query(): HTMLInputElement {
  return screen.getByLabelText('Serial or MAC address') as HTMLInputElement;
}

async function typeQuery(value: string) {
  fireEvent.change(await screen.findByLabelText('Serial or MAC address'), { target: { value } });
}

describe('DeviceProfilesPage profile lookup (#2048)', () => {
  it('finds a profile by serial', async () => {
    const sent = stubControlPlane({
      ...routes(2, 2, ok({ count: 2 })),
      ['GET ' + SERIAL_PATH]: ok({ id: '42', name: 'edge-gw', role: 'server' }),
    });
    render(withControlPlane(<DeviceProfilesPage />));

    await typeQuery('SN-001');
    fireEvent.click(screen.getByRole('button', { name: 'Find by serial' }));

    const result = await screen.findByTestId('profile-lookup-result');
    await waitFor(() => expect(result.textContent).toContain('edge-gw'));
    expect(sent).toContainEqual({ method: 'GET', path: SERIAL_PATH, body: undefined });
    expect(within(result).queryByRole('link')).toBeNull();
  });

  it('finds a profile by MAC address', async () => {
    const sent = stubControlPlane({
      ...routes(2, 2, ok({ count: 2 })),
      ['GET ' + MAC_PATH]: ok({ id: '7', name: 'lab-node', role: 'workstation' }),
    });
    render(withControlPlane(<DeviceProfilesPage />));

    await typeQuery('aa:bb:cc:dd:ee:ff');
    fireEvent.click(screen.getByRole('button', { name: 'Find by MAC' }));

    const result = await screen.findByTestId('profile-lookup-result');
    await waitFor(() => expect(result.textContent).toContain('lab-node'));
    expect(sent).toContainEqual({ method: 'GET', path: MAC_PATH, body: undefined });
    expect(within(result).queryByRole('link')).toBeNull();
  });

  it('shows the matched profile in place, with no link to a missing route', async () => {
    stubControlPlane({
      ...routes(2, 2, ok({ count: 2 })),
      ['GET ' + SERIAL_PATH]: ok({ id: '42', name: 'edge-gw', role: 'server' }),
    });
    render(withControlPlane(<DeviceProfilesPage />));

    await typeQuery('SN-001');
    fireEvent.click(screen.getByRole('button', { name: 'Find by serial' }));

    const result = await screen.findByTestId('profile-lookup-result');
    await waitFor(() => expect(result.textContent).toContain('edge-gw'));
    expect(document.querySelector('a[href^="/devices/profiles/"]')).toBeNull();
  });

  it('ignores a lookup answer that arrives after the query changed', async () => {
    stubControlPlane({
      ...routes(2, 2, ok({ count: 2 })),
      ['GET ' + SERIAL_PATH]: ok({ id: '42', name: 'edge-gw', role: 'server' }),
    });
    const stubbed = globalThis.fetch;
    let release: () => void = () => {};
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    let answered = false;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = new URL(input instanceof Request ? input.url : String(input));
        if (url.pathname === SERIAL_PATH) {
          await held;
          const response = await stubbed(input, init);
          answered = true;
          return response;
        }
        return stubbed(input, init);
      })
    );
    render(withControlPlane(<DeviceProfilesPage />));

    await typeQuery('SN-001');
    fireEvent.click(screen.getByRole('button', { name: 'Find by serial' }));
    fireEvent.change(query(), { target: { value: 'SN-002' } });

    release();
    await waitFor(() => expect(answered).toBe(true));
    await act(async () => {});

    expect(screen.queryByTestId('profile-lookup-result')).toBeNull();
    expect(screen.queryByTestId('profile-lookup-error')).toBeNull();
    expect((screen.getByRole('button', { name: 'Find by serial' }) as HTMLButtonElement).disabled).toBe(false);
    expect((screen.getByRole('button', { name: 'Find by MAC' }) as HTMLButtonElement).disabled).toBe(false);
  });

  it('says no profile matches on a 404', async () => {
    stubControlPlane({
      ...routes(2, 2, ok({ count: 2 })),
      'GET /api/v1/device/profiles/serial/SN-404': refused(404, 'profile not found'),
    });
    render(withControlPlane(<DeviceProfilesPage />));

    await typeQuery('SN-404');
    fireEvent.click(screen.getByRole('button', { name: 'Find by serial' }));

    const result = await screen.findByTestId('profile-lookup-result');
    expect(result.textContent).toBe('No profile matches SN-404');
  });

  it('shows a refused lookup', async () => {
    stubControlPlane({
      ...routes(2, 2, ok({ count: 2 })),
      'GET /api/v1/device/profiles/serial/SN-403': refused(403, 'lookup denied'),
    });
    render(withControlPlane(<DeviceProfilesPage />));

    await typeQuery('SN-403');
    fireEvent.click(screen.getByRole('button', { name: 'Find by serial' }));

    const error = await screen.findByTestId('profile-lookup-error');
    expect(error.textContent).toBe('Lookup refused: lookup denied');
    expect(screen.queryByTestId('profile-lookup-result')).toBeNull();
  });

  it('clears the answer when the query changes', async () => {
    const sent = stubControlPlane({
      ...routes(2, 2, ok({ count: 2 })),
      ['GET ' + SERIAL_PATH]: ok({ id: '42', name: 'edge-gw', role: 'server' }),
    });
    render(withControlPlane(<DeviceProfilesPage />));

    await typeQuery('');
    expect((screen.getByRole('button', { name: 'Find by serial' }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole('button', { name: 'Find by MAC' }) as HTMLButtonElement).disabled).toBe(true);
    await typeQuery('   ');
    expect((screen.getByRole('button', { name: 'Find by serial' }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole('button', { name: 'Find by MAC' }) as HTMLButtonElement).disabled).toBe(true);

    await typeQuery('SN-001');
    fireEvent.click(screen.getByRole('button', { name: 'Find by serial' }));
    const result = await screen.findByTestId('profile-lookup-result');
    await waitFor(() => expect(result.textContent).toContain('edge-gw'));
    const lookups = () => sent.filter((r) => r.path.startsWith('/api/v1/device/profiles/serial/')).length;
    expect(lookups()).toBe(1);

    fireEvent.change(query(), { target: { value: 'SN-002' } });
    expect(screen.queryByTestId('profile-lookup-result')).toBeNull();
    expect(lookups()).toBe(1);
  });
});
