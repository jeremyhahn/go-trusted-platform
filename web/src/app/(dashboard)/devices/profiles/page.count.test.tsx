import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';

// The device profiles page reads the registered total through the real SDK
// client (DeviceService.countProfiles -> GET /device/profiles/count, #2048).
// Only the Radix select and dropdown are stubbed; fetch is the control-plane
// stub.

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

function stat(title: string): string {
  const header = screen.getByText(title).parentElement;
  return header?.nextElementSibling?.firstElementChild?.textContent ?? '';
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('DeviceProfilesPage registered total (#2048)', () => {
  it('shows the registered total from GET /device/profiles/count', async () => {
    const sent = stubControlPlane(routes(3, 3, ok({ count: 3 })));
    render(withControlPlane(<DeviceProfilesPage />));

    const line = await screen.findByTestId('profile-count');
    expect(line.textContent).toBe('Showing 3 of 3 registered profiles');
    expect(sent).toContainEqual({ method: 'GET', path: '/api/v1/device/profiles/count', body: undefined });
    expect(await screen.findByText('profile-3')).toBeTruthy();
  });

  it('says the list is cut off and the card shows the registered total', async () => {
    stubControlPlane(routes(2, 40, ok({ count: 40 })));
    render(withControlPlane(<DeviceProfilesPage />));

    await waitFor(() =>
      expect(screen.getByTestId('profile-count').textContent).toBe(
        'Showing 2 of 40 registered profiles (only the first 2 are loaded)'
      )
    );
    expect(stat('Total Profiles')).toBe('40');
  });

  it('Refresh re-reads the count', async () => {
    const sent = stubControlPlane(routes(1, 1, ok({ count: 1 })));
    render(withControlPlane(<DeviceProfilesPage />));

    await screen.findByTestId('profile-count');
    fireEvent.click(screen.getByText('Refresh').closest('button')!);
    await waitFor(() =>
      expect(
        sent.filter((r) => r.method === 'GET' && r.path === '/api/v1/device/profiles/count')
      ).toHaveLength(2)
    );
  });

  it('hides the total and keeps the list when the count is refused', async () => {
    const sent = stubControlPlane(routes(2, 2, refused(403, 'forbidden')));
    render(withControlPlane(<DeviceProfilesPage />));

    expect(await screen.findByText('profile-2')).toBeTruthy();
    await waitFor(() =>
      expect(sent.some((r) => r.method === 'GET' && r.path === '/api/v1/device/profiles/count')).toBe(true)
    );
    expect(screen.queryByTestId('profile-count')).toBeNull();
    expect(stat('Total Profiles')).toBe('2');
  });
});
