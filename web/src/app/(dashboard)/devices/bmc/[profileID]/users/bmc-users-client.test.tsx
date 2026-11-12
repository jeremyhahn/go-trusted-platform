import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { UseBMCUsersResult } from '@/hooks';
import BMCUsersClient from './bmc-users-client';

// #1720 (Codex round 2 on #1730): CreateUser writes the supplied slot without
// an occupancy check, so the page offers creation only once the current
// profile's user listing has succeeded.

vi.mock('next/navigation', () => ({
  useParams: () => ({ profileID: '7' }),
  usePathname: () => '/devices/bmc/7/users',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

let hook: UseBMCUsersResult;
const createUser = vi.fn(async () => {});

vi.mock('@/hooks', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/hooks')>();
  return {
    ...actual,
    useBMCUsers: () => hook,
    useToast: () => ({ toast: vi.fn() }),
  };
});

function state(over: Partial<UseBMCUsersResult>): UseBMCUsersResult {
  return {
    users: [],
    isLoading: false,
    error: null,
    listed: false,
    refetch: vi.fn(async () => {}),
    createUser,
    deleteUser: vi.fn(async () => {}),
    setUserPassword: vi.fn(async () => {}),
    setUserPrivilege: vi.fn(async () => {}),
    replaceWebCertificate: vi.fn(async () => {}),
    ...over,
  };
}

const listedUsers = [
  { slot: 3, username: 'ops', enabled: true, privilege: 0x02, channel: 1 },
  { slot: 4, username: 'backup', enabled: true, privilege: 0x02, channel: 1 },
];

function createButton(): HTMLButtonElement {
  return screen.getByRole('button', { name: 'Create User' }) as HTMLButtonElement;
}

function fillAndSubmit() {
  const dialog = screen.getByRole('dialog');
  fireEvent.change(dialog.querySelector('#bmc-create-username')!, { target: { value: 'auditor' } });
  fireEvent.change(dialog.querySelector('#bmc-create-password')!, { target: { value: 'pw-123456' } });
  fireEvent.submit(dialog.querySelector('form')!);
}

describe('BMCUsersClient Create User', () => {
  beforeEach(() => {
    createUser.mockClear();
  });
  afterEach(() => {
    cleanup();
  });

  it('is disabled while the listing loads', () => {
    hook = state({ isLoading: true, listed: false });
    render(<BMCUsersClient />);
    expect(createButton().disabled).toBe(true);
  });

  it('is disabled after a failed listing', () => {
    hook = state({ error: 'boom', listed: false });
    render(<BMCUsersClient />);
    expect(createButton().disabled).toBe(true);
    expect(screen.getByText('boom')).toBeTruthy();
  });

  it('opens on a free slot and creates once the listing succeeded', () => {
    hook = state({ users: listedUsers, listed: true });
    render(<BMCUsersClient />);
    expect(createButton().disabled).toBe(false);
    fireEvent.click(createButton());
    const slot = screen.getByRole('dialog').querySelector('#bmc-create-slot') as HTMLInputElement;
    expect(slot.value).toBe('5');
    fillAndSubmit();
    expect(createUser).toHaveBeenCalledTimes(1);
    expect(createUser).toHaveBeenCalledWith(expect.objectContaining({ slot: 5, username: 'auditor' }));
  });

  it('refuses submit when the listing is lost while the dialog is open', () => {
    hook = state({ users: listedUsers, listed: true });
    const { rerender } = render(<BMCUsersClient />);
    fireEvent.click(createButton());
    hook = state({ users: [], isLoading: true, listed: false });
    rerender(<BMCUsersClient />);
    fillAndSubmit();
    expect(createUser).not.toHaveBeenCalled();
    expect(screen.getByTestId('bmc-create-slot-error').textContent).toContain(
      'The user list has not loaded; reload it before creating a user.'
    );
  });
});
