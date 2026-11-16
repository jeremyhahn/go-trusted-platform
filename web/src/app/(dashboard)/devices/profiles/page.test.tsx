import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import type { ReactNode } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const { toast, push, service } = vi.hoisted(() => ({
  toast: vi.fn(),
  push: vi.fn(),
  service: { listProfiles: vi.fn(), createProfile: vi.fn(), deleteProfile: vi.fn() },
}));

vi.mock('next/navigation', () => ({ useRouter: () => ({ push }) }));
vi.mock('next/link', () => ({
  default: ({ href, children, className }: { href: string; children: ReactNode; className?: string }) => (
    <a href={href} className={className}>
      {children}
    </a>
  ),
}));

// useApi and useMutation are the SDK's real hooks; only the service is mocked.
vi.mock('@/hooks', async () => {
  const sdk = await import('trusted-platform-sdk');
  return {
    useApi: sdk.useApi,
    useMutation: sdk.useMutation,
    useDevice: () => service,
    useToast: () => ({ toast }),
  };
});

vi.mock('@/lib/device-profile-networks', () => ({
  networkPhaseRows: (p: { id: string }) =>
    p.id === 'p-1'
      ? [
          { name: 'mgmt', config: { vlan: 101 }, roles: ['enroll', 'runtime'] },
          { name: 'data', config: {}, roles: [] },
        ]
      : [],
}));

vi.mock('@/lib/pcr-baseline', () => ({
  baselineSourceLabel: (s: string) => `source:${s}`,
  baselineAge: () => '3 days',
  baselineRegisters: () => 'PCR 0,7',
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

function profiles() {
  return [
    {
      id: 'p-1',
      name: 'Edge Box',
      model: 'RPi4',
      role: 'edge',
      updated_at: '2026-03-05T12:00:00Z',
      pcr_baseline: { source: 'signed', recorded_at: '2026-03-01T00:00:00Z', recorded_from_device_id: 'dev-9' },
    },
    { id: 'p-2', name: 'Rack Server', role: 'server', updated_at: 'not-a-date' },
    { id: 'p-3', name: 'Lab Desk', model: 'Dell', role: 'workstation', pcr_baseline: { source: 'observed', recorded_at: 'x' } },
    { id: 'p-4', name: 'Sensor', role: 'iot' },
    { id: 'p-5', name: 'Second Server', role: 'server' },
  ];
}

function row(name: string): HTMLElement {
  const tr = screen.getByText(name).closest('tr');
  if (!tr) throw new Error(`no row for ${name}`);
  return tr;
}

function stat(title: string): string {
  const header = screen.getByText(title).parentElement;
  return header?.nextElementSibling?.firstElementChild?.textContent ?? '';
}

function names(): string[] {
  return screen.queryAllByRole('row').slice(1).map((tr) => tr.querySelector('.font-medium')?.textContent ?? '').filter(Boolean);
}

async function renderLoaded() {
  render(<DeviceProfilesPage />);
  await waitFor(() => expect(screen.queryByText('Loading profiles...')).toBeNull());
}

function openCreateDialog(): HTMLFormElement {
  fireEvent.click(screen.getByText('Create Profile'));
  const form = document.querySelector('form');
  if (!form) throw new Error('create form not rendered');
  return form;
}

beforeEach(() => {
  toast.mockReset();
  push.mockReset();
  service.listProfiles.mockReset();
  service.createProfile.mockReset();
  service.deleteProfile.mockReset();
  service.listProfiles.mockImplementation(() => Promise.resolve({ data: { profiles: profiles() } }));
  service.createProfile.mockImplementation(() => Promise.resolve({ data: { profile: { id: 'p-new' } } }));
  service.deleteProfile.mockImplementation(() => Promise.resolve({ data: {} }));
  vi.stubGlobal('confirm', vi.fn(() => true));
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('DeviceProfilesPage: loading and errors', () => {
  it('shows the loading state and disables Refresh while profiles load', () => {
    service.listProfiles.mockImplementation(() => new Promise(() => {}));
    render(<DeviceProfilesPage />);
    expect(screen.getByText('Loading profiles...')).toBeTruthy();
    expect((screen.getByText('Refresh').closest('button') as HTMLButtonElement).disabled).toBe(true);
  });

  it('shows the error alert, toasts it, and Retry refetches into the table', async () => {
    service.listProfiles.mockImplementationOnce(() => Promise.resolve({ error: { message: 'boom', status: 500 } }));
    render(<DeviceProfilesPage />);
    await waitFor(() => expect(screen.getByText('Error Loading Profiles')).toBeTruthy());
    expect(screen.getByText('boom')).toBeTruthy();
    expect(toast).toHaveBeenCalledWith({ title: 'Error loading profiles', description: 'boom', variant: 'destructive' });

    fireEvent.click(screen.getByText('Retry'));
    await waitFor(() => expect(screen.getByText('Edge Box')).toBeTruthy());
    expect(service.listProfiles).toHaveBeenCalledTimes(2);
    expect(screen.queryByText('Error Loading Profiles')).toBeNull();
  });

  it('shows the empty state and zero stats when there are no profiles', async () => {
    service.listProfiles.mockImplementation(() => Promise.resolve({ data: {} }));
    await renderLoaded();
    expect(screen.getByText('No device profiles found')).toBeTruthy();
    expect(stat('Total Profiles')).toBe('0');
    expect(stat('Servers')).toBe('0');
    expect(stat('Workstations')).toBe('0');
    expect(stat('IoT Devices')).toBe('0');
  });

  it('Refresh refetches the profiles', async () => {
    await renderLoaded();
    fireEvent.click(screen.getByText('Refresh'));
    await waitFor(() => expect(service.listProfiles).toHaveBeenCalledTimes(2));
  });
});

describe('DeviceProfilesPage: table and stats', () => {
  it('counts profiles in total and by role', async () => {
    await renderLoaded();
    expect(stat('Total Profiles')).toBe('5');
    expect(stat('Servers')).toBe('2');
    expect(stat('Workstations')).toBe('1');
    expect(stat('IoT Devices')).toBe('1');
  });

  it('counts a profile without a role as unknown, not as any card', async () => {
    service.listProfiles.mockImplementation(() =>
      Promise.resolve({ data: { profiles: [{ id: 'p-x', name: 'No Role', role: '' }] } }),
    );
    await renderLoaded();
    expect(stat('Total Profiles')).toBe('1');
    expect(stat('Servers')).toBe('0');
    expect(screen.getByText('No Role')).toBeTruthy();
  });

  it('renders model, role label and updated date, with dashes for missing or invalid values', async () => {
    await renderLoaded();
    const edge = within(row('Edge Box'));
    expect(edge.getByText('RPi4')).toBeTruthy();
    expect(edge.getByText('Edge')).toBeTruthy();
    expect(edge.getByText('Mar 5, 2026')).toBeTruthy();

    const rack = within(row('Rack Server'));
    expect(rack.getByText('-')).toBeTruthy();
    expect(rack.getByText('Server')).toBeTruthy();
    expect(rack.getByText('—')).toBeTruthy();

    expect(within(row('Lab Desk')).getByText('—')).toBeTruthy();
    expect(within(row('Sensor')).getByText('IoT')).toBeTruthy();
  });

  it('renders network phase rows with VLAN and roles, or No networks', async () => {
    await renderLoaded();
    const edge = within(row('Edge Box'));
    expect(edge.getByText('mgmt (VLAN 101)')).toBeTruthy();
    expect(edge.getByText('enroll, runtime')).toBeTruthy();
    expect(edge.getByText('data')).toBeTruthy();
    expect(screen.getAllByText('No networks')).toHaveLength(4);
  });

  it('renders the PCR baseline with its seeding device, or No baseline', async () => {
    await renderLoaded();
    const edge = within(row('Edge Box'));
    expect(edge.getByText('source:signed')).toBeTruthy();
    expect(edge.getByText('3 days old')).toBeTruthy();
    expect(edge.getByText('PCR 0,7')).toBeTruthy();
    expect(edge.getByText('dev-9').getAttribute('href')).toBe('/devices/dev-9');

    const lab = within(row('Lab Desk'));
    expect(lab.getByText('source:observed')).toBeTruthy();
    expect(lab.queryByText(/seeded by device/)).toBeNull();
    expect(screen.getAllByText('No baseline')).toHaveLength(3);
  });
});

describe('DeviceProfilesPage: filters', () => {
  it('searches name, model and id case-insensitively', async () => {
    await renderLoaded();
    const input = screen.getByPlaceholderText('Search profiles...');
    fireEvent.change(input, { target: { value: 'RACK' } });
    expect(names()).toEqual(['Rack Server']);
    fireEvent.change(input, { target: { value: 'rpi' } });
    expect(names()).toEqual(['Edge Box']);
    fireEvent.change(input, { target: { value: 'p-4' } });
    expect(names()).toEqual(['Sensor']);
  });

  it('shows the no-match message and Clear filters restores every profile', async () => {
    await renderLoaded();
    fireEvent.change(screen.getByPlaceholderText('Search profiles...'), { target: { value: 'zzz' } });
    expect(screen.getByText('No profiles match your filters')).toBeTruthy();
    fireEvent.click(screen.getByText('Clear filters'));
    expect(names()).toHaveLength(5);
    expect(screen.queryByText('Clear filters')).toBeNull();
  });

  it('filters by role, combines with search, and "all" removes the role filter', async () => {
    await renderLoaded();
    const role = screen.getByTestId('select') as HTMLSelectElement;
    fireEvent.change(role, { target: { value: 'server' } });
    expect(names()).toEqual(['Rack Server', 'Second Server']);
    fireEvent.change(screen.getByPlaceholderText('Search profiles...'), { target: { value: 'second' } });
    expect(names()).toEqual(['Second Server']);
    fireEvent.change(screen.getByPlaceholderText('Search profiles...'), { target: { value: '' } });
    fireEvent.change(role, { target: { value: 'all' } });
    expect(names()).toHaveLength(5);
    expect(screen.queryByText('Clear filters')).toBeNull();
  });

  it('lists every role, unknown included, in the role filter', async () => {
    await renderLoaded();
    const options = [...(screen.getByTestId('select') as HTMLSelectElement).options].map((o) => o.value);
    expect(options[0]).toBe('all');
    expect(options).toContain('unknown');
    expect(options).toContain('load-balancer');
  });
});

describe('DeviceProfilesPage: row actions', () => {
  it('navigates to the detail and edit pages', async () => {
    await renderLoaded();
    fireEvent.click(within(row('Edge Box')).getByText('View Details'));
    expect(push).toHaveBeenCalledWith('/devices/profiles/p-1');
    fireEvent.click(within(row('Edge Box')).getByText('Edit Profile'));
    expect(push).toHaveBeenCalledWith('/devices/profiles/p-1/edit');
  });

  it('duplicates a profile as a copy and refetches', async () => {
    await renderLoaded();
    await act(async () => {
      fireEvent.click(within(row('Edge Box')).getByText('Duplicate'));
    });
    expect(service.createProfile).toHaveBeenCalledWith({ profile: { name: 'Edge Box (Copy)', model: 'RPi4', role: 'edge' } });
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: 'Profile created', variant: 'success' }));
    await waitFor(() => expect(service.listProfiles).toHaveBeenCalledTimes(2));
  });

  it('toasts a failed duplicate without an unhandled rejection', async () => {
    service.createProfile.mockImplementation(() => Promise.resolve({ error: { code: 'conflict', message: 'exists', status: 409 } }));
    await renderLoaded();
    await act(async () => {
      fireEvent.click(within(row('Sensor')).getByText('Duplicate'));
    });
    expect(toast).toHaveBeenCalledWith({ title: 'Error creating profile', description: 'exists', variant: 'destructive' });
    expect(service.listProfiles).toHaveBeenCalledTimes(1);
  });

  it('does not delete when the confirmation is declined', async () => {
    const confirm = vi.fn(() => false);
    vi.stubGlobal('confirm', confirm);
    await renderLoaded();
    fireEvent.click(within(row('Edge Box')).getByText('Delete'));
    expect(confirm).toHaveBeenCalledWith('Are you sure you want to delete "Edge Box"?');
    expect(service.deleteProfile).not.toHaveBeenCalled();
  });

  it('deletes a confirmed profile, toasts and refetches', async () => {
    await renderLoaded();
    await act(async () => {
      fireEvent.click(within(row('Rack Server')).getByText('Delete'));
    });
    expect(service.deleteProfile).toHaveBeenCalledWith('p-2');
    await waitFor(() => expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: 'Profile deleted' })));
    await waitFor(() => expect(service.listProfiles).toHaveBeenCalledTimes(2));
  });

  it('toasts a failed delete and does not refetch', async () => {
    service.deleteProfile.mockImplementation(() => Promise.resolve({ error: { code: 'denied', message: 'forbidden', status: 403 } }));
    await renderLoaded();
    await act(async () => {
      fireEvent.click(within(row('Rack Server')).getByText('Delete'));
    });
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({ title: 'Error deleting profile', description: 'forbidden', variant: 'destructive' }),
    );
    expect(service.listProfiles).toHaveBeenCalledTimes(1);
  });
});

describe('DeviceProfilesPage: create dialog', () => {
  it('opens, closes on Cancel, and offers only assignable roles with server as default', async () => {
    await renderLoaded();
    openCreateDialog();
    expect(screen.getByText('Create Device Profile')).toBeTruthy();
    const roleField = screen.getByTestId('form-select') as HTMLSelectElement;
    expect(roleField.value).toBe('server');
    expect([...roleField.options].map((o) => o.value)).not.toContain('unknown');
    fireEvent.click(screen.getByText('Cancel'));
    await waitFor(() => expect(screen.queryByText('Create Device Profile')).toBeNull());
  });

  it('creates a profile with an empty model as undefined and the default role', async () => {
    await renderLoaded();
    const form = openCreateDialog();
    fireEvent.change(screen.getByPlaceholderText('e.g., Production Server Profile'), { target: { value: 'New One' } });
    await act(async () => {
      fireEvent.submit(form);
    });
    expect(service.createProfile).toHaveBeenCalledWith({ profile: { name: 'New One', model: undefined, role: 'server' } });
    await waitFor(() => expect(screen.queryByText('Create Device Profile')).toBeNull());
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: 'Profile created' }));
    await waitFor(() => expect(service.listProfiles).toHaveBeenCalledTimes(2));
  });

  it('creates a profile with the chosen model and role', async () => {
    await renderLoaded();
    const form = openCreateDialog();
    fireEvent.change(screen.getByPlaceholderText('e.g., Production Server Profile'), { target: { value: 'GW' } });
    fireEvent.change(screen.getByPlaceholderText('Optional device model'), { target: { value: 'APU2' } });
    fireEvent.change(screen.getByTestId('form-select'), { target: { value: 'gateway' } });
    await act(async () => {
      fireEvent.submit(form);
    });
    expect(service.createProfile).toHaveBeenCalledWith({ profile: { name: 'GW', model: 'APU2', role: 'gateway' } });
  });

  it('disables the submit button while the create is in flight', async () => {
    service.createProfile.mockImplementation(() => new Promise(() => {}));
    await renderLoaded();
    const form = openCreateDialog();
    fireEvent.change(screen.getByPlaceholderText('e.g., Production Server Profile'), { target: { value: 'Slow' } });
    await act(async () => {
      fireEvent.submit(form);
    });
    expect((form.querySelector('button[type="submit"]') as HTMLButtonElement).disabled).toBe(true);
  });

  it('keeps the dialog open and toasts when the create fails, without an unhandled rejection', async () => {
    const unhandled = vi.fn();
    process.on('unhandledRejection', unhandled);
    try {
      service.createProfile.mockImplementation(() =>
        Promise.resolve({ error: { code: 'invalid', message: 'name taken', status: 400 } }),
      );
      await renderLoaded();
      const form = openCreateDialog();
      fireEvent.change(screen.getByPlaceholderText('e.g., Production Server Profile'), { target: { value: 'Dup' } });
      await act(async () => {
        fireEvent.submit(form);
      });
      await new Promise((r) => setTimeout(r, 20));
      expect(toast).toHaveBeenCalledWith({ title: 'Error creating profile', description: 'name taken', variant: 'destructive' });
      expect(screen.getByText('Create Device Profile')).toBeTruthy();
      expect(unhandled).not.toHaveBeenCalled();
    } finally {
      process.off('unhandledRejection', unhandled);
    }
  });

  it('rejects a role outside the SDK contract with a toast and no request', async () => {
    const unhandled = vi.fn();
    process.on('unhandledRejection', unhandled);
    try {
      await renderLoaded();
      const form = openCreateDialog();
      fireEvent.change(screen.getByPlaceholderText('e.g., Production Server Profile'), { target: { value: 'Bad' } });
      const roleField = screen.getByTestId('form-select') as HTMLSelectElement;
      const bogus = document.createElement('option');
      bogus.value = 'bogus';
      roleField.appendChild(bogus);
      roleField.value = 'bogus';
      await act(async () => {
        fireEvent.submit(form);
      });
      await new Promise((r) => setTimeout(r, 20));
      expect(service.createProfile).not.toHaveBeenCalled();
      expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: 'Error creating profile', variant: 'destructive' }));
      expect(unhandled).not.toHaveBeenCalled();
    } finally {
      process.off('unhandledRejection', unhandled);
    }
  });
});
