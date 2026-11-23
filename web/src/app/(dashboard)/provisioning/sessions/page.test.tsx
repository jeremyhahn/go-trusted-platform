import type { ReactNode } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import ProvisioningSessionsPage from './page';

const LIST_OP = 'GET /api/v1/provisioning/sessions';
const FULFILL_OP = 'POST /api/v1/provisioning/sessions/{sessionID}/fulfill';

type Answer = { enabled: boolean; reason?: string };

const { push, toast, refetch, sessionsState, sessionsArgs, caps } = vi.hoisted(() => ({
  push: vi.fn(),
  toast: vi.fn(),
  refetch: vi.fn(),
  sessionsState: { result: {} as Record<string, unknown> },
  sessionsArgs: [] as unknown[],
  caps: {
    loading: false,
    capability: (_op: string): { enabled: boolean; reason?: string } => ({ enabled: true }),
  },
}));

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push }),
}));

vi.mock('@/hooks', () => ({
  useToast: () => ({ toast }),
  useProvisioningSessions: (...args: unknown[]) => {
    sessionsArgs.push(args[0]);
    return sessionsState.result;
  },
  useDeviceTemplates: () => ({ templates: [], isLoading: false }),
}));

vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({
    loading: caps.loading,
    error: undefined,
    capability: (op: string) => caps.capability(op),
  }),
}));

vi.mock('@/components/ui/dropdown-menu', () => ({
  DropdownMenu: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DropdownMenuTrigger: ({ children }: { children: ReactNode }) => <>{children}</>,
  DropdownMenuContent: ({ children }: { children: ReactNode }) => <div role="menu">{children}</div>,
  DropdownMenuLabel: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DropdownMenuSeparator: () => <hr />,
  DropdownMenuItem: ({
    children,
    onClick,
    disabled,
    title,
  }: {
    children: ReactNode;
    onClick?: () => void;
    disabled?: boolean;
    title?: string;
  }) => (
    <div role="menuitem" onClick={onClick} aria-disabled={disabled} title={title}>
      {children}
    </div>
  ),
}));

const pending = {
  id: 'sess-1',
  ek_serial: 'EK-1',
  mac_address: '02:00:00:00:00:01',
  fulfilled: false,
  created_at: '2026-11-01T00:00:00Z',
  expires_at: '2099-01-01T00:00:00Z',
};

function setCaps(answers: Record<string, Answer>) {
  caps.capability = (op: string) => answers[op] ?? { enabled: true };
}

function setSessions(overrides: Record<string, unknown> = {}) {
  sessionsState.result = {
    sessions: [pending],
    isLoading: false,
    error: null,
    refetch,
    fulfill: { mutateAsync: vi.fn(), isLoading: false },
    ...overrides,
  };
}

beforeEach(() => {
  push.mockReset();
  toast.mockReset();
  refetch.mockReset();
  sessionsArgs.length = 0;
  caps.loading = false;
  setCaps({});
  setSessions();
});

afterEach(() => {
  cleanup();
});

function menuItem(name: string): HTMLElement {
  return screen.getByRole('menuitem', { name: new RegExp(name) });
}

describe('ProvisioningSessionsPage capability gate', () => {
  it('withholds Refresh when the server does not offer the session list', () => {
    setCaps({ [LIST_OP]: { enabled: false, reason: 'not-configured: provisioning' } });
    render(<ProvisioningSessionsPage />);

    const refresh = screen.getByRole('button', { name: /Refresh/ });
    expect((refresh as HTMLButtonElement).disabled).toBe(true);
    expect(refresh.getAttribute('title')).toBe('not-configured: provisioning');
    expect(refresh.getAttribute('data-capability-op')).toBe(LIST_OP);
    fireEvent.click(refresh);
    expect(refetch).not.toHaveBeenCalled();
  });

  it('withholds the row Assign Template when the server does not offer the fulfil', () => {
    setCaps({ [FULFILL_OP]: { enabled: false, reason: 'unimplemented' } });
    render(<ProvisioningSessionsPage />);

    const assign = menuItem('Assign Template');
    expect(assign.getAttribute('aria-disabled')).toBe('true');
    expect(assign.getAttribute('title')).toBe('unimplemented');
    fireEvent.click(assign);
    expect(screen.queryByText('Assign Template to Session')).toBeNull();

    fireEvent.click(menuItem('View Session'));
    expect(push).toHaveBeenCalledWith('/provisioning/sessions/sess-1');
  });

  it('shows the not-enabled notice, not a load error, when the server does not offer the list', () => {
    setCaps({ [LIST_OP]: { enabled: false, reason: 'not-configured: provisioning' } });
    setSessions({ error: new Error('boom') });
    render(<ProvisioningSessionsPage />);

    expect(screen.getByTestId('sessions-not-enabled').textContent).toContain(
      'not-configured: provisioning',
    );
    expect(screen.queryByRole('button', { name: /Retry/ })).toBeNull();
    expect(screen.queryByText('boom')).toBeNull();
  });

  it('leaves the controls on when the server offers them', () => {
    render(<ProvisioningSessionsPage />);
    expect(screen.getByTestId('provisioning-session-sess-1')).not.toBeNull();

    const refresh = screen.getByRole('button', { name: /Refresh/ });
    expect((refresh as HTMLButtonElement).disabled).toBe(false);
    expect(refresh.getAttribute('data-capability-enabled')).toBe('true');

    const assign = menuItem('Assign Template');
    expect(assign.getAttribute('aria-disabled')).not.toBe('true');
    fireEvent.click(assign);
    expect(screen.queryByText('Assign Template to Session')).not.toBeNull();
  });
});

function recordedEnabled(): unknown[] {
  return sessionsArgs.map((opts) => (opts as { enabled?: unknown } | undefined)?.enabled);
}

describe('ProvisioningSessionsPage list capability', () => {
  const listOff = { [LIST_OP]: { enabled: false, reason: 'not-configured: provisioning' } };

  it('does not ask for the list when the server does not offer it', () => {
    setCaps(listOff);
    render(<ProvisioningSessionsPage />);

    expect(sessionsArgs.length).toBeGreaterThan(0);
    expect(recordedEnabled().every((v) => v === false)).toBe(true);
  });

  it('shows the not-enabled notice with the reason', () => {
    setCaps(listOff);
    render(<ProvisioningSessionsPage />);

    expect(screen.getByTestId('sessions-not-enabled').textContent).toContain(
      'not-configured: provisioning',
    );
    expect(screen.queryByTestId('provisioning-session-sess-1')).toBeNull();
    expect(screen.queryByText('No provisioning sessions found')).toBeNull();
  });

  it('does not poll when the list is off', () => {
    vi.useFakeTimers();
    try {
      setCaps(listOff);
      render(<ProvisioningSessionsPage />);
      vi.advanceTimersByTime(30_000);
      expect(refetch).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });

  it('polls every 10 seconds when the list is on', () => {
    vi.useFakeTimers();
    try {
      render(<ProvisioningSessionsPage />);
      expect(sessionsArgs.length).toBeGreaterThan(0);
      expect(recordedEnabled().every((v) => v === true)).toBe(true);
      vi.advanceTimersByTime(10_000);
      expect(refetch).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it('waits for the capability answer before asking', () => {
    caps.loading = true;
    render(<ProvisioningSessionsPage />);

    expect(sessionsArgs.length).toBeGreaterThan(0);
    expect(recordedEnabled().every((v) => v === false)).toBe(true);
    expect(screen.queryByTestId('sessions-not-enabled')).toBeNull();
  });
});
