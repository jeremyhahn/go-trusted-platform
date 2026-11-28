import type { ReactNode } from 'react';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import TokensPage from './page';

// The API credentials page drives the real SDK client through the stubbed
// fetch (#2035, Codex round 4 on #2341): RegisterApp and RotateAppSecret
// answer the snake_case AppResponse / RotateSecretResponse under the
// envelope's payload, and the page must show that one-time secret in the
// Application Credentials dialog.

vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({ tenantId: 't-1', isLoading: false }),
}));

// The Radix row menu does not open in jsdom; the row actions call
// action.onClick(row) from DropdownMenuItem's onClick, so a flat menu serves.
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

const APPS = '/api/v1/iam/tenants/t-1/apps';

function routes() {
  return {
    [`GET ${APPS}`]: ok({ apps: [{ clientId: 'app-1', name: 'demo', grantTypes: ['client_credentials'] }] }),
    [`POST ${APPS}`]: ok({
      client_id: 'app-2',
      client_secret: 'secret-new',
      name: 'fresh',
      grant_types: ['client_credentials'],
    }),
    [`POST ${APPS}/app-1/rotate-secret`]: ok({ client_id: 'app-1', name: 'demo', client_secret: 'secret-rotated' }),
  };
}

async function credentialsDialog(): Promise<HTMLElement> {
  const title = await screen.findByText('Application Credentials');
  const dialog = title.closest('[role="dialog"]');
  expect(dialog).not.toBeNull();
  return dialog as HTMLElement;
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('API credentials page', () => {
  it('shows the one-time secret after a register', async () => {
    const sent = stubControlPlane(routes());
    render(withControlPlane(<TokensPage />));
    await screen.findByText('demo');

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /Register Application/ }));
    });
    fireEvent.change(await screen.findByLabelText('Application Name'), { target: { value: 'fresh' } });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Register' }));
    });

    await waitFor(() => expect(sent.some((r) => r.method === 'POST' && r.path === APPS)).toBe(true));
    const dialog = await credentialsDialog();
    expect(within(dialog).getByText('secret-new')).toBeTruthy();
    expect(within(dialog).getByText('app-2')).toBeTruthy();
  });

  it('shows the rotated secret', async () => {
    const sent = stubControlPlane(routes());
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    render(withControlPlane(<TokensPage />));
    await screen.findByText('demo');

    await act(async () => {
      fireEvent.click(screen.getByRole('menuitem', { name: 'Rotate Secret' }));
    });

    await waitFor(() =>
      expect(sent.some((r) => r.method === 'POST' && r.path === `${APPS}/app-1/rotate-secret`)).toBe(true),
    );
    const dialog = await credentialsDialog();
    expect(within(dialog).getByText('secret-rotated')).toBeTruthy();
    expect(within(dialog).getByText('app-1')).toBeTruthy();
  });

  it('copies the one-time secret', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    stubControlPlane(routes());
    render(withControlPlane(<TokensPage />));
    await screen.findByText('demo');

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /Register Application/ }));
    });
    fireEvent.change(await screen.findByLabelText('Application Name'), { target: { value: 'fresh' } });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Register' }));
    });

    const dialog = await credentialsDialog();
    const secret = within(dialog).getByText('secret-new');
    await act(async () => {
      fireEvent.click(within(secret.parentElement as HTMLElement).getByRole('button'));
    });
    expect(writeText).toHaveBeenCalledTimes(1);
    expect(writeText).toHaveBeenCalledWith('secret-new');
  });
});
