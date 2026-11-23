import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import MigrationsPage from './page';

// #2044: the migrations page prepares a receiver (PrepareMigration) and
// commits or aborts it after a confirm (FinalizeMigration) through the SDK
// client, each control behind the server's capability gate.

vi.mock('next/navigation', () => ({
  usePathname: () => '/compute/migrations',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const PREPARE_OP = 'POST /api/v1/compute/migrations/prepare';
const FINALIZE_OP = 'POST /api/v1/compute/migrations/{receiverId}/finalize';
const MIGRATION_OPS = [PREPARE_OP, FINALIZE_OP] as const;

// The server's capabilities listing: every migration op enabled except those in off.
function caps(off: string[] = []): Answer {
  const capabilities = MIGRATION_OPS.map((op) =>
    off.includes(op)
      ? { op, kind: 'route', enabled: false, reason: 'not-configured: compute' }
      : { op, kind: 'route', enabled: true },
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

function routes(off: string[] = [], prepare?: Answer): Record<string, Answer> {
  return {
    'GET /api/v1/capabilities': caps(off),
    'POST /api/v1/compute/migrations/prepare':
      prepare ?? ok({ status: { success: true }, receiverId: 'rx-1', port: 7443, tlsHostname: 'receiver.example.test' }),
    'POST /api/v1/compute/migrations/rx-1/finalize': ok({ status: { success: true } }),
  };
}

async function click(name: string) {
  // The gate holds the control disabled until the capabilities listing arrives.
  await waitFor(() => {
    expect((screen.getByRole('button', { name }) as HTMLButtonElement).disabled).toBe(false);
  });
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

function fillForm() {
  fireEvent.change(screen.getByLabelText('VM ID'), { target: { value: 'vm-1' } });
  fireEvent.change(screen.getByLabelText('VM name'), { target: { value: 'vm-one' } });
  fireEvent.change(screen.getByLabelText('Mode'), { target: { value: 'cold' } });
}

async function prepareReceiver() {
  fillForm();
  await click('Prepare receiver');
  await screen.findByTestId('migration-receiver');
}

function toastWith(text: string, variant?: string) {
  return screen
    .queryAllByTestId('toast')
    .find((t) => t.textContent?.includes(text) && (variant === undefined || t.getAttribute('data-variant') === variant));
}

describe('MigrationsPage', () => {
  it('prepares a receiver and shows its endpoint', async () => {
    const sent = stubControlPlane(routes());
    render(withControlPlane(<MigrationsPage />));

    await prepareReceiver();

    expect(sent).toContainEqual({
      method: 'POST',
      path: '/api/v1/compute/migrations/prepare',
      body: { vmId: 'vm-1', vmName: 'vm-one', mode: 'cold' },
    });
    const receiver = screen.getByTestId('migration-receiver');
    expect(receiver.textContent).toContain('rx-1');
    expect(receiver.textContent).toContain('7443');
    expect(receiver.textContent).toContain('receiver.example.test');
  });

  it('commits only after the confirm', async () => {
    const sent = stubControlPlane(routes());
    render(withControlPlane(<MigrationsPage />));
    await prepareReceiver();

    await click('Commit');
    expect(sent.some((r) => r.path.endsWith('/finalize'))).toBe(false);

    const dialog = screen.getByRole('dialog');
    expect(within(dialog).getByText('Commit migration?')).toBeDefined();
    await act(async () => {
      fireEvent.click(within(dialog).getByRole('button', { name: 'Commit' }));
    });

    await waitFor(() => {
      expect(sent).toContainEqual({
        method: 'POST',
        path: '/api/v1/compute/migrations/rx-1/finalize',
        body: { commit: true },
      });
    });
    await waitFor(() => {
      expect(toastWith('Migration committed', 'success')).toBeDefined();
    });
    await waitFor(() => {
      expect(screen.queryByTestId('migration-receiver')).toBeNull();
    });
  });

  it('aborts with commit false', async () => {
    const sent = stubControlPlane(routes());
    render(withControlPlane(<MigrationsPage />));
    await prepareReceiver();

    await click('Abort');
    expect(sent.some((r) => r.path.endsWith('/finalize'))).toBe(false);

    const dialog = screen.getByRole('dialog');
    expect(within(dialog).getByText('Abort migration?')).toBeDefined();
    await act(async () => {
      fireEvent.click(within(dialog).getByRole('button', { name: 'Abort' }));
    });

    await waitFor(() => {
      expect(sent).toContainEqual({
        method: 'POST',
        path: '/api/v1/compute/migrations/rx-1/finalize',
        body: { commit: false },
      });
    });
    await waitFor(() => {
      expect(toastWith('Migration aborted', 'success')).toBeDefined();
    });
  });

  it('withholds controls the server does not offer', async () => {
    const sent = stubControlPlane(routes([PREPARE_OP, FINALIZE_OP]));
    render(withControlPlane(<MigrationsPage />));
    fillForm();

    const button = screen.getByRole('button', { name: 'Prepare receiver' }) as HTMLButtonElement;
    await waitFor(() => {
      expect(button.getAttribute('data-capability-enabled')).toBe('false');
    });
    expect(button.disabled).toBe(true);
    expect(button.title).toBe('not-configured: compute');

    await act(async () => {
      fireEvent.click(button);
    });
    expect(sent.some((r) => r.path.startsWith('/api/v1/compute/migrations/'))).toBe(false);
  });

  it('shows a refused prepare as a destructive toast', async () => {
    stubControlPlane(routes([], refused(409, 'receiver busy')));
    render(withControlPlane(<MigrationsPage />));
    fillForm();

    await click('Prepare receiver');

    await waitFor(() => {
      const toast = toastWith('Migration request failed', 'destructive');
      expect(toast?.textContent).toContain('receiver busy');
    });
    expect(screen.queryByTestId('migration-receiver')).toBeNull();
  });
});
