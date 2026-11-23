import type { ReactNode } from 'react';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import EABCredentialsPage from './page';

// #2024 Codex round 3 P1: an EAB validation verdict belongs to the exact
// credential it was computed for. A response for older inputs, or one that
// arrives after an edit, must not be shown beside the current inputs.

type Verdict = { valid: boolean };

const { validate } = vi.hoisted(() => ({ validate: vi.fn() }));
const listState = vi.hoisted(() => ({ credentials: [] as Array<Record<string, unknown>> }));
const caps = vi.hoisted(() => ({ capability: vi.fn() }));
const listArgs = vi.hoisted(() => ({ calls: [] as unknown[] }));

vi.mock('next/link', () => ({
  default: ({ href, children }: { href: string; children: ReactNode }) => (
    <a href={href}>{children}</a>
  ),
}));

vi.mock('@/hooks', () => ({
  useEAB: () => ({
    create: { mutateAsync: vi.fn() },
    revoke: { mutateAsync: vi.fn() },
    deleteCredential: { mutateAsync: vi.fn() },
    cleanupExpired: { mutateAsync: vi.fn() },
    validate: { mutateAsync: validate },
    service: { getByKeyId: vi.fn() },
  }),
  useEABList: (opts?: unknown) => {
    listArgs.calls.push(opts);
    return {
      data: { credentials: listState.credentials },
      error: null,
      isLoading: false,
      isFetching: false,
      refetch: vi.fn(),
    };
  },
}));

vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({ loading: false, error: undefined, capability: caps.capability }),
}));

beforeEach(() => {
  caps.capability.mockReset();
  caps.capability.mockImplementation(() => ({ enabled: true }));
  listState.credentials.length = 0;
  listArgs.calls.length = 0;
});

function deferred() {
  let resolve: (v: Verdict) => void = () => {};
  const promise = new Promise<Verdict>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

function fill(keyId: string, hmac: string) {
  fireEvent.change(screen.getByLabelText('Key ID', { selector: '#eab-validate-key-id' }), {
    target: { value: keyId },
  });
  fireEvent.change(screen.getByLabelText('HMAC Key'), { target: { value: hmac } });
}

async function clickValidate() {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Validate' }));
  });
}

function verdict() {
  return screen.queryByTestId('eab-validation')?.textContent ?? null;
}

describe('EABCredentialsPage validate verdict', () => {
  afterEach(() => {
    cleanup();
    validate.mockReset();
  });

  it('keeps the newest verdict when responses arrive in reverse order', async () => {
    const a = deferred();
    const b = deferred();
    validate.mockReturnValueOnce(a.promise).mockReturnValueOnce(b.promise);
    render(<EABCredentialsPage />);

    fill('key-a', 'hmac-a');
    await clickValidate();
    fill('key-b', 'hmac-b');
    await clickValidate();
    expect(validate).toHaveBeenNthCalledWith(2, { keyId: 'key-b', hmacKey: 'hmac-b' });

    await act(async () => {
      b.resolve({ valid: false });
    });
    expect(verdict()).toBe('Invalid');

    await act(async () => {
      a.resolve({ valid: true });
    });
    expect(verdict()).toBe('Invalid');
    expect(screen.getByTestId('eab-message').textContent).toBe('Credential is not valid');
  });

  it('clears the verdict when an input changes', async () => {
    validate.mockResolvedValue({ valid: true });
    render(<EABCredentialsPage />);
    fill('key-a', 'hmac-a');
    await clickValidate();
    expect(verdict()).toBe('Valid');

    fireEvent.change(screen.getByLabelText('HMAC Key'), { target: { value: 'other' } });
    expect(verdict()).toBeNull();
  });

  it('drops a verdict that arrives after an input changed', async () => {
    const a = deferred();
    validate.mockReturnValueOnce(a.promise);
    render(<EABCredentialsPage />);
    fill('key-a', 'hmac-a');
    await clickValidate();

    fireEvent.change(screen.getByLabelText('Key ID', { selector: '#eab-validate-key-id' }), {
      target: { value: 'key-b' },
    });
    await act(async () => {
      a.resolve({ valid: true });
    });
    expect(verdict()).toBeNull();
    expect(screen.queryByTestId('eab-message')).toBeNull();
  });
});

// #2050: every control on the list page is gated on the server's
// capabilities, named by the route's mux path template.
const CONTROLS: Array<[string, string]> = [
  ['Clean Up Expired', 'POST /api/v1/eab/credentials/cleanup'],
  ['Refresh', 'GET /api/v1/eab/credentials'],
  ['Revoke', 'POST /api/v1/eab/credentials/{id:[0-9]+}/revoke'],
  ['Delete', 'DELETE /api/v1/eab/credentials/{id:[0-9]+}'],
  ['Create', 'POST /api/v1/eab/credentials'],
  ['Validate', 'POST /api/v1/eab/credentials/validate'],
  ['Look Up', 'GET /api/v1/eab/credentials/key/{key}'],
];

function button_(name: string): HTMLButtonElement {
  return screen.getByRole('button', { name }) as HTMLButtonElement;
}

function addCredential() {
  listState.credentials.push({
    id: '1700000000000000001',
    keyId: 'kid-1',
    profileId: '1',
    status: 'EAB_CREDENTIAL_STATUS_ACTIVE',
    expiresAt: '2026-12-31T00:00:00Z',
  });
}

describe('EABCredentialsPage capability gate', () => {
  afterEach(() => {
    cleanup();
    validate.mockReset();
  });

  it('withholds each list-page control the server does not offer, with its reason', () => {
    addCredential();
    caps.capability.mockImplementation(() => ({ enabled: false, reason: 'not-configured: eab' }));
    render(<EABCredentialsPage />);
    for (const [name] of CONTROLS) {
      const button = button_(name);
      expect(button.disabled, name).toBe(true);
      expect(button.getAttribute('title'), name).toBe('not-configured: eab');
      expect(button.getAttribute('data-capability-enabled'), name).toBe('false');
    }
  });

  it('names the server op on each control', () => {
    addCredential();
    render(<EABCredentialsPage />);
    for (const [name, op] of CONTROLS) {
      const button = button_(name);
      expect(button.getAttribute('data-capability-op'), name).toBe(op);
      expect(button.getAttribute('data-capability-enabled'), name).toBe('true');
      expect(button.disabled, name).toBe(false);
    }
  });

  it('withholds only the op that is off', async () => {
    caps.capability.mockImplementation((op: string) =>
      op === 'POST /api/v1/eab/credentials/validate'
        ? { enabled: false, reason: 'not-configured: eab' }
        : { enabled: true },
    );
    render(<EABCredentialsPage />);
    expect(button_('Validate').disabled).toBe(true);
    expect(button_('Create').disabled).toBe(false);
    expect(button_('Look Up').disabled).toBe(false);
    fill('key-a', 'hmac-a');
    await clickValidate();
    expect(validate).not.toHaveBeenCalled();
  });
});

// #2050: the list read itself is gated on GET /api/v1/eab/credentials. When
// the server does not offer it, the page does not query and says why.
const LIST_OP = 'GET /api/v1/eab/credentials';

function listOff() {
  caps.capability.mockImplementation((op: string) =>
    op === LIST_OP ? { enabled: false, reason: 'not-configured: eab' } : { enabled: true },
  );
}

function lastListOpts(): { enabled?: boolean } | undefined {
  return listArgs.calls[listArgs.calls.length - 1] as { enabled?: boolean } | undefined;
}

describe('EABCredentialsPage list gate', () => {
  afterEach(cleanup);

  it('shows the not-enabled state with the reason and no table when the list is not offered', () => {
    listOff();
    addCredential();
    render(<EABCredentialsPage />);
    const state = screen.getByTestId('eab-list-not-enabled');
    expect(state.textContent).toContain('EAB credentials are not enabled');
    expect(state.textContent).toContain('not-configured: eab');
    expect(screen.queryByTestId('eab-row-1700000000000000001')).toBeNull();
  });

  it('does not enable the list query when the list is withheld', () => {
    listOff();
    render(<EABCredentialsPage />);
    expect(lastListOpts()?.enabled).toBe(false);
  });

  it('enables the list query and shows the table when the list is offered', () => {
    addCredential();
    render(<EABCredentialsPage />);
    expect(lastListOpts()?.enabled).toBe(true);
    expect(screen.getByTestId('eab-row-1700000000000000001')).not.toBeNull();
    expect(screen.queryByTestId('eab-list-not-enabled')).toBeNull();
  });
});
