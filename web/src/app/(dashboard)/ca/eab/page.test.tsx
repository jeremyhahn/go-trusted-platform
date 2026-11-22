import type { ReactNode } from 'react';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import EABCredentialsPage from './page';

// #2024 Codex round 3 P1: an EAB validation verdict belongs to the exact
// credential it was computed for. A response for older inputs, or one that
// arrives after an edit, must not be shown beside the current inputs.

type Verdict = { valid: boolean };

const { validate } = vi.hoisted(() => ({ validate: vi.fn() }));

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
  useEABList: () => ({
    data: { credentials: [] },
    error: null,
    isLoading: false,
    isFetching: false,
    refetch: vi.fn(),
  }),
}));

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
