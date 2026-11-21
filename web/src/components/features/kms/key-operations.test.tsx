import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { Key } from '@/types/security';
import { KeyOperations } from './key-operations';

const activeKey: Key = {
  id: 'key-1',
  name: 'payments',
  algorithm: 'AES-256',
  type: 'symmetric',
  status: 'active',
  createdAt: '2026-11-01T00:00:00Z',
  rotationCount: 0,
};

async function encrypt(plaintext: string) {
  fireEvent.change(screen.getByLabelText('Plaintext to Encrypt'), { target: { value: plaintext } });
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Encrypt' }));
  });
}

describe('KeyOperations errors', () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it('shows a refused encrypt instead of swallowing it', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const onEncrypt = vi.fn().mockRejectedValue(new Error('encrypt refused'));
    render(<KeyOperations keyItem={activeKey} onEncrypt={onEncrypt} />);

    await encrypt('hello');

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('encrypt refused');
    expect(onEncrypt).toHaveBeenCalledWith('hello');
  });

  it('shows a refused decrypt and no decrypted result', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const onEncrypt = vi.fn().mockResolvedValue('ct-1');
    const onDecrypt = vi.fn().mockRejectedValue(new Error('bad ciphertext'));
    render(<KeyOperations keyItem={activeKey} onEncrypt={onEncrypt} onDecrypt={onDecrypt} />);

    await encrypt('hello');
    expect(await screen.findByText('ct-1')).toBeDefined();

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Decrypt' }));
    });

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('bad ciphertext');
    expect(onDecrypt).toHaveBeenCalledWith('ct-1');
    expect(screen.queryByText('Decrypted Result')).toBeNull();
  });

  it('clears the error when the next attempt succeeds', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const onEncrypt = vi
      .fn()
      .mockRejectedValueOnce(new Error('encrypt refused'))
      .mockResolvedValueOnce('ct-2');
    render(<KeyOperations keyItem={activeKey} onEncrypt={onEncrypt} />);

    await encrypt('hello');
    expect((await screen.findByRole('alert')).textContent).toContain('encrypt refused');

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Encrypt' }));
    });

    expect(await screen.findByText('ct-2')).toBeDefined();
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('offers no operation on an inactive key', () => {
    render(<KeyOperations keyItem={{ ...activeKey, status: 'disabled' }} />);

    expect(screen.getByText('Key Inactive')).toBeDefined();
    expect(screen.queryByRole('button', { name: 'Encrypt' })).toBeNull();
  });
});
