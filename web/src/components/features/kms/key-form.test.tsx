import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { KeyForm } from './key-form';

async function typeName(value: string) {
  await act(async () => {
    fireEvent.change(screen.getByLabelText(/Key Name/), { target: { value } });
  });
}

async function clickGenerate() {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Generate Key' }));
  });
}

describe('KeyForm submit errors', () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it('shows a refused generate and keeps the typed name', async () => {
    const onSubmit = vi.fn().mockRejectedValueOnce(new Error('key name already exists'));
    render(<KeyForm onSubmit={onSubmit} />);

    await typeName('dup-key');
    await clickGenerate();

    expect(screen.getByRole('alert').textContent).toContain('key name already exists');
    expect((screen.getByLabelText(/Key Name/) as HTMLInputElement).value).toBe('dup-key');
    expect(onSubmit).toHaveBeenCalledTimes(1);
    expect(onSubmit).toHaveBeenCalledWith({ name: 'dup-key', algorithm: 'AES-256', metadata: {} });
  });

  it('clears the alert when a later generate succeeds', async () => {
    const onSubmit = vi
      .fn()
      .mockRejectedValueOnce(new Error('key name already exists'))
      .mockResolvedValueOnce(undefined);
    render(<KeyForm onSubmit={onSubmit} />);

    await typeName('dup-key');
    await clickGenerate();
    await clickGenerate();

    expect(onSubmit).toHaveBeenCalledTimes(2);
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('sends the added metadata with the generate', async () => {
    const onSubmit = vi.fn().mockResolvedValueOnce(undefined);
    render(<KeyForm onSubmit={onSubmit} />);

    await typeName('meta-key');
    await act(async () => {
      fireEvent.change(screen.getByPlaceholderText('Key'), { target: { value: 'env' } });
      fireEvent.change(screen.getByPlaceholderText('Value'), { target: { value: 'prod' } });
    });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Add' }));
    });
    await clickGenerate();

    expect(onSubmit).toHaveBeenCalledTimes(1);
    expect(onSubmit).toHaveBeenCalledWith({
      name: 'meta-key',
      algorithm: 'AES-256',
      metadata: { env: 'prod' },
    });
  });
});
