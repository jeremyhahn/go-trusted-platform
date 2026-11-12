import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { TokenDisplay } from './token-display';

const secret = 'tok_0123456789abcdefghijKLMNOP';

function stubClipboard(writeText: (text: string) => Promise<void>) {
  Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
}

async function copy() {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Copy token' }));
  });
}

describe('TokenDisplay', () => {
  afterEach(() => {
    cleanup();
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('renders nothing while closed', () => {
    render(<TokenDisplay open={false} onOpenChange={vi.fn()} token={secret} tokenName="ci" />);

    expect(screen.queryByText('Token Generated Successfully')).toBeNull();
  });

  it('shows the name, the secret and the one-time warning', () => {
    render(<TokenDisplay open onOpenChange={vi.fn()} token={secret} tokenName="ci" />);

    expect(screen.getByText('Token Generated Successfully')).toBeDefined();
    expect(screen.getByText('Important: Save this token now')).toBeDefined();
    expect((screen.getByLabelText('Token Secret') as HTMLInputElement).value).toBe(secret);
    expect((screen.getByLabelText('Token Secret') as HTMLInputElement).readOnly).toBe(true);
    expect(screen.getByDisplayValue('ci')).toBeDefined();
  });

  it('shows only the first 20 characters of the secret in the usage example', () => {
    render(<TokenDisplay open onOpenChange={vi.fn()} token={secret} tokenName="ci" />);

    const example = screen.getByText(/Authorization: Bearer/);
    expect(example.textContent).toContain(`Bearer ${secret.substring(0, 20)}...`);
    expect(example.textContent).not.toContain(secret);
  });

  it('handles a secret shorter than 20 characters and an empty one', () => {
    const { rerender } = render(<TokenDisplay open onOpenChange={vi.fn()} token="short" tokenName="ci" />);
    expect(screen.getByText(/Authorization: Bearer/).textContent).toContain('Bearer short...');

    rerender(<TokenDisplay open onOpenChange={vi.fn()} token="" tokenName="" />);
    expect(screen.getByText(/Authorization: Bearer/).textContent).toContain('Bearer ...');
  });

  it('copies the secret and confirms it, then resets after two seconds', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    stubClipboard(writeText);
    vi.useFakeTimers();
    render(<TokenDisplay open onOpenChange={vi.fn()} token={secret} tokenName="ci" />);

    await copy();

    expect(writeText).toHaveBeenCalledWith(secret);
    expect(screen.getByText('Token copied to clipboard!')).toBeDefined();
    expect(screen.getByRole('button', { name: 'Copied' })).toBeDefined();

    act(() => {
      vi.advanceTimersByTime(2000);
    });
    expect(screen.queryByText('Token copied to clipboard!')).toBeNull();
    expect(screen.getByRole('button', { name: 'Copy token' })).toBeDefined();
  });

  it('logs a refused copy and does not claim it was copied', async () => {
    stubClipboard(vi.fn().mockRejectedValue(new Error('denied')));
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {});
    render(<TokenDisplay open onOpenChange={vi.fn()} token={secret} tokenName="ci" />);

    await copy();

    expect(logged).toHaveBeenCalledWith('Failed to copy token:', expect.any(Error));
    expect(screen.queryByText('Token copied to clipboard!')).toBeNull();
  });

  it('closes from the confirm button', () => {
    const onOpenChange = vi.fn();
    render(<TokenDisplay open onOpenChange={onOpenChange} token={secret} tokenName="ci" />);

    fireEvent.click(screen.getByRole('button', { name: "I've Saved the Token" }));

    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it('closes on Escape', () => {
    const onOpenChange = vi.fn();
    render(<TokenDisplay open onOpenChange={onOpenChange} token={secret} tokenName="ci" />);

    fireEvent.keyDown(document.activeElement ?? document.body, { key: 'Escape' });

    expect(onOpenChange).toHaveBeenCalledWith(false);
  });
});
