import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

// The write controls are capability-gated (#2054); these cases run with
// every op offered.
vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({
    loading: false,
    error: undefined,
    capability: () => ({ enabled: true }),
  }),
}));

import { AppRenameForm } from './app-rename-form';

describe('AppRenameForm', () => {
  afterEach(() => {
    cleanup();
  });

  it('disables Save while the input equals the current name or is blank', () => {
    render(<AppRenameForm name="portal" saving={false} onSave={vi.fn()} />);
    const save = screen.getByRole('button', { name: /save/i });
    expect((save as HTMLButtonElement).disabled).toBe(true);

    const input = screen.getByLabelText(/application name/i);
    fireEvent.change(input, { target: { value: '   ' } });
    expect((save as HTMLButtonElement).disabled).toBe(true);

    fireEvent.change(input, { target: { value: 'portal' } });
    expect((save as HTMLButtonElement).disabled).toBe(true);
  });

  it('calls onSave once with the trimmed new name', () => {
    const onSave = vi.fn();
    render(<AppRenameForm name="portal" saving={false} onSave={onSave} />);
    const input = screen.getByLabelText(/application name/i);
    fireEvent.change(input, { target: { value: '  billing portal  ' } });

    const save = screen.getByRole('button', { name: /save/i });
    expect((save as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(save);

    expect(onSave).toHaveBeenCalledTimes(1);
    expect(onSave).toHaveBeenCalledWith('billing portal');
  });

  it('disables Save while saving', () => {
    render(<AppRenameForm name="portal" saving onSave={vi.fn()} />);
    const input = screen.getByLabelText(/application name/i);
    fireEvent.change(input, { target: { value: 'billing' } });
    expect((screen.getByRole('button', { name: /sav/i }) as HTMLButtonElement).disabled).toBe(true);
  });
});
