import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { TokenForm } from './token-form';

// A Radix checkbox inside a form measures itself; jsdom has no ResizeObserver.
vi.stubGlobal(
  'ResizeObserver',
  class {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
);

function monthFromNow(): string {
  const d = new Date();
  d.setMonth(d.getMonth() + 1);
  return d.toISOString().split('T')[0];
}

function name(value: string) {
  fireEvent.change(screen.getByLabelText(/Token Name/), { target: { value } });
}

async function generate() {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Generate Token' }));
  });
}

describe('TokenForm', () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it('renders nothing while closed', () => {
    render(<TokenForm open={false} onOpenChange={vi.fn()} onSubmit={vi.fn()} />);

    expect(screen.queryByText('Generate API Token')).toBeNull();
  });

  it('opens empty, with the expiry a month ahead and every common scope offered', () => {
    render(<TokenForm open onOpenChange={vi.fn()} onSubmit={vi.fn()} />);

    expect((screen.getByLabelText(/Token Name/) as HTMLInputElement).value).toBe('');
    expect((screen.getByLabelText('Expiration Date') as HTMLInputElement).value).toBe(monthFromNow());
    for (const label of ['Read Users', 'Write Users', 'Read Roles', 'Write Roles', 'Read Tokens', 'Write Tokens', 'Admin']) {
      expect(screen.getByText(label)).toBeDefined();
    }
    expect(screen.getAllByRole('checkbox').every((b) => b.getAttribute('aria-checked') === 'false')).toBe(true);
    expect(screen.queryByText('Selected Scopes')).toBeNull();
  });

  it('refuses to submit without a name or a scope', async () => {
    const onSubmit = vi.fn();
    render(<TokenForm open onOpenChange={vi.fn()} onSubmit={onSubmit} />);

    name('   ');
    await generate();

    expect(screen.getByText('Token name is required')).toBeDefined();
    expect(screen.getByText('At least one scope is required')).toBeDefined();
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it('refuses an expiry that is not in the future', async () => {
    const onSubmit = vi.fn();
    render(<TokenForm open onOpenChange={vi.fn()} onSubmit={onSubmit} />);

    name('ci');
    fireEvent.click(screen.getByText('Read Users'));
    fireEvent.change(screen.getByLabelText('Expiration Date'), { target: { value: '2000-01-01' } });
    await generate();

    expect(screen.getByText('Expiration date must be in the future')).toBeDefined();
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it('submits the name, the chosen scopes and the expiry, then closes', async () => {
    const onSubmit = vi.fn().mockResolvedValue(undefined);
    const onOpenChange = vi.fn();
    render(<TokenForm open onOpenChange={onOpenChange} onSubmit={onSubmit} />);

    name('ci');
    fireEvent.click(screen.getByText('Read Users'));
    fireEvent.click(screen.getByText('Admin'));
    await generate();

    expect(onSubmit).toHaveBeenCalledWith({ name: 'ci', scopes: ['users:read', 'admin'], expiresAt: monthFromNow() });
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it('accepts a blank expiry as no expiration', async () => {
    const onSubmit = vi.fn();
    render(<TokenForm open onOpenChange={vi.fn()} onSubmit={onSubmit} />);

    name('forever');
    fireEvent.click(screen.getByText('Read Roles'));
    fireEvent.change(screen.getByLabelText('Expiration Date'), { target: { value: '' } });
    await generate();

    expect(onSubmit).toHaveBeenCalledWith({ name: 'forever', scopes: ['roles:read'], expiresAt: '' });
  });

  it('toggles a scope off again from its row and from its badge', () => {
    render(<TokenForm open onOpenChange={vi.fn()} onSubmit={vi.fn()} />);

    fireEvent.click(screen.getByText('Write Tokens'));
    expect(screen.getByText('tokens:write')).toBeDefined();
    fireEvent.click(screen.getByText('Write Tokens'));
    expect(screen.queryByText('tokens:write')).toBeNull();

    fireEvent.click(screen.getByText('Write Tokens'));
    fireEvent.click(screen.getByRole('button', { name: 'Remove tokens:write' }));
    expect(screen.queryByText('tokens:write')).toBeNull();
  });

  it('toggles a scope once from its own checkbox', () => {
    render(<TokenForm open onOpenChange={vi.fn()} onSubmit={vi.fn()} />);
    const admin = () => screen.getAllByRole('checkbox')[6];

    fireEvent.click(admin());
    expect(admin().getAttribute('aria-checked')).toBe('true');
    expect(screen.getByText('admin')).toBeDefined();

    fireEvent.click(admin());
    expect(admin().getAttribute('aria-checked')).toBe('false');
    expect(screen.queryByText('admin')).toBeNull();
  });

  it('adds a trimmed custom scope once, from the button and from Enter', async () => {
    const onSubmit = vi.fn();
    render(<TokenForm open onOpenChange={vi.fn()} onSubmit={onSubmit} />);
    const custom = screen.getByLabelText('Custom Scope') as HTMLInputElement;
    const add = screen.getByRole('button', { name: 'Add' });

    expect(add.hasAttribute('disabled')).toBe(true);
    fireEvent.change(custom, { target: { value: '   ' } });
    expect(add.hasAttribute('disabled')).toBe(true);

    fireEvent.change(custom, { target: { value: ' fleet:read ' } });
    fireEvent.click(add);
    expect(custom.value).toBe('');

    fireEvent.change(custom, { target: { value: 'fleet:read' } });
    fireEvent.keyPress(custom, { key: 'Enter', code: 'Enter', charCode: 13 });
    expect(screen.getAllByText('fleet:read')).toHaveLength(1);

    fireEvent.change(custom, { target: { value: 'fleet:write' } });
    fireEvent.keyPress(custom, { key: 'Enter', code: 'Enter', charCode: 13 });

    name('ci');
    await generate();
    expect(onSubmit).toHaveBeenCalledWith(expect.objectContaining({ scopes: ['fleet:read', 'fleet:write'] }));
  });

  it('stays open and logs when the submit is refused', async () => {
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {});
    const onOpenChange = vi.fn();
    render(<TokenForm open onOpenChange={onOpenChange} onSubmit={vi.fn().mockRejectedValue(new Error('quota'))} />);

    name('ci');
    fireEvent.click(screen.getByText('Admin'));
    await generate();

    expect(logged).toHaveBeenCalledWith('Form submission error:', expect.any(Error));
    expect(onOpenChange).not.toHaveBeenCalledWith(false);
  });

  it('cancels', () => {
    const onOpenChange = vi.fn();
    render(<TokenForm open onOpenChange={onOpenChange} onSubmit={vi.fn()} />);

    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));

    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it('while loading, disables the inputs, hides the badge remove buttons and says so', () => {
    const { rerender } = render(<TokenForm open onOpenChange={vi.fn()} onSubmit={vi.fn()} />);
    fireEvent.click(screen.getByText('Admin'));

    rerender(<TokenForm open onOpenChange={vi.fn()} onSubmit={vi.fn()} loading />);

    expect(screen.getByRole('button', { name: 'Generating...' }).hasAttribute('disabled')).toBe(true);
    expect(screen.getByRole('button', { name: 'Cancel' }).hasAttribute('disabled')).toBe(true);
    expect((screen.getByLabelText(/Token Name/) as HTMLInputElement).disabled).toBe(true);
    expect(screen.queryByRole('button', { name: 'Remove admin' })).toBeNull();
  });

  it('resets the form when it is opened again', () => {
    const { rerender } = render(<TokenForm open onOpenChange={vi.fn()} onSubmit={vi.fn()} />);
    name('old');
    fireEvent.click(screen.getByText('Admin'));

    rerender(<TokenForm open={false} onOpenChange={vi.fn()} onSubmit={vi.fn()} />);
    rerender(<TokenForm open onOpenChange={vi.fn()} onSubmit={vi.fn()} />);

    expect((screen.getByLabelText(/Token Name/) as HTMLInputElement).value).toBe('');
    expect(screen.queryByText('Selected Scopes')).toBeNull();
  });
});
