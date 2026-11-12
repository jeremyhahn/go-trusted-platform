import type { ReactNode } from 'react';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { IssueCertForm } from './issue-cert-form';

// Radix Select needs pointer capture and layout that jsdom lacks, so the
// select renders as a native <select>. The value, its change handler and the
// disabled state are the form's own; only the popup is replaced.
vi.mock('@/components/ui/select', () => ({
  Select: ({
    children,
    value,
    onValueChange,
    disabled,
  }: {
    children: ReactNode;
    value?: string;
    onValueChange?: (v: string) => void;
    disabled?: boolean;
  }) => (
    <select value={value} disabled={disabled} onChange={(e) => onValueChange?.(e.target.value)}>
      {children}
    </select>
  ),
  SelectTrigger: () => null,
  SelectValue: () => null,
  SelectContent: ({ children }: { children: ReactNode }) => <>{children}</>,
  SelectItem: ({ children, value }: { children: ReactNode; value: string }) => (
    <option value={value}>{children}</option>
  ),
}));

function subject(): HTMLInputElement {
  return screen.getByPlaceholderText('CN=example.com,O=Organization,C=US') as HTMLInputElement;
}

function validity(): HTMLInputElement {
  return screen.getByRole('spinbutton') as HTMLInputElement;
}

function selects(): HTMLSelectElement[] {
  return screen.getAllByRole('combobox') as HTMLSelectElement[];
}

function form(): HTMLFormElement {
  return subject().closest('form')!;
}

async function submit() {
  await act(async () => {
    fireEvent.submit(form());
  });
}

describe('IssueCertForm', () => {
  afterEach(() => cleanup());

  it('starts with a leaf, RSA-2048, 365-day request and Issue disabled', () => {
    render(<IssueCertForm onSubmit={vi.fn()} />);
    expect(subject().value).toBe('');
    const [type, alg] = selects();
    expect(type.value).toBe('leaf');
    expect(alg.value).toBe('RSA-2048');
    expect(validity().value).toBe('365');
    const issue = screen.getByRole('button', { name: 'Issue Certificate' });
    expect(issue.hasAttribute('disabled')).toBe(true);
  });

  it('refuses an empty subject through the form constraints', () => {
    render(<IssueCertForm onSubmit={vi.fn()} />);
    expect(subject().required).toBe(true);
    expect(form().checkValidity()).toBe(false);
  });

  it('enables Issue once a subject is typed', () => {
    render(<IssueCertForm onSubmit={vi.fn()} />);
    fireEvent.change(subject(), { target: { value: 'CN=device-7' } });
    expect(screen.getByRole('button', { name: 'Issue Certificate' }).hasAttribute('disabled')).toBe(false);
    expect(form().checkValidity()).toBe(true);
  });

  it('submits the defaults with the typed subject', async () => {
    const onSubmit = vi.fn();
    render(<IssueCertForm onSubmit={onSubmit} />);
    fireEvent.change(subject(), { target: { value: 'CN=device-7' } });
    await submit();
    expect(onSubmit).toHaveBeenCalledWith({
      subject: 'CN=device-7',
      type: 'leaf',
      validityDays: 365,
      keyAlgorithm: 'RSA-2048',
    });
  });

  it('submits the chosen type, algorithm and validity', async () => {
    const onSubmit = vi.fn();
    render(<IssueCertForm onSubmit={onSubmit} />);
    fireEvent.change(subject(), { target: { value: 'CN=Intermediate CA' } });
    const [type, alg] = selects();
    fireEvent.change(type, { target: { value: 'intermediate' } });
    fireEvent.change(alg, { target: { value: 'ECDSA-P384' } });
    fireEvent.change(validity(), { target: { value: '730' } });
    await submit();
    expect(onSubmit).toHaveBeenCalledWith({
      subject: 'CN=Intermediate CA',
      type: 'intermediate',
      validityDays: 730,
      keyAlgorithm: 'ECDSA-P384',
    });
  });

  it('offers every type and algorithm', () => {
    render(<IssueCertForm onSubmit={vi.fn()} />);
    const [type, alg] = selects();
    expect(Array.from(type.options).map((o) => o.value)).toEqual(['root', 'intermediate', 'leaf']);
    expect(Array.from(alg.options).map((o) => o.value)).toEqual([
      'RSA-2048',
      'RSA-4096',
      'ECDSA-P256',
      'ECDSA-P384',
    ]);
  });

  it('bounds the validity to 1..3650 days', () => {
    render(<IssueCertForm onSubmit={vi.fn()} />);
    fireEvent.change(subject(), { target: { value: 'CN=device-7' } });
    expect(validity().min).toBe('1');
    expect(validity().max).toBe('3650');
    fireEvent.change(validity(), { target: { value: '0' } });
    expect(form().checkValidity()).toBe(false);
    fireEvent.change(validity(), { target: { value: '3651' } });
    expect(form().checkValidity()).toBe(false);
    fireEvent.change(validity(), { target: { value: '3650' } });
    expect(form().checkValidity()).toBe(true);
  });

  it('refuses a cleared validity through the form constraints', () => {
    render(<IssueCertForm onSubmit={vi.fn()} />);
    fireEvent.change(subject(), { target: { value: 'CN=device-7' } });
    fireEvent.change(validity(), { target: { value: '' } });
    expect(validity().required).toBe(true);
    expect(form().checkValidity()).toBe(false);
  });

  it('awaits an async onSubmit', async () => {
    let resolve: () => void = () => {};
    const onSubmit = vi.fn(() => new Promise<void>((r) => (resolve = r)));
    render(<IssueCertForm onSubmit={onSubmit} />);
    fireEvent.change(subject(), { target: { value: 'CN=device-7' } });
    await submit();
    expect(onSubmit).toHaveBeenCalledTimes(1);
    await act(async () => resolve());
  });

  it('disables every field and shows Issuing... while loading', () => {
    render(<IssueCertForm onSubmit={vi.fn()} loading />);
    expect(subject().disabled).toBe(true);
    expect(validity().disabled).toBe(true);
    selects().forEach((s) => expect(s.disabled).toBe(true));
    const button = screen.getByRole('button', { name: 'Issuing...' });
    expect(button.hasAttribute('disabled')).toBe(true);
    expect(screen.queryByRole('button', { name: 'Issue Certificate' })).toBeNull();
  });
});
