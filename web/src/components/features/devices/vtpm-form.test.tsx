import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { VTPMForm } from './vtpm-form';

const created = ok({ bundle: { id: 'b1', hostname: 'vm-one' } });

function fill(values: Partial<Record<'vTPM Name' | 'VM/Container ID' | 'VM/Container Name' | 'PCR Profile', string>>) {
  for (const [label, value] of Object.entries(values)) {
    fireEvent.change(screen.getByLabelText(label), { target: { value } });
  }
}

async function create() {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Create vTPM' }));
  });
}

describe('VTPMForm', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('renders the fields with the default PCR profile', () => {
    stubControlPlane({});
    render(withControlPlane(<VTPMForm />));

    expect((screen.getByLabelText('vTPM Name') as HTMLInputElement).value).toBe('');
    expect((screen.getByLabelText('PCR Profile') as HTMLInputElement).value).toBe('default');
    expect(screen.getByLabelText('Description (Optional)')).toBeDefined();
    expect(screen.queryByRole('button', { name: 'Cancel' })).toBeNull();
  });

  it('posts the VM name as the bundle hostname, then resets and reports success', async () => {
    const sent = stubControlPlane({ 'POST /api/v1/vtpm/bundles': created });
    const onSuccess = vi.fn();
    render(withControlPlane(<VTPMForm onSuccess={onSuccess} />));

    fill({ 'vTPM Name': 'vtpm-one', 'VM/Container ID': 'vm-1', 'VM/Container Name': 'vm-one' });
    await create();

    await waitFor(() => expect(onSuccess).toHaveBeenCalledTimes(1));
    expect(sent).toEqual([{ method: 'POST', path: '/api/v1/vtpm/bundles', body: { options: { hostname: 'vm-one' } } }]);
    expect(screen.getByText('Success: vTPM instance created successfully')).toBeDefined();
    expect((screen.getByLabelText('vTPM Name') as HTMLInputElement).value).toBe('');
  });

  it('sends nothing while a required field is empty', async () => {
    const sent = stubControlPlane({ 'POST /api/v1/vtpm/bundles': created });
    render(withControlPlane(<VTPMForm />));

    await create();

    expect(await screen.findByText('Name is required')).toBeDefined();
    expect(screen.getByText('VM ID is required')).toBeDefined();
    expect(screen.getByText('VM name is required')).toBeDefined();
    expect(sent).toEqual([]);
  });

  it('refuses a name longer than 100 characters', async () => {
    const sent = stubControlPlane({ 'POST /api/v1/vtpm/bundles': created });
    render(withControlPlane(<VTPMForm />));

    fill({ 'vTPM Name': 'x'.repeat(101), 'VM/Container ID': 'vm-1', 'VM/Container Name': 'vm-one' });
    await create();

    await waitFor(() => expect(screen.getByLabelText('vTPM Name').getAttribute('aria-invalid')).toBe('true'));
    expect(sent).toEqual([]);
  });

  it('accepts a name of exactly 100 characters', async () => {
    const sent = stubControlPlane({ 'POST /api/v1/vtpm/bundles': created });
    const onSuccess = vi.fn();
    render(withControlPlane(<VTPMForm onSuccess={onSuccess} />));

    fill({ 'vTPM Name': 'x'.repeat(100), 'VM/Container ID': 'vm-1', 'VM/Container Name': 'vm-one' });
    await create();

    await waitFor(() => expect(onSuccess).toHaveBeenCalledTimes(1));
    expect(sent).toHaveLength(1);
  });

  it('shows the REST refusal to the operator and keeps the input', async () => {
    stubControlPlane({ 'POST /api/v1/vtpm/bundles': refused(409, 'bundle vm-two already exists') });
    const onSuccess = vi.fn();
    render(withControlPlane(<VTPMForm onSuccess={onSuccess} />));

    fill({ 'vTPM Name': 'vtpm-two', 'VM/Container ID': 'vm-2', 'VM/Container Name': 'vm-two' });
    await create();

    const toast = await screen.findByText('Error: bundle vm-two already exists');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(onSuccess).not.toHaveBeenCalled();
    expect((screen.getByLabelText('vTPM Name') as HTMLInputElement).value).toBe('vtpm-two');
  });

  it('calls onCancel from the Cancel button without submitting', () => {
    const sent = stubControlPlane({});
    const onCancel = vi.fn();
    render(withControlPlane(<VTPMForm onCancel={onCancel} />));

    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(onCancel).toHaveBeenCalledTimes(1);
    expect(sent).toEqual([]);
  });
});
