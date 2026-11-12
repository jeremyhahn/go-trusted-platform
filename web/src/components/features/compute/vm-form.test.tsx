import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { VMForm } from './vm-form';

const CREATE = 'POST /api/v1/compute/vms';
const created = ok({ vm: { id: 'vm-1', name: 'build' } });

function mount(open = true) {
  const onOpenChange = vi.fn();
  const onSuccess = vi.fn();
  render(withControlPlane(<VMForm open={open} onOpenChange={onOpenChange} onSuccess={onSuccess} />));
  return { onOpenChange, onSuccess };
}

function type(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

function input(label: string) {
  return screen.getByLabelText(label) as HTMLInputElement;
}

async function submit() {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Create VM' }));
  });
}

describe('VMForm', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('renders nothing while closed', () => {
    stubControlPlane({});
    mount(false);

    expect(screen.queryByText('Create Virtual Machine')).toBeNull();
    expect(screen.queryByLabelText('Name')).toBeNull();
  });

  it('shows the fields with their defaults when open', () => {
    stubControlPlane({});
    mount();

    expect(screen.getByRole('heading', { name: 'Create Virtual Machine' })).toBeDefined();
    expect(input('Name').value).toBe('');
    expect(input('Description').value).toBe('');
    expect(input('vCPUs').value).toBe('2');
    expect(input('Memory (MB)').value).toBe('2048');
    expect(input('Storage (MB)').value).toBe('20480');
    expect(screen.getByRole('combobox').textContent).toContain('Linux');
  });

  it('posts the SDK request: one qcow2 disk named after the VM, storage rounded up to whole GB', async () => {
    const sent = stubControlPlane({ [CREATE]: created });
    const { onOpenChange, onSuccess } = mount();

    type('Name', 'build');
    type('Description', 'CI builder');
    type('vCPUs', '4');
    type('Memory (MB)', '4096');
    type('Storage (MB)', '1500');
    await submit();

    await waitFor(() => expect(onSuccess).toHaveBeenCalledTimes(1));
    expect(sent).toHaveLength(1);
    expect(sent[0].method).toBe('POST');
    expect(sent[0].path).toBe('/api/v1/compute/vms');
    expect(sent[0].body).toEqual({
      config: {
        name: 'build',
        cpu: { cores: 4 },
        memory: { sizeMb: 4096 },
        disks: [{ path: '/data/build.qcow2', type: 'DISK_TYPE_QCOW2', sizeGb: 2 }],
        networks: [],
      },
    });
    expect(onOpenChange).toHaveBeenCalledWith(false);
    expect(screen.getByText('Success: Virtual machine created successfully')).toBeDefined();
  });

  it('resets the fields after a create', async () => {
    stubControlPlane({ [CREATE]: created });
    const { onSuccess } = mount();

    type('Name', 'build');
    type('vCPUs', '8');
    await submit();

    await waitFor(() => expect(onSuccess).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(input('Name').value).toBe(''));
    expect(input('vCPUs').value).toBe('2');
  });

  it('sends nothing and names the missing name', async () => {
    const sent = stubControlPlane({ [CREATE]: created });
    const { onSuccess } = mount();

    await submit();

    expect(await screen.findByText('Name is required')).toBeDefined();
    expect(sent).toEqual([]);
    expect(onSuccess).not.toHaveBeenCalled();
  });

  it('refuses a name over 64 characters', async () => {
    const sent = stubControlPlane({ [CREATE]: created });
    mount();

    type('Name', 'v'.repeat(65));
    await submit();

    expect(await screen.findByText('Name too long')).toBeDefined();
    expect(sent).toEqual([]);
  });

  it('refuses vCPUs, memory and storage under their minimums', async () => {
    const sent = stubControlPlane({ [CREATE]: created });
    mount();

    type('Name', 'build');
    type('vCPUs', '0');
    type('Memory (MB)', '256');
    type('Storage (MB)', '512');
    await submit();

    expect(input('vCPUs').validity.rangeUnderflow).toBe(true);
    expect(input('Memory (MB)').validity.rangeUnderflow).toBe(true);
    expect(input('Storage (MB)').validity.rangeUnderflow).toBe(true);
    await new Promise((r) => setTimeout(r, 50));
    expect(sent).toEqual([]);
  });

  it('refuses more than 64 vCPUs', async () => {
    const sent = stubControlPlane({ [CREATE]: created });
    mount();

    type('Name', 'build');
    type('vCPUs', '65');
    await submit();

    expect(input('vCPUs').validity.rangeOverflow).toBe(true);
    await new Promise((r) => setTimeout(r, 50));
    expect(sent).toEqual([]);
  });

  it('refuses memory and storage over their schema maximums', async () => {
    const sent = stubControlPlane({ [CREATE]: created });
    mount();

    type('Name', 'build');
    type('Memory (MB)', '524289');
    type('Storage (MB)', '10485761');
    await submit();

    await waitFor(() => expect(input('Memory (MB)').getAttribute('aria-invalid')).toBe('true'));
    expect(input('Storage (MB)').getAttribute('aria-invalid')).toBe('true');
    expect(sent).toEqual([]);
  });

  it('shows the REST refusal and keeps the dialog open', async () => {
    stubControlPlane({ [CREATE]: refused(507, 'no host has room for 4 vCPUs') });
    const { onOpenChange, onSuccess } = mount();

    type('Name', 'build');
    await submit();

    const toast = await screen.findByText('Error: Failed to create VM: no host has room for 4 vCPUs');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(onSuccess).not.toHaveBeenCalled();
    expect(onOpenChange).not.toHaveBeenCalled();
    expect(input('Name').value).toBe('build');
  });

  it('closes on Cancel without a request', () => {
    const sent = stubControlPlane({});
    const { onOpenChange } = mount();

    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));

    expect(onOpenChange).toHaveBeenCalledWith(false);
    expect(sent).toEqual([]);
  });
});
