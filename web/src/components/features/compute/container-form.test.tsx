import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { ContainerForm } from './container-form';

const CREATE = 'POST /api/v1/compute/containers';
const created = ok({ container: { id: 'c-1', name: 'web' } });

function mount(open = true) {
  const onOpenChange = vi.fn();
  const onSuccess = vi.fn();
  render(withControlPlane(<ContainerForm open={open} onOpenChange={onOpenChange} onSuccess={onSuccess} />));
  return { onOpenChange, onSuccess };
}

function type(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

async function submit() {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Create Container' }));
  });
}

describe('ContainerForm', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('renders nothing while closed', () => {
    stubControlPlane({});
    mount(false);

    expect(screen.queryByText('Create Container')).toBeNull();
    expect(screen.queryByLabelText('Name')).toBeNull();
  });

  it('shows the fields with their defaults when open', () => {
    stubControlPlane({});
    mount();

    expect(screen.getByRole('heading', { name: 'Create Container' })).toBeDefined();
    expect((screen.getByLabelText('Name') as HTMLInputElement).value).toBe('');
    expect((screen.getByLabelText('Image') as HTMLInputElement).value).toBe('');
    expect((screen.getByLabelText('Memory (MB)') as HTMLInputElement).value).toBe('512');
    expect((screen.getByLabelText('CPU Shares') as HTMLInputElement).value).toBe('512');
    expect(screen.queryByPlaceholderText('Host')).toBeNull();
  });

  it('posts the SDK request: command split on spaces, CPU shares as a fraction of 1024', async () => {
    const sent = stubControlPlane({ [CREATE]: created });
    const { onOpenChange, onSuccess } = mount();

    type('Name', 'web');
    type('Image', 'nginx:latest');
    type('Command (Optional)', 'nginx -g daemon');
    type('Memory (MB)', '1024');
    type('CPU Shares', '256');
    fireEvent.click(screen.getByRole('button', { name: 'Add Port' }));
    await submit();

    await waitFor(() => expect(onSuccess).toHaveBeenCalledTimes(1));
    expect(sent).toHaveLength(1);
    expect(sent[0].method).toBe('POST');
    expect(sent[0].path).toBe('/api/v1/compute/containers');
    expect(sent[0].body).toEqual({
      config: {
        name: 'web',
        image: 'nginx:latest',
        command: ['nginx', '-g', 'daemon'],
        ports: [{ containerPort: 80, hostPort: 8080, protocol: 'tcp' }],
        resources: { maxMemoryMb: 1024, maxCpus: 0.25 },
      },
    });
    expect(onOpenChange).toHaveBeenCalledWith(false);
    expect(screen.getByText('Success: Container created successfully')).toBeDefined();
  });

  it('sends no command when the command field is empty', async () => {
    const sent = stubControlPlane({ [CREATE]: created });
    const { onSuccess } = mount();

    type('Name', 'web');
    type('Image', 'nginx');
    await submit();

    await waitFor(() => expect(onSuccess).toHaveBeenCalledTimes(1));
    const config = (sent[0].body as { config: Record<string, unknown> }).config;
    expect(config.command).toBeUndefined();
    expect(config.ports).toEqual([]);
    expect(config.resources).toEqual({ maxMemoryMb: 512, maxCpus: 0.5 });
  });

  it('adds and removes port mappings', () => {
    stubControlPlane({});
    mount();

    fireEvent.click(screen.getByRole('button', { name: 'Add Port' }));
    fireEvent.click(screen.getByRole('button', { name: 'Add Port' }));
    expect(screen.getAllByPlaceholderText('Host')).toHaveLength(2);
    expect((screen.getAllByPlaceholderText('Host')[0] as HTMLInputElement).value).toBe('8080');
    expect((screen.getAllByPlaceholderText('Container')[0] as HTMLInputElement).value).toBe('80');

    const before = screen.getAllByRole('button').length;
    const removeButtons = screen
      .getAllByRole('button')
      .filter((b) => b.getAttribute('type') === 'button' && b.textContent === '');
    fireEvent.click(removeButtons[0]);
    expect(screen.getAllByPlaceholderText('Host')).toHaveLength(1);
    expect(screen.getAllByRole('button').length).toBe(before - 1);
  });

  it('sends nothing and names the missing fields without a name and image', async () => {
    const sent = stubControlPlane({ [CREATE]: created });
    const { onSuccess } = mount();

    await submit();

    expect(await screen.findByText('Name is required')).toBeDefined();
    expect(screen.getByText('Image is required')).toBeDefined();
    expect(sent).toEqual([]);
    expect(onSuccess).not.toHaveBeenCalled();
  });

  it('refuses a name over 64 characters', async () => {
    const sent = stubControlPlane({ [CREATE]: created });
    mount();

    type('Name', 'n'.repeat(65));
    type('Image', 'nginx');
    await submit();

    expect(await screen.findByText('Name too long')).toBeDefined();
    expect(sent).toEqual([]);
  });

  it('refuses memory under 128 MB and CPU shares over 1024', async () => {
    const sent = stubControlPlane({ [CREATE]: created });
    const { onSuccess } = mount();

    type('Name', 'web');
    type('Image', 'nginx');
    type('Memory (MB)', '64');
    type('CPU Shares', '2048');
    await submit();

    const memory = screen.getByLabelText('Memory (MB)') as HTMLInputElement;
    const cpu = screen.getByLabelText('CPU Shares') as HTMLInputElement;
    expect(memory.validity.rangeUnderflow).toBe(true);
    expect(cpu.validity.rangeOverflow).toBe(true);
    await new Promise((r) => setTimeout(r, 50));
    expect(sent).toEqual([]);
    expect(onSuccess).not.toHaveBeenCalled();
  });

  it('refuses a port outside 1-65535', async () => {
    const sent = stubControlPlane({ [CREATE]: created });
    mount();

    type('Name', 'web');
    type('Image', 'nginx');
    fireEvent.click(screen.getByRole('button', { name: 'Add Port' }));
    fireEvent.change(screen.getByPlaceholderText('Host'), { target: { value: '70000' } });
    await submit();

    await waitFor(() =>
      expect(screen.getByPlaceholderText('Host').getAttribute('aria-invalid')).toBe('true')
    );
    expect(sent).toEqual([]);
  });

  it('shows the REST refusal and keeps the dialog open', async () => {
    stubControlPlane({ [CREATE]: refused(409, 'container web already exists') });
    const { onOpenChange, onSuccess } = mount();

    type('Name', 'web');
    type('Image', 'nginx');
    await submit();

    const toast = await screen.findByText('Error: Failed to create container: container web already exists');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(onSuccess).not.toHaveBeenCalled();
    expect(onOpenChange).not.toHaveBeenCalled();
  });

  it('closes on Cancel without a request', () => {
    const sent = stubControlPlane({});
    const { onOpenChange } = mount();

    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));

    expect(onOpenChange).toHaveBeenCalledWith(false);
    expect(sent).toEqual([]);
  });
});
