import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const { toast } = vi.hoisted(() => ({ toast: vi.fn() }));

vi.mock('@/hooks/use-toast', () => ({
  useToast: () => ({ toast }),
}));

import { ConfigSection } from './config-section';

function deferred() {
  let resolve!: () => void;
  let reject!: (err: unknown) => void;
  const promise = new Promise<void>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

describe('ConfigSection', () => {
  beforeEach(() => {
    toast.mockReset();
  });
  afterEach(cleanup);

  it('renders the title, the description and the children', () => {
    render(
      <ConfigSection title="General" description="Platform settings" onSave={vi.fn()}>
        <span>child field</span>
      </ConfigSection>,
    );
    expect(screen.getByText('General')).toBeDefined();
    expect(screen.getByText('Platform settings')).toBeDefined();
    expect(screen.getByText('child field')).toBeDefined();
    expect(screen.getByRole('button', { name: /Save/ })).toBeDefined();
  });

  it('omits the description when none is given', () => {
    const { container } = render(
      <ConfigSection title="General" onSave={vi.fn()}>
        <span>x</span>
      </ConfigSection>,
    );
    expect(screen.getByText('General')).toBeDefined();
    expect(container.querySelector('p')).toBeNull();
  });

  it('collects the form fields, converting checkboxes and numbers', async () => {
    const onSave = vi.fn().mockResolvedValue(undefined);
    render(
      <ConfigSection title="General" onSave={onSave}>
        <input name="name" defaultValue="edge-01" />
        <input name="port" defaultValue="8443" />
        <input name="ratio" defaultValue="0.5" />
        <input type="checkbox" name="enabled" defaultChecked />
        <input type="checkbox" name="unchecked" />
        <input name="flag" defaultValue="off" />
      </ConfigSection>,
    );
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /Save/ }));
    });
    expect(onSave).toHaveBeenCalledTimes(1);
    expect(onSave.mock.calls[0][0]).toEqual({
      name: 'edge-01',
      port: 8443,
      ratio: 0.5,
      enabled: true,
      flag: false,
    });
    expect(toast).toHaveBeenCalledWith({
      title: 'Settings saved',
      description: 'Your configuration has been updated successfully.',
    });
  });

  it('keeps an empty or blank text field as a string, not 0', async () => {
    const onSave = vi.fn().mockResolvedValue(undefined);
    render(
      <ConfigSection title="General" onSave={onSave}>
        <input name="empty" defaultValue="" />
        <input name="blank" defaultValue="  " />
      </ConfigSection>,
    );
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /Save/ }));
    });
    expect(onSave.mock.calls[0][0]).toEqual({ empty: '', blank: '  ' });
  });

  it('saves an empty object when the form has no fields', async () => {
    const onSave = vi.fn().mockResolvedValue(undefined);
    render(
      <ConfigSection title="General" onSave={onSave}>
        <span>no fields</span>
      </ConfigSection>,
    );
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /Save/ }));
    });
    expect(onSave).toHaveBeenCalledWith({});
  });

  it('disables the button and shows Saving... while the save is pending', async () => {
    const d = deferred();
    const onSave = vi.fn().mockReturnValue(d.promise);
    render(
      <ConfigSection title="General" onSave={onSave}>
        <input name="a" defaultValue="x" />
      </ConfigSection>,
    );
    fireEvent.click(screen.getByRole('button', { name: /Save/ }));
    const busy = await screen.findByRole('button', { name: /Saving\.\.\./ });
    expect((busy as HTMLButtonElement).disabled).toBe(true);
    await act(async () => {
      d.resolve();
    });
    const idle = screen.getByRole('button', { name: /Save/ });
    expect((idle as HTMLButtonElement).disabled).toBe(false);
    expect(screen.queryByText('Saving...')).toBeNull();
  });

  it('shows a destructive toast with the error message when the save fails', async () => {
    const onSave = vi.fn().mockRejectedValue(new Error('config reload refused'));
    render(
      <ConfigSection title="General" onSave={onSave}>
        <input name="a" defaultValue="x" />
      </ConfigSection>,
    );
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /Save/ }));
    });
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({
        title: 'Error saving settings',
        description: 'config reload refused',
        variant: 'destructive',
      }),
    );
    expect(toast).toHaveBeenCalledTimes(1);
    expect((screen.getByRole('button', { name: /Save/ }) as HTMLButtonElement).disabled).toBe(false);
  });

  it('uses a generic message when the save rejects with a non-Error', async () => {
    const onSave = vi.fn().mockRejectedValue('nope');
    render(
      <ConfigSection title="General" onSave={onSave}>
        <input name="a" defaultValue="x" />
      </ConfigSection>,
    );
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /Save/ }));
    });
    expect(toast).toHaveBeenCalledWith({
      title: 'Error saving settings',
      description: 'An error occurred',
      variant: 'destructive',
    });
  });
});
