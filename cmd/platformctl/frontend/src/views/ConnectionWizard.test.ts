import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/svelte';
import ConnectionWizard from './ConnectionWizard.svelte';

let connectionBinding: {
  Connect: ReturnType<typeof vi.fn>;
  Disconnect: ReturnType<typeof vi.fn>;
  IsConnected: ReturnType<typeof vi.fn>;
  GetVersion: ReturnType<typeof vi.fn>;
};

beforeEach(() => {
  connectionBinding = {
    Connect: vi.fn().mockResolvedValue(undefined),
    Disconnect: vi.fn().mockResolvedValue(undefined),
    IsConnected: vi.fn().mockResolvedValue(true),
    GetVersion: vi.fn().mockResolvedValue({ version: '1.2.3' }),
  };
  window.go = {
    main: { ConnectionBinding: connectionBinding, DaemonBinding: {} },
  } as unknown as Window['go'];
});

afterEach(() => {
  cleanup();
  delete (window as Partial<Window>).go;
});

function protocolSelect(): HTMLSelectElement {
  return screen.getByRole('combobox') as HTMLSelectElement;
}

function addressInput(): HTMLInputElement {
  return screen.getByPlaceholderText('Server address') as HTMLInputElement;
}

describe('ConnectionWizard', () => {
  it('switching the protocol fills in that protocol default address', async () => {
    render(ConnectionWizard);
    await fireEvent.change(protocolSelect(), { target: { value: 'unix' } });
    expect(addressInput().value).toBe('/run/platformd.sock');
  });

  it('Connect calls ConnectionBinding.Connect with the protocol, address and no TLS options', async () => {
    render(ConnectionWizard);
    await fireEvent.change(protocolSelect(), { target: { value: 'unix' } });
    await fireEvent.input(addressInput(), { target: { value: '/tmp/platformd-test.sock' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Connect' }));
    expect(connectionBinding.Connect).toHaveBeenCalledWith('unix', '/tmp/platformd-test.sock', {});
  });

  it('Skip TLS verification passes insecure=true', async () => {
    render(ConnectionWizard);
    await fireEvent.change(protocolSelect(), { target: { value: 'unix' } });
    await fireEvent.click(screen.getByRole('checkbox'));
    await fireEvent.click(screen.getByRole('button', { name: 'Connect' }));
    expect(connectionBinding.Connect).toHaveBeenCalledWith('unix', '/run/platformd.sock', {
      insecure: 'true',
    });
  });

  it('shows the error when Connect rejects and re-enables the button', async () => {
    connectionBinding.Connect.mockRejectedValue(new Error('connection refused'));
    render(ConnectionWizard);
    await fireEvent.click(screen.getByRole('button', { name: 'Connect' }));
    expect(await screen.findByText('connection refused')).toBeTruthy();
    const button = screen.getByRole('button', { name: 'Connect' }) as HTMLButtonElement;
    expect(button.disabled).toBe(false);
  });
});
