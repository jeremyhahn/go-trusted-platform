import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/svelte';
import Dashboard from './Dashboard.svelte';

function makeDaemonBinding() {
  return {
    GetVersion: vi.fn().mockResolvedValue({ version: '1.2.3' }),
    GetStatus: vi.fn().mockResolvedValue({ status: 'SERVING' }),
    GetHealth: vi.fn().mockResolvedValue({ status: 'HEALTHY' }),
    ListServices: vi.fn().mockResolvedValue([
      { name: 'kms', status: 'RUNNING' },
      { name: 'ca', status: 'STOPPED' },
    ]),
    StartService: vi.fn().mockResolvedValue(undefined),
    StopService: vi.fn().mockResolvedValue(undefined),
    RestartService: vi.fn().mockResolvedValue(undefined),
    GetServiceStatus: vi.fn().mockResolvedValue({}),
  };
}

function makeConnectionBinding() {
  return {
    Connect: vi.fn().mockResolvedValue(undefined),
    Disconnect: vi.fn().mockResolvedValue(undefined),
    IsConnected: vi.fn().mockResolvedValue(true),
    GetVersion: vi.fn().mockResolvedValue({}),
  };
}

let daemonBinding: ReturnType<typeof makeDaemonBinding>;

beforeEach(() => {
  daemonBinding = makeDaemonBinding();
  window.go = {
    main: {
      DaemonBinding: daemonBinding,
      ConnectionBinding: makeConnectionBinding(),
    },
  } as unknown as Window['go'];
});

afterEach(() => {
  cleanup();
  delete (window as Partial<Window>).go;
});

async function renderLoaded() {
  render(Dashboard);
  await screen.findByText('kms');
}

describe('Dashboard', () => {
  it('loads version, status, health and services on mount', async () => {
    await renderLoaded();
    expect(daemonBinding.GetVersion).toHaveBeenCalled();
    expect(daemonBinding.GetStatus).toHaveBeenCalled();
    expect(daemonBinding.GetHealth).toHaveBeenCalledWith(true);
    expect(daemonBinding.ListServices).toHaveBeenCalled();
    expect(screen.getByText('1.2.3')).toBeTruthy();
    expect(screen.getByText('SERVING')).toBeTruthy();
    expect(screen.getByText('HEALTHY')).toBeTruthy();
    expect(screen.getByText('Services (2)')).toBeTruthy();
  });

  it('Start calls StartService with the stopped service name', async () => {
    await renderLoaded();
    await fireEvent.click(screen.getByRole('button', { name: 'Start' }));
    expect(daemonBinding.StartService).toHaveBeenCalledWith('ca');
    expect(daemonBinding.StopService).not.toHaveBeenCalled();
  });

  it('Stop calls StopService with the running service name', async () => {
    await renderLoaded();
    await fireEvent.click(screen.getByRole('button', { name: 'Stop' }));
    expect(daemonBinding.StopService).toHaveBeenCalledWith('kms');
    expect(daemonBinding.StartService).not.toHaveBeenCalled();
  });

  it('Restart calls RestartService with the running service name', async () => {
    await renderLoaded();
    await fireEvent.click(screen.getByRole('button', { name: 'Restart' }));
    expect(daemonBinding.RestartService).toHaveBeenCalledWith('kms');
  });

  it('Refresh queries the daemon again', async () => {
    await renderLoaded();
    daemonBinding.ListServices.mockClear();
    await fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
    expect(daemonBinding.ListServices).toHaveBeenCalledTimes(1);
  });

  it('shows the binding error instead of the cards', async () => {
    daemonBinding.GetStatus.mockRejectedValue(new Error('daemon unreachable'));
    render(Dashboard);
    expect(await screen.findByText('daemon unreachable')).toBeTruthy();
    expect(screen.queryByText('kms')).toBeNull();
  });
});
