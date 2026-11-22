/**
 * Unit tests for the Wails desktop client (#1799).
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { WailsPlatformClient } from './wails-client.js';

function makeBindings() {
  return {
    ConnectionBinding: {
      Connect: vi.fn().mockResolvedValue(undefined),
      Disconnect: vi.fn().mockResolvedValue(undefined),
      IsConnected: vi.fn().mockResolvedValue(true),
      GetVersion: vi.fn().mockResolvedValue({ version: '1.2.3' }),
    },
    DaemonBinding: {
      GetVersion: vi.fn().mockResolvedValue({ version: '9.9.9' }),
      GetStatus: vi.fn().mockResolvedValue({ state: 'running' }),
      GetHealth: vi.fn().mockResolvedValue({ healthy: true }),
      ListServices: vi.fn().mockResolvedValue([{ name: 'kms' }, { name: 'ca' }]),
      StartService: vi.fn().mockResolvedValue({ name: 'kms', state: 'started' }),
      StopService: vi.fn().mockResolvedValue({ name: 'kms', state: 'stopped' }),
      RestartService: vi.fn().mockResolvedValue({ name: 'kms', state: 'restarted' }),
      GetServiceStatus: vi.fn().mockResolvedValue({ name: 'kms', state: 'running' }),
    },
  };
}

type Bindings = ReturnType<typeof makeBindings>;

describe('WailsPlatformClient with bindings', () => {
  let b: Bindings;
  let client: WailsPlatformClient;

  beforeEach(() => {
    b = makeBindings();
    vi.stubGlobal('window', { go: { main: b } });
    client = new WailsPlatformClient();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('connect passes protocol, address and TLS options', async () => {
    const tls = { ca: 'ca.pem' };
    await expect(client.connect('quic', 'daemon', tls)).resolves.toBeUndefined();
    expect(b.ConnectionBinding.Connect).toHaveBeenCalledWith('quic', 'daemon', tls);
  });

  it('connect sends empty TLS options when none are given', async () => {
    await client.connect('unix', 'sock');
    expect(b.ConnectionBinding.Connect).toHaveBeenCalledWith('unix', 'sock', {});
  });

  it('connect passes empty strings through unchanged', async () => {
    await client.connect('', '');
    expect(b.ConnectionBinding.Connect).toHaveBeenCalledWith('', '', {});
  });

  it('connect rejects with the binding error', async () => {
    b.ConnectionBinding.Connect.mockRejectedValueOnce(new Error('refused'));
    await expect(client.connect('quic', 'daemon')).rejects.toThrow('refused');
  });

  it('disconnect calls the binding', async () => {
    await expect(client.disconnect()).resolves.toBeUndefined();
    expect(b.ConnectionBinding.Disconnect).toHaveBeenCalledTimes(1);
  });

  it('isConnected returns the binding result', async () => {
    await expect(client.isConnected()).resolves.toBe(true);
    b.ConnectionBinding.IsConnected.mockResolvedValueOnce(false);
    await expect(client.isConnected()).resolves.toBe(false);
  });

  it('getClientVersion reads the connection binding version', async () => {
    await expect(client.getClientVersion()).resolves.toEqual({ version: '1.2.3' });
    expect(b.DaemonBinding.GetVersion).not.toHaveBeenCalled();
  });

  it('getDaemonVersion reads the daemon binding version', async () => {
    await expect(client.getDaemonVersion()).resolves.toEqual({ version: '9.9.9' });
    expect(b.ConnectionBinding.GetVersion).not.toHaveBeenCalled();
  });

  it('getDaemonStatus returns the status', async () => {
    await expect(client.getDaemonStatus()).resolves.toEqual({ state: 'running' });
  });

  it('getDaemonHealth defaults to a non-detailed check', async () => {
    await expect(client.getDaemonHealth()).resolves.toEqual({ healthy: true });
    expect(b.DaemonBinding.GetHealth).toHaveBeenCalledWith(false);
  });

  it('getDaemonHealth passes detailed=true', async () => {
    await client.getDaemonHealth(true);
    expect(b.DaemonBinding.GetHealth).toHaveBeenCalledWith(true);
  });

  it('listServices returns the list, including an empty one', async () => {
    await expect(client.listServices()).resolves.toEqual([{ name: 'kms' }, { name: 'ca' }]);
    b.DaemonBinding.ListServices.mockResolvedValueOnce([]);
    await expect(client.listServices()).resolves.toEqual([]);
  });

  it('startService, stopService and restartService pass the name', async () => {
    await expect(client.startService('kms')).resolves.toEqual({ name: 'kms', state: 'started' });
    await expect(client.stopService('kms')).resolves.toEqual({ name: 'kms', state: 'stopped' });
    await expect(client.restartService('kms')).resolves.toEqual({
      name: 'kms',
      state: 'restarted',
    });
    expect(b.DaemonBinding.StartService).toHaveBeenCalledWith('kms');
    expect(b.DaemonBinding.StopService).toHaveBeenCalledWith('kms');
    expect(b.DaemonBinding.RestartService).toHaveBeenCalledWith('kms');
  });

  it('getServiceStatus passes the name', async () => {
    await expect(client.getServiceStatus('ca')).resolves.toEqual({ name: 'kms', state: 'running' });
    expect(b.DaemonBinding.GetServiceStatus).toHaveBeenCalledWith('ca');
  });

  it('service calls reject with the binding error for an unknown service', async () => {
    b.DaemonBinding.StartService.mockRejectedValueOnce(new Error('unknown service'));
    await expect(client.startService('nope')).rejects.toThrow('unknown service');
  });

  it('reads the bindings at call time, not at construction', async () => {
    const other = makeBindings();
    other.ConnectionBinding.IsConnected.mockResolvedValue(false);
    vi.stubGlobal('window', { go: { main: other } });
    await expect(client.isConnected()).resolves.toBe(false);
    expect(b.ConnectionBinding.IsConnected).not.toHaveBeenCalled();
  });
});

describe('WailsPlatformClient without bindings', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  const notDesktop = 'Wails bindings not available: not running in desktop mode';

  it('can be constructed outside the desktop runtime', () => {
    vi.stubGlobal('window', undefined);
    expect(() => new WailsPlatformClient()).not.toThrow();
  });

  it('rejects every call when there is no window', async () => {
    vi.stubGlobal('window', undefined);
    const c = new WailsPlatformClient();
    await expect(c.connect('quic', 'daemon')).rejects.toThrow(notDesktop);
    await expect(c.disconnect()).rejects.toThrow(notDesktop);
    await expect(c.isConnected()).rejects.toThrow(notDesktop);
    await expect(c.getClientVersion()).rejects.toThrow(notDesktop);
    await expect(c.getDaemonVersion()).rejects.toThrow(notDesktop);
    await expect(c.getDaemonStatus()).rejects.toThrow(notDesktop);
    await expect(c.getDaemonHealth()).rejects.toThrow(notDesktop);
    await expect(c.listServices()).rejects.toThrow(notDesktop);
    await expect(c.startService('kms')).rejects.toThrow(notDesktop);
    await expect(c.stopService('kms')).rejects.toThrow(notDesktop);
    await expect(c.restartService('kms')).rejects.toThrow(notDesktop);
    await expect(c.getServiceStatus('kms')).rejects.toThrow(notDesktop);
  });

  it('rejects when the window has no go object', async () => {
    vi.stubGlobal('window', {});
    await expect(new WailsPlatformClient().isConnected()).rejects.toThrow(notDesktop);
  });
});
