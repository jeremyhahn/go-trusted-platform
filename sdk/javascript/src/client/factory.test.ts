/**
 * Unit tests for the client factory (#1799).
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { getClient, isDesktop } from './factory.js';
import { PlatformClient } from './platform-client.js';
import { WailsPlatformClient } from './wails-client.js';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('isDesktop', () => {
  it('is false when there is no window (Node, SSR)', () => {
    vi.stubGlobal('window', undefined);
    expect(isDesktop()).toBe(false);
  });

  it('is false in a browser window without the Wails go object', () => {
    vi.stubGlobal('window', {});
    expect(isDesktop()).toBe(false);
  });

  it('is true when the Wails runtime injected window.go', () => {
    vi.stubGlobal('window', { go: { main: {} } });
    expect(isDesktop()).toBe(true);
  });

  it('is true even for a falsy but defined window.go', () => {
    vi.stubGlobal('window', { go: null });
    expect(isDesktop()).toBe(true);
  });

  it('is false when window.go is explicitly undefined', () => {
    vi.stubGlobal('window', { go: undefined });
    expect(isDesktop()).toBe(false);
  });
});

describe('getClient', () => {
  it('returns a REST PlatformClient outside the desktop runtime', async () => {
    vi.stubGlobal('window', undefined);
    const client = await getClient({ baseUrl: '/api' });
    expect(client).toBeInstanceOf(PlatformClient);
  });

  it('returns a REST PlatformClient for a given baseUrl', async () => {
    vi.stubGlobal('window', {});
    const client = await getClient({ baseUrl: '/api' });
    expect(client).toBeInstanceOf(PlatformClient);
    expect(client).not.toBeInstanceOf(WailsPlatformClient);
  });

  it('rejects an empty config object outside the desktop runtime', async () => {
    vi.stubGlobal('window', undefined);
    await expect(getClient({})).rejects.toThrow('baseUrl cannot be empty');
  });

  it('returns a WailsPlatformClient inside the desktop runtime', async () => {
    vi.stubGlobal('window', { go: { main: {} } });
    const client = await getClient({ baseUrl: '/ignored' });
    expect(client).toBeInstanceOf(WailsPlatformClient);
    expect(client).not.toBeInstanceOf(PlatformClient);
  });

  it('returns a fresh client on every call', async () => {
    vi.stubGlobal('window', undefined);
    const a = await getClient({ baseUrl: '/api' });
    const b = await getClient({ baseUrl: '/api' });
    expect(a).not.toBe(b);
  });
});
