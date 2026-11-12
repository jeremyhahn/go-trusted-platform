import { afterEach, describe, expect, it } from 'vitest';
import { getConnectionBinding, getDaemonBinding, isWailsReady } from './wails';

type GoRuntime = Window['go'];

function installRuntime(): GoRuntime {
  const runtime = {
    main: {
      ConnectionBinding: { name: 'connection' },
      DaemonBinding: { name: 'daemon' },
    },
  } as unknown as GoRuntime;
  window.go = runtime;
  return runtime;
}

afterEach(() => {
  delete (window as Partial<Window>).go;
});

describe('wails bindings', () => {
  it('isWailsReady is false before the Wails runtime injects window.go', () => {
    expect(isWailsReady()).toBe(false);
  });

  it('isWailsReady is true once window.go exists', () => {
    installRuntime();
    expect(isWailsReady()).toBe(true);
  });

  it('getDaemonBinding returns window.go.main.DaemonBinding', () => {
    const runtime = installRuntime();
    expect(getDaemonBinding()).toBe(runtime.main.DaemonBinding);
  });

  it('getConnectionBinding returns window.go.main.ConnectionBinding', () => {
    const runtime = installRuntime();
    expect(getConnectionBinding()).toBe(runtime.main.ConnectionBinding);
  });

  it('getDaemonBinding throws when the runtime is missing', () => {
    expect(() => getDaemonBinding()).toThrow();
  });

  it('getConnectionBinding throws when the runtime is missing', () => {
    expect(() => getConnectionBinding()).toThrow();
  });
});
