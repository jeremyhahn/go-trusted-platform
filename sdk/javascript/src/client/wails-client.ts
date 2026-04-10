/**
 * Wails IPC client for desktop mode.
 * Delegates all calls to Go bindings via the Wails-generated window.go namespace.
 */

/** Wails Go binding interface - matches the Go binding methods. */
interface WailsBindings {
  main: {
    ConnectionBinding: {
      Connect(protocol: string, address: string, tlsOpts: Record<string, string>): Promise<void>;
      Disconnect(): Promise<void>;
      IsConnected(): Promise<boolean>;
      GetVersion(): Promise<Record<string, string>>;
    };
    DaemonBinding: {
      GetVersion(): Promise<Record<string, unknown>>;
      GetStatus(): Promise<Record<string, unknown>>;
      GetHealth(detailed: boolean): Promise<Record<string, unknown>>;
      ListServices(): Promise<Record<string, unknown>[]>;
      StartService(name: string): Promise<Record<string, unknown>>;
      StopService(name: string): Promise<Record<string, unknown>>;
      RestartService(name: string): Promise<Record<string, unknown>>;
      GetServiceStatus(name: string): Promise<Record<string, unknown>>;
    };
  };
}

declare global {
  interface Window {
    go: WailsBindings;
  }
}

/**
 * Returns the Wails Go bindings, throwing if not in desktop mode.
 */
function getBindings(): WailsBindings['main'] {
  if (typeof window === 'undefined' || typeof window.go === 'undefined') {
    throw new Error('Wails bindings not available: not running in desktop mode');
  }
  return window.go.main;
}

/**
 * WailsPlatformClient provides the same interface as PlatformClient
 * but routes calls through Wails IPC to Go bindings.
 *
 * This is a stub that provides the connection management and daemon
 * service. Additional services will be added as Go bindings are implemented.
 */
export class WailsPlatformClient {
  /** Connect to a platform daemon via the specified protocol. */
  async connect(
    protocol: string,
    address: string,
    tlsOpts?: Record<string, string>,
  ): Promise<void> {
    return getBindings().ConnectionBinding.Connect(protocol, address, tlsOpts ?? {});
  }

  /** Disconnect from the platform daemon. */
  async disconnect(): Promise<void> {
    return getBindings().ConnectionBinding.Disconnect();
  }

  /** Check if connected to a platform daemon. */
  async isConnected(): Promise<boolean> {
    return getBindings().ConnectionBinding.IsConnected();
  }

  /** Get the client build version. */
  async getClientVersion(): Promise<Record<string, string>> {
    return getBindings().ConnectionBinding.GetVersion();
  }

  /** Get daemon version. */
  async getDaemonVersion(): Promise<Record<string, unknown>> {
    return getBindings().DaemonBinding.GetVersion();
  }

  /** Get daemon status. */
  async getDaemonStatus(): Promise<Record<string, unknown>> {
    return getBindings().DaemonBinding.GetStatus();
  }

  /** Get daemon health. */
  async getDaemonHealth(detailed: boolean = false): Promise<Record<string, unknown>> {
    return getBindings().DaemonBinding.GetHealth(detailed);
  }

  /** List services. */
  async listServices(): Promise<Record<string, unknown>[]> {
    return getBindings().DaemonBinding.ListServices();
  }

  /** Start a service by name. */
  async startService(name: string): Promise<Record<string, unknown>> {
    return getBindings().DaemonBinding.StartService(name);
  }

  /** Stop a service by name. */
  async stopService(name: string): Promise<Record<string, unknown>> {
    return getBindings().DaemonBinding.StopService(name);
  }

  /** Restart a service by name. */
  async restartService(name: string): Promise<Record<string, unknown>> {
    return getBindings().DaemonBinding.RestartService(name);
  }

  /** Get a service status by name. */
  async getServiceStatus(name: string): Promise<Record<string, unknown>> {
    return getBindings().DaemonBinding.GetServiceStatus(name);
  }
}
