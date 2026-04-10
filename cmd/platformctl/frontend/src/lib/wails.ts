/** Type-safe wrapper around Wails Go bindings */

interface ConnectionBindingInterface {
  Connect(protocol: string, address: string, tlsOpts: Record<string, string>): Promise<void>;
  Disconnect(): Promise<void>;
  IsConnected(): Promise<boolean>;
  GetVersion(): Promise<Record<string, string>>;
}

interface DaemonBindingInterface {
  GetVersion(): Promise<Record<string, unknown>>;
  GetStatus(): Promise<Record<string, unknown>>;
  GetHealth(detailed: boolean): Promise<Record<string, unknown>>;
  ListServices(): Promise<Array<Record<string, unknown>>>;
  StartService(name: string): Promise<void>;
  StopService(name: string): Promise<void>;
  RestartService(name: string): Promise<void>;
  GetServiceStatus(name: string): Promise<Record<string, unknown>>;
}

declare global {
  interface Window {
    go: {
      main: {
        ConnectionBinding: ConnectionBindingInterface;
        DaemonBinding: DaemonBindingInterface;
      };
    };
  }
}

export function getConnectionBinding(): ConnectionBindingInterface {
  return window.go.main.ConnectionBinding;
}

export function getDaemonBinding(): DaemonBindingInterface {
  return window.go.main.DaemonBinding;
}

export function isWailsReady(): boolean {
  return typeof window !== 'undefined' && typeof window.go !== 'undefined';
}
