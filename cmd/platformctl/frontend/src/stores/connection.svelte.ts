import { getConnectionBinding } from '../lib/wails';

export type Protocol = 'unix' | 'grpc' | 'rest' | 'quic' | 'mcp' | 'embedded';

export type ConnectionStatus = 'disconnected' | 'connecting' | 'connected' | 'error';

class ConnectionStore {
  status = $state<ConnectionStatus>('disconnected');
  protocol = $state<Protocol>('grpc');
  address = $state('localhost:10443');
  error = $state<string | null>(null);
  clientVersion = $state<Record<string, string> | null>(null);

  async connect(protocol: Protocol, address: string, tlsOpts?: Record<string, string>) {
    this.status = 'connecting';
    this.error = null;
    try {
      await getConnectionBinding().Connect(protocol, address, tlsOpts ?? {});
      this.status = 'connected';
      this.protocol = protocol;
      this.address = address;
      this.clientVersion = await getConnectionBinding().GetVersion();
    } catch (e) {
      this.status = 'error';
      this.error = e instanceof Error ? e.message : String(e);
      throw e;
    }
  }

  async disconnect() {
    try {
      await getConnectionBinding().Disconnect();
    } finally {
      this.status = 'disconnected';
      this.error = null;
      this.clientVersion = null;
    }
  }

  async checkConnection() {
    try {
      const connected = await getConnectionBinding().IsConnected();
      this.status = connected ? 'connected' : 'disconnected';
    } catch {
      this.status = 'disconnected';
    }
  }
}

export const connection = new ConnectionStore();
