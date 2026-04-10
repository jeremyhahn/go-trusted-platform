import { getDaemonBinding } from '../lib/wails';

class DaemonStore {
  version = $state<Record<string, unknown> | null>(null);
  status = $state<Record<string, unknown> | null>(null);
  health = $state<Record<string, unknown> | null>(null);
  services = $state<Array<Record<string, unknown>>>([]);
  loading = $state(false);
  error = $state<string | null>(null);

  async refresh() {
    this.loading = true;
    this.error = null;
    try {
      const [version, status, health, services] = await Promise.all([
        getDaemonBinding().GetVersion(),
        getDaemonBinding().GetStatus(),
        getDaemonBinding().GetHealth(true),
        getDaemonBinding().ListServices(),
      ]);
      this.version = version;
      this.status = status;
      this.health = health;
      this.services = services ?? [];
    } catch (e) {
      this.error = e instanceof Error ? e.message : String(e);
    } finally {
      this.loading = false;
    }
  }

  async startService(name: string) {
    await getDaemonBinding().StartService(name);
    await this.refresh();
  }

  async stopService(name: string) {
    await getDaemonBinding().StopService(name);
    await this.refresh();
  }

  async restartService(name: string) {
    await getDaemonBinding().RestartService(name);
    await this.refresh();
  }
}

export const daemon = new DaemonStore();
