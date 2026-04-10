<script lang="ts">
  import { connection } from '../stores/connection.svelte';
  import { daemon } from '../stores/daemon.svelte';
  import Sidebar from '../components/Sidebar.svelte';
  import StatusBar from '../components/StatusBar.svelte';
  import { onMount } from 'svelte';

  onMount(() => {
    daemon.refresh();
  });
</script>

<div class="layout">
  <Sidebar />
  <main class="content">
    <div class="header">
      <h2>Dashboard</h2>
      <button class="primary" onclick={() => daemon.refresh()}>
        Refresh
      </button>
    </div>

    {#if daemon.loading}
      <div class="loading">Loading...</div>
    {:else if daemon.error}
      <div class="error-banner">{daemon.error}</div>
    {:else}
      <div class="cards">
        <div class="card">
          <h3>Daemon</h3>
          <div class="card-body">
            <div class="stat">
              <span class="stat-label">Status</span>
              <span class="stat-value">{daemon.status?.status ?? 'Unknown'}</span>
            </div>
            <div class="stat">
              <span class="stat-label">Version</span>
              <span class="stat-value">{daemon.version?.version ?? 'Unknown'}</span>
            </div>
            <div class="stat">
              <span class="stat-label">Health</span>
              <span class="stat-value">{daemon.health?.status ?? 'Unknown'}</span>
            </div>
          </div>
        </div>

        <div class="card">
          <h3>Connection</h3>
          <div class="card-body">
            <div class="stat">
              <span class="stat-label">Protocol</span>
              <span class="stat-value">{connection.protocol}</span>
            </div>
            <div class="stat">
              <span class="stat-label">Address</span>
              <span class="stat-value">{connection.address}</span>
            </div>
          </div>
        </div>

        <div class="card wide">
          <h3>Services ({daemon.services.length})</h3>
          <div class="services-list">
            {#each daemon.services as svc}
              <div class="service-row">
                <span class="service-name">{svc.name}</span>
                <span class="service-status" class:running={svc.status === 'RUNNING'}
                      class:stopped={svc.status === 'STOPPED'}>
                  {svc.status}
                </span>
                <div class="service-actions">
                  {#if svc.status === 'RUNNING'}
                    <button onclick={() => daemon.stopService(String(svc.name))}>Stop</button>
                    <button onclick={() => daemon.restartService(String(svc.name))}>Restart</button>
                  {:else}
                    <button onclick={() => daemon.startService(String(svc.name))}>Start</button>
                  {/if}
                </div>
              </div>
            {/each}
            {#if daemon.services.length === 0}
              <div class="empty">No services reported</div>
            {/if}
          </div>
        </div>
      </div>
    {/if}
  </main>
  <StatusBar />
</div>

<style>
  .layout {
    display: flex;
    flex: 1;
    overflow: hidden;
  }

  .content {
    flex: 1;
    padding: 24px;
    overflow-y: auto;
  }

  .header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 24px;
  }

  .loading, .error-banner, .empty {
    padding: 16px;
    text-align: center;
    color: var(--text-secondary);
  }

  .error-banner {
    background: rgba(239, 68, 68, 0.1);
    border: 1px solid var(--error);
    border-radius: 8px;
    color: var(--error);
  }

  .cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 16px;
  }

  .card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
  }

  .card.wide {
    grid-column: 1 / -1;
  }

  .card h3 {
    font-size: 15px;
    font-weight: 600;
    margin-bottom: 16px;
    color: var(--text-secondary);
  }

  .card-body {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .stat {
    display: flex;
    justify-content: space-between;
  }

  .stat-label {
    color: var(--text-secondary);
    font-size: 13px;
  }

  .stat-value {
    font-weight: 500;
  }

  .services-list {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .service-row {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 8px 0;
    border-bottom: 1px solid var(--border);
  }

  .service-row:last-child {
    border-bottom: none;
  }

  .service-name {
    flex: 1;
    font-weight: 500;
  }

  .service-status {
    font-size: 12px;
    font-weight: 600;
    padding: 2px 8px;
    border-radius: 4px;
    background: var(--bg-secondary);
  }

  .service-status.running { color: var(--success); }
  .service-status.stopped { color: var(--text-secondary); }

  .service-actions {
    display: flex;
    gap: 4px;
  }

  .service-actions button {
    font-size: 12px;
    padding: 4px 8px;
    background: var(--bg-secondary);
    color: var(--text-primary);
    border: 1px solid var(--border);
  }
</style>
