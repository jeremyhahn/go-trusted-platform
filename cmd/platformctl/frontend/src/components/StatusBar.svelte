<script lang="ts">
  import { connection } from '../stores/connection.svelte';
</script>

<div class="statusbar">
  <div class="status-left">
    <span class="status-dot" class:connected={connection.status === 'connected'}></span>
    <span>{connection.status === 'connected' ? 'Connected' : 'Disconnected'}</span>
    {#if connection.status === 'connected'}
      <span class="separator">|</span>
      <span>{connection.protocol}://{connection.address}</span>
    {/if}
  </div>
  <div class="status-right">
    {#if connection.clientVersion}
      <span>v{connection.clientVersion.version}</span>
    {/if}
  </div>
</div>

<style>
  .statusbar {
    height: var(--statusbar-height);
    background: var(--bg-secondary);
    border-top: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 12px;
    font-size: 12px;
    color: var(--text-secondary);
    flex-shrink: 0;
  }

  .status-left, .status-right {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .status-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--text-secondary);
  }

  .status-dot.connected {
    background: var(--success);
  }

  .separator {
    opacity: 0.3;
  }
</style>
