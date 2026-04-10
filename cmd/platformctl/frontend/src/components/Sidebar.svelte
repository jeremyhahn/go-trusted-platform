<script lang="ts">
  import { connection } from '../stores/connection.svelte';
  import { theme } from '../stores/theme.svelte';

  const navItems = [
    { label: 'Dashboard', icon: '\u229E' },
    { label: 'CA', icon: '\uD83D\uDD10' },
    { label: 'Devices', icon: '\uD83D\uDCBB' },
    { label: 'TPM', icon: '\uD83D\uDD11' },
    { label: 'IAM', icon: '\uD83D\uDC64' },
    { label: 'KMS', icon: '\uD83D\uDDDD' },
    { label: 'SDN', icon: '\uD83C\uDF10' },
    { label: 'Compute', icon: '\u26A1' },
  ];

  let active = $state('Dashboard');
</script>

<aside class="sidebar">
  <div class="sidebar-header">
    <span class="logo">TP</span>
    <span class="title">Trusted Platform</span>
  </div>

  <nav class="sidebar-nav">
    {#each navItems as item}
      <button
        class="nav-item"
        class:active={active === item.label}
        onclick={() => active = item.label}
      >
        <span class="nav-icon">{item.icon}</span>
        <span>{item.label}</span>
      </button>
    {/each}
  </nav>

  <div class="sidebar-footer">
    <button class="nav-item" onclick={() => theme.toggle()}>
      <span class="nav-icon">{theme.mode === 'dark' ? '\u2600' : '\uD83C\uDF19'}</span>
      <span>{theme.mode === 'dark' ? 'Light Mode' : 'Dark Mode'}</span>
    </button>
    <button class="nav-item disconnect" onclick={() => connection.disconnect()}>
      <span class="nav-icon">\u23FB</span>
      <span>Disconnect</span>
    </button>
  </div>
</aside>

<style>
  .sidebar {
    width: var(--sidebar-width);
    background: var(--bg-secondary);
    border-right: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    flex-shrink: 0;
  }

  .sidebar-header {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 16px;
    border-bottom: 1px solid var(--border);
  }

  .logo {
    background: var(--accent);
    color: white;
    width: 32px;
    height: 32px;
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 700;
    font-size: 13px;
  }

  .title {
    font-weight: 600;
    font-size: 15px;
  }

  .sidebar-nav {
    flex: 1;
    padding: 8px;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .nav-item {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 12px;
    border-radius: 6px;
    background: transparent;
    color: var(--text-secondary);
    font-size: 14px;
    text-align: left;
    width: 100%;
    transition: all 0.15s;
  }

  .nav-item:hover {
    background: var(--bg-primary);
    color: var(--text-primary);
  }

  .nav-item.active {
    background: var(--accent);
    color: white;
  }

  .nav-icon {
    width: 20px;
    text-align: center;
    font-size: 16px;
  }

  .sidebar-footer {
    padding: 8px;
    border-top: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .disconnect {
    color: var(--error);
  }
</style>
