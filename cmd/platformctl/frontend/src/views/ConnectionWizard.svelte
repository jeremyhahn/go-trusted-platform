<script lang="ts">
  import { connection, type Protocol } from '../stores/connection.svelte';

  let protocol = $state<Protocol>('grpc');
  let address = $state('localhost:10443');
  let insecure = $state(false);
  let connecting = $state(false);
  let errorMsg = $state<string | null>(null);

  const protocols: { value: Protocol; label: string; defaultAddr: string }[] = [
    { value: 'unix', label: 'Unix Socket', defaultAddr: '/run/platformd.sock' },
    { value: 'grpc', label: 'gRPC', defaultAddr: 'localhost:10443' },
    { value: 'rest', label: 'REST', defaultAddr: 'https://localhost:8443' },
    { value: 'quic', label: 'QUIC', defaultAddr: 'localhost:9444' },
    { value: 'mcp', label: 'MCP', defaultAddr: 'http://localhost:9445' },
  ];

  function onProtocolChange() {
    const found = protocols.find(p => p.value === protocol);
    if (found) address = found.defaultAddr;
  }

  async function handleConnect() {
    connecting = true;
    errorMsg = null;
    try {
      const tlsOpts: Record<string, string> = {};
      if (insecure) tlsOpts['insecure'] = 'true';
      await connection.connect(protocol, address, tlsOpts);
    } catch (e) {
      errorMsg = e instanceof Error ? e.message : String(e);
    } finally {
      connecting = false;
    }
  }
</script>

<div class="wizard">
  <div class="wizard-card">
    <div class="wizard-header">
      <h1>Trusted Platform</h1>
      <p>Connect to a platform daemon</p>
    </div>

    <div class="wizard-form">
      <label>
        <span>Protocol</span>
        <select bind:value={protocol} onchange={onProtocolChange}>
          {#each protocols as p}
            <option value={p.value}>{p.label}</option>
          {/each}
        </select>
      </label>

      <label>
        <span>Address</span>
        <input type="text" bind:value={address} placeholder="Server address" />
      </label>

      <label class="checkbox">
        <input type="checkbox" bind:checked={insecure} />
        <span>Skip TLS verification (dev only)</span>
      </label>

      {#if errorMsg}
        <div class="error">{errorMsg}</div>
      {/if}

      <button class="primary connect-btn" onclick={handleConnect} disabled={connecting}>
        {connecting ? 'Connecting...' : 'Connect'}
      </button>
    </div>
  </div>
</div>

<style>
  .wizard {
    height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--bg-primary);
  }

  .wizard-card {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 40px;
    width: 420px;
    max-width: 90vw;
  }

  .wizard-header {
    text-align: center;
    margin-bottom: 32px;
  }

  .wizard-header h1 {
    font-size: 24px;
    margin-bottom: 8px;
    color: var(--accent);
  }

  .wizard-header p {
    color: var(--text-secondary);
  }

  .wizard-form {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  label {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  label span {
    font-size: 13px;
    font-weight: 500;
    color: var(--text-secondary);
  }

  label.checkbox {
    flex-direction: row;
    align-items: center;
    gap: 8px;
  }

  label.checkbox input {
    width: 16px;
    height: 16px;
  }

  .error {
    background: rgba(239, 68, 68, 0.1);
    border: 1px solid var(--error);
    border-radius: 6px;
    padding: 8px 12px;
    color: var(--error);
    font-size: 13px;
  }

  .connect-btn {
    margin-top: 8px;
    padding: 12px;
    font-size: 15px;
  }

  .connect-btn:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }
</style>
