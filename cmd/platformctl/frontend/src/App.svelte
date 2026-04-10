<script lang="ts">
  import { connection } from './stores/connection.svelte';
  import ConnectionWizard from './views/ConnectionWizard.svelte';
  import Dashboard from './views/Dashboard.svelte';
</script>

{#if connection.status === 'connected'}
  <Dashboard />
{:else}
  <ConnectionWizard />
{/if}
