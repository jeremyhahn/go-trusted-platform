import { defineConfig } from 'vitest/config';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { svelteTesting } from '@testing-library/svelte/vite';

const webStorageFlag = '--no-experimental-webstorage';
const webStorageExecArgv = process.allowedNodeEnvironmentFlags.has(webStorageFlag)
  ? [webStorageFlag]
  : [];

export default defineConfig({
  plugins: [svelte(), svelteTesting()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.ts'],
    // Node 26's built-in localStorage global is undefined without
    // --localstorage-file and shadows jsdom's window.localStorage (#1871).
    // The flag is gated: Node 20 does not know it and refuses to start the
    // worker, so it is passed only where the running Node accepts it.
    execArgv: webStorageExecArgv,
  },
});
