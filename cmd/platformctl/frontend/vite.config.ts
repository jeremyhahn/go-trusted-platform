import { defineConfig } from 'vitest/config';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { svelteTesting } from '@testing-library/svelte/vite';

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
    execArgv: ['--no-experimental-webstorage'],
  },
});
