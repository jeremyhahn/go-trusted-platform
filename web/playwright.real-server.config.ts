import { defineConfig, devices } from '@playwright/test';
import path from 'path';

/**
 * Playwright against a real platform daemon (#2034, epic #1665).
 *
 * `make web-e2e` builds platformd with the console embedded (WITH_WEB=1) and
 * runs this config. global-setup.ts starts the daemon on the TPM simulator
 * with a throwaway data directory; the specs in e2e/real-server/ drive the
 * console it serves, same origin, logging in through real WebAuthn
 * ceremonies with Chromium's virtual authenticator. Nothing is mocked.
 *
 * Chromium only: the virtual authenticator is a CDP feature.
 * E2E_PORT moves the daemon off 18443.
 */
const port = Number(process.env.E2E_PORT || 18443);

export default defineConfig({
  testDir: './e2e/real-server',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: 0,
  // One daemon, one worker: specs share its state.
  workers: 1,
  reporter: process.env.CI ? [['github'], ['list']] : [['list']],
  outputDir: path.join(__dirname, 'test-results', 'real-server'),

  globalSetup: path.join(__dirname, 'e2e', 'real-server', 'global-setup.ts'),
  globalTeardown: path.join(__dirname, 'e2e', 'real-server', 'global-teardown.ts'),

  use: {
    baseURL: `https://localhost:${port}`,
    ignoreHTTPSErrors: true,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    navigationTimeout: 60000,
  },

  timeout: 60000,
  expect: {
    timeout: 15000,
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'], ignoreHTTPSErrors: true },
    },
  ],
});
