/**
 * Playwright configuration for Integration Testing
 *
 * This configuration is for running integration tests against a real backend.
 * Tests should be run in the devcontainer environment with all services running.
 *
 * Run from the web directory:
 *   npx playwright test --config ../test/integration/web/playwright.config.ts
 *
 * See https://playwright.dev/docs/test-configuration
 */

// Note: This file is loaded from the web directory, so @playwright/test resolves
// from web/node_modules
import { defineConfig, devices } from '@playwright/test';
import path from 'path';

// Get the directory where this config file lives
const integrationTestDir = path.dirname(__filename);

export default defineConfig({
  testDir: integrationTestDir,
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 1,
  workers: process.env.CI ? 1 : 2,
  reporter: process.env.CI
    ? [['github'], ['html', { outputFolder: path.join(integrationTestDir, 'playwright-report') }]]
    : [['html', { outputFolder: path.join(integrationTestDir, 'playwright-report') }], ['list']],

  use: {
    // Base URL for the frontend
    baseURL: process.env.FRONTEND_URL || 'http://localhost:3000',

    // Collect trace on first retry
    trace: 'on-first-retry',

    // Take screenshot on failure
    screenshot: 'only-on-failure',

    // Video recording for debugging
    video: 'on-first-retry',

    // Accept self-signed certificates for backend API
    ignoreHTTPSErrors: true,

    // Extra HTTP headers
    extraHTTPHeaders: {
      'Accept': 'application/json',
    },
  },

  // Timeouts
  timeout: 60000,
  expect: {
    timeout: 10000,
  },

  // Test projects
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],

  // Global setup and teardown - use absolute paths
  globalSetup: path.join(integrationTestDir, 'global-setup.ts'),
  globalTeardown: path.join(integrationTestDir, 'global-teardown.ts'),

  // Web server configuration
  webServer: [
    {
      // Frontend Next.js server - run from where the command is invoked (web directory)
      command: 'npm run dev',
      url: 'http://localhost:3000',
      reuseExistingServer: !process.env.CI,
      timeout: 120000,
    },
  ],

  // Output directory for test artifacts
  outputDir: path.join(integrationTestDir, 'test-results'),
});
