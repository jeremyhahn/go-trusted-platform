import { defineConfig, devices } from '@playwright/test';
import path from 'path';

/**
 * Playwright configuration for Integration Testing
 *
 * This configuration runs integration tests from test/integration/web/
 * against a real backend in the devcontainer environment.
 *
 * Environment Variables:
 *   HEADED=1          - Run with visible browser window (default: headless)
 *   CI=1              - CI mode (headless, retries, github reporter)
 *   FRONTEND_URL      - Frontend URL (default: http://localhost:3000)
 *
 * Usage:
 *   # Headless (default) - results logged to playwright.log
 *   npx playwright test --config playwright.integration.config.ts
 *
 *   # With browser window
 *   HEADED=1 npx playwright test --config playwright.integration.config.ts
 *
 *   # UI mode (interactive)
 *   npx playwright test --config playwright.integration.config.ts --ui
 *
 * See https://playwright.dev/docs/test-configuration
 */

// Path to integration test directory
const integrationTestDir = path.resolve(__dirname, '../test/integration/web');

// Determine if running headed or headless
const isHeaded = process.env.HEADED === '1' || process.env.HEADED === 'true';
const isCI = !!process.env.CI;

// Skip local web server when targeting a remote frontend (QEMU, staging, etc.)
const skipWebServer = !!process.env.NO_WEB_SERVER ||
  (!!process.env.FRONTEND_URL && !process.env.FRONTEND_URL.includes('localhost'));

// Log file path
const logFile = path.join(__dirname, 'playwright.log');

export default defineConfig({
  testDir: integrationTestDir,
  fullyParallel: true,
  forbidOnly: isCI,
  retries: isCI ? 2 : 1,
  workers: isCI ? 1 : 2,

  // Reporter configuration:
  // - 'json' writes results to playwright.log for automated parsing
  // - 'line' shows progress in terminal
  // - 'html' generates interactive report
  reporter: isCI
    ? [
        ['github'],
        ['json', { outputFile: logFile }],
        ['html', { outputFolder: path.join(integrationTestDir, 'playwright-report') }],
      ]
    : [
        ['line'],
        ['json', { outputFile: logFile }],
        ['html', { outputFolder: path.join(integrationTestDir, 'playwright-report') }],
      ],

  use: {
    // Base URL for the frontend
    baseURL: process.env.FRONTEND_URL || 'http://localhost:3000',

    // Headless mode - controlled by HEADED env var
    headless: !isHeaded,

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

  // Test projects — Chromium required for WebAuthn virtual authenticator (CDP)
  projects: [
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        ignoreHTTPSErrors: true,
      },
    },
  ],

  // Global setup and teardown
  globalSetup: path.join(integrationTestDir, 'global-setup.ts'),
  globalTeardown: path.join(integrationTestDir, 'global-teardown.ts'),

  // Web server configuration
  // Skipped when FRONTEND_URL points to a remote server or NO_WEB_SERVER=1
  ...(skipWebServer ? {} : {
    webServer: [
      {
        command: 'npm run dev',
        url: 'http://localhost:3000',
        reuseExistingServer: !isCI,
        timeout: 120000,
      },
    ],
  }),

  // Output directory for test artifacts
  outputDir: path.join(integrationTestDir, 'test-results'),
});
