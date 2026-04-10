import { defineConfig, devices } from '@playwright/test';

/**
 * Playwright configuration for E2E testing
 * See https://playwright.dev/docs/test-configuration
 */
export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  // Limit workers to prevent overwhelming the dev server
  // Using 1 worker to prevent resource contention and page.goto timeouts
  workers: 1,
  reporter: process.env.CI ? 'github' : 'html',

  use: {
    baseURL: 'http://localhost:3000',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    // Increase navigation timeout to prevent page.goto failures
    navigationTimeout: 60000,
  },

  timeout: 60000,
  expect: {
    timeout: 10000,
  },

  // In CI, run all browsers. Locally, just chromium for faster feedback.
  projects: process.env.CI
    ? [
        {
          name: 'chromium',
          use: { ...devices['Desktop Chrome'] },
        },
        {
          name: 'firefox',
          use: { ...devices['Desktop Firefox'] },
        },
        {
          name: 'webkit',
          use: { ...devices['Desktop Safari'] },
        },
        {
          name: 'mobile-chrome',
          use: { ...devices['Pixel 5'] },
        },
        {
          name: 'mobile-safari',
          use: { ...devices['iPhone 12'] },
        },
      ]
    : [
        {
          name: 'chromium',
          use: { ...devices['Desktop Chrome'] },
        },
        // Mobile tests require mobile-specific UI handling (opening menus, etc.)
        // Run mobile tests only in CI for comprehensive cross-device coverage
      ],

  // Uses webpack mode (not turbopack) for better compatibility with linked SDK
  webServer: {
    command: 'npm run dev:webpack',
    url: 'http://localhost:3000',
    reuseExistingServer: !process.env.CI,
    timeout: 120000,
  },
});
