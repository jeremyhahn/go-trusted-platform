# Frontend Testing Guide

This document describes the testing strategy, setup, and best practices for the Trusted Platform web frontend.

## Table of Contents

- [Overview](#overview)
- [Playwright Setup](#playwright-setup)
- [Running Tests](#running-tests)
- [CI Integration](#ci-integration)
- [WebAuthn Mocking](#webauthn-mocking)
- [Test Patterns](#test-patterns)
- [Best Practices](#best-practices)

## Overview

The frontend uses Playwright for end-to-end (E2E) testing, providing cross-browser testing capabilities and built-in support for modern web features.

### Testing Stack

| Tool | Purpose |
|------|---------|
| Playwright | E2E testing framework |
| Next.js | React framework |
| TypeScript | Type-safe test code |
| WebAuthn | Passwordless authentication |

### Test Types

| Type | Location | Purpose |
|------|----------|---------|
| E2E | `web/e2e/` | Full user flow testing |
| Component | `web/src/**/*.test.tsx` | Individual component testing |
| Integration | `web/e2e/integration/` | API integration testing |

## Playwright Setup

### Installation

Playwright is included as a dev dependency. Install browsers after initial setup:

```bash
cd web
npm install
npx playwright install
```

### Configuration

Playwright configuration is defined in `playwright.config.ts`:

```typescript
import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: process.env.CI ? 'github' : 'html',

  use: {
    baseURL: 'http://localhost:3000',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
  },

  timeout: 30000,
  expect: {
    timeout: 5000,
  },

  projects: [
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
  ],

  webServer: {
    command: 'npm run dev',
    url: 'http://localhost:3000',
    reuseExistingServer: !process.env.CI,
    timeout: 120000,
  },
});
```

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `testDir` | Directory containing test files | `./e2e` |
| `fullyParallel` | Run tests in parallel | `true` |
| `retries` | Number of retries on failure | 0 (local), 2 (CI) |
| `workers` | Parallel worker count | auto (local), 1 (CI) |
| `timeout` | Test timeout in ms | 30000 |
| `baseURL` | Base URL for navigation | `http://localhost:3000` |

## Running Tests

### NPM Scripts

```bash
# Run all E2E tests
npm run test:e2e

# Run tests with UI mode (interactive)
npm run test:e2e:ui

# Run tests in headed mode (visible browser)
npm run test:e2e:headed
```

### Playwright CLI

```bash
# Run specific test file
npx playwright test e2e/auth.spec.ts

# Run tests matching pattern
npx playwright test -g "login"

# Run in specific browser
npx playwright test --project=chromium

# Run with debug mode
npx playwright test --debug

# Show test report
npx playwright show-report
```

### Running with Local Backend

Ensure the platform daemon is running before tests:

```bash
# Terminal 1: Start backend
cd /path/to/go-trusted-platform
make run

# Terminal 2: Run tests
cd web
npm run test:e2e
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CI` | Running in CI environment | (unset) |
| `BASE_URL` | Override base URL | `http://localhost:3000` |
| `API_URL` | Backend API URL | `https://localhost:8443` |
| `HEADLESS` | Run in headless mode | `true` in CI |

## CI Integration

### GitHub Actions Configuration

```yaml
# .github/workflows/e2e-tests.yml
name: E2E Tests

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
          cache-dependency-path: web/package-lock.json

      - name: Install dependencies
        working-directory: web
        run: npm ci

      - name: Install Playwright Browsers
        working-directory: web
        run: npx playwright install --with-deps

      - name: Start backend
        run: |
          make build
          make run &
          sleep 10

      - name: Run Playwright tests
        working-directory: web
        run: npx playwright test
        env:
          CI: true

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: playwright-report
          path: web/playwright-report/
          retention-days: 30
```

### CI Considerations

| Aspect | Recommendation |
|--------|----------------|
| Parallelism | Use 1 worker to avoid race conditions |
| Retries | Enable 2 retries for flaky tests |
| Reporter | Use `github` reporter for PR annotations |
| Artifacts | Upload reports and screenshots on failure |
| Timeout | Increase timeouts for slower CI machines |

## WebAuthn Mocking

WebAuthn requires special handling in headless testing environments since hardware authenticators are not available.

### Virtual Authenticator

Playwright supports virtual authenticators via CDP (Chrome DevTools Protocol):

```typescript
// e2e/fixtures/webauthn.ts
import { test as base, BrowserContext } from '@playwright/test';

type WebAuthnFixtures = {
  authenticatedContext: BrowserContext;
};

export const test = base.extend<WebAuthnFixtures>({
  authenticatedContext: async ({ browser }, use) => {
    const context = await browser.newContext();
    const cdpSession = await context.newCDPSession(await context.newPage());

    // Enable virtual authenticator
    await cdpSession.send('WebAuthn.enable');

    // Add virtual authenticator
    const { authenticatorId } = await cdpSession.send('WebAuthn.addVirtualAuthenticator', {
      options: {
        protocol: 'ctap2',
        transport: 'internal',
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
      },
    });

    await use(context);

    // Cleanup
    await cdpSession.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId });
    await context.close();
  },
});

export { expect } from '@playwright/test';
```

### Using the Virtual Authenticator

```typescript
// e2e/auth/registration.spec.ts
import { test, expect } from '../fixtures/webauthn';

test.describe('WebAuthn Registration', () => {
  test('should register new user with passkey', async ({ authenticatedContext }) => {
    const page = await authenticatedContext.newPage();

    await page.goto('/register');

    // Fill email
    await page.fill('[data-testid="email-input"]', 'test@example.com');
    await page.click('[data-testid="register-button"]');

    // Virtual authenticator handles the WebAuthn ceremony automatically

    // Verify redirect to dashboard
    await expect(page).toHaveURL('/dashboard');
    await expect(page.locator('[data-testid="user-email"]')).toHaveText('test@example.com');
  });

  test('should handle registration with invitation', async ({ authenticatedContext }) => {
    const page = await authenticatedContext.newPage();
    const invitationToken = 'test-invitation-token';

    await page.goto(`/register?token=${invitationToken}`);

    // Email should be pre-filled from invitation
    await expect(page.locator('[data-testid="email-input"]')).toHaveValue('invited@example.com');

    await page.click('[data-testid="register-button"]');

    // Verify tenant assignment
    await expect(page).toHaveURL('/dashboard');
    await expect(page.locator('[data-testid="tenant-name"]')).toHaveText('Engineering');
  });
});
```

### Mock API Responses

For tests that need specific API behavior:

```typescript
// e2e/auth/login.spec.ts
import { test, expect } from '@playwright/test';

test('should handle WebAuthn login', async ({ page }) => {
  // Mock the WebAuthn begin endpoint
  await page.route('**/api/v1/webauthn/login/begin', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        publicKey: {
          challenge: 'mock-challenge',
          timeout: 60000,
          rpId: 'localhost',
          allowCredentials: [
            { type: 'public-key', id: 'mock-credential-id' }
          ],
        },
      }),
    });
  });

  // Mock the WebAuthn finish endpoint
  await page.route('**/api/v1/webauthn/login/finish', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        access_token: 'mock-jwt-token',
        token_type: 'Bearer',
        expires_in: 3600,
      }),
    });
  });

  await page.goto('/login');
  await page.fill('[data-testid="email-input"]', 'test@example.com');
  await page.click('[data-testid="login-button"]');

  await expect(page).toHaveURL('/dashboard');
});
```

## Test Patterns

### Page Object Model

Organize tests using the Page Object Model pattern:

```typescript
// e2e/pages/LoginPage.ts
import { Page, Locator } from '@playwright/test';

export class LoginPage {
  readonly page: Page;
  readonly emailInput: Locator;
  readonly loginButton: Locator;
  readonly errorMessage: Locator;

  constructor(page: Page) {
    this.page = page;
    this.emailInput = page.locator('[data-testid="email-input"]');
    this.loginButton = page.locator('[data-testid="login-button"]');
    this.errorMessage = page.locator('[data-testid="error-message"]');
  }

  async goto() {
    await this.page.goto('/login');
  }

  async login(email: string) {
    await this.emailInput.fill(email);
    await this.loginButton.click();
  }

  async expectError(message: string) {
    await expect(this.errorMessage).toContainText(message);
  }
}

// Usage in test
test('login page', async ({ page }) => {
  const loginPage = new LoginPage(page);
  await loginPage.goto();
  await loginPage.login('user@example.com');
});
```

### Test Data Factories

Create reusable test data:

```typescript
// e2e/factories/user.ts
export interface TestUser {
  email: string;
  displayName: string;
  tenantId?: string;
}

export function createTestUser(overrides: Partial<TestUser> = {}): TestUser {
  const timestamp = Date.now();
  return {
    email: `test-${timestamp}@example.com`,
    displayName: `Test User ${timestamp}`,
    ...overrides,
  };
}

// e2e/factories/invitation.ts
export function createTestInvitation(tenantId: string, email: string) {
  return {
    token: `test-token-${Date.now()}`,
    tenantId,
    email,
    role: 'developer',
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
  };
}
```

### API Helpers

Abstract API interactions:

```typescript
// e2e/helpers/api.ts
import { APIRequestContext } from '@playwright/test';

export class ApiHelper {
  constructor(private request: APIRequestContext, private baseUrl: string) {}

  async createInvitation(email: string, role: string) {
    const response = await this.request.post(`${this.baseUrl}/api/v1/invitations`, {
      data: { email, role },
    });
    return response.json();
  }

  async deleteUser(userId: string) {
    await this.request.delete(`${this.baseUrl}/api/v1/users/${userId}`);
  }
}
```

## Best Practices

### Test Organization

```
web/
  e2e/
    fixtures/          # Custom fixtures (WebAuthn, auth, etc.)
    helpers/           # API and utility helpers
    pages/             # Page Object Models
    factories/         # Test data factories
    auth/              # Authentication tests
      login.spec.ts
      registration.spec.ts
      logout.spec.ts
    dashboard/         # Dashboard tests
    tenant/            # Tenant management tests
    global-setup.ts    # Global setup script
    global-teardown.ts # Global teardown script
```

### Naming Conventions

| Convention | Example |
|------------|---------|
| Test files | `*.spec.ts` |
| Page objects | `*Page.ts` |
| Fixtures | Descriptive names in `fixtures/` |
| Test IDs | `data-testid="component-action"` |

### Test Isolation

Each test should:

1. Set up its own state
2. Not depend on other tests
3. Clean up after itself
4. Use unique test data (timestamps, UUIDs)

```typescript
test.beforeEach(async ({ page }) => {
  // Clear cookies and storage
  await page.context().clearCookies();
});

test.afterEach(async ({ page }) => {
  // Cleanup test data if needed
});
```

### Assertions

Use specific assertions for better error messages:

```typescript
// Good: Specific assertion
await expect(page.locator('[data-testid="user-email"]')).toHaveText('user@example.com');

// Avoid: Generic assertion
expect(await page.textContent('[data-testid="user-email"]')).toBe('user@example.com');
```

### Waiting Strategies

Use Playwright's auto-waiting instead of explicit waits:

```typescript
// Good: Auto-waiting locator
await page.locator('[data-testid="submit"]').click();

// Avoid: Explicit waits
await page.waitForTimeout(1000);
await page.click('[data-testid="submit"]');
```

### Debugging Tips

1. **Use UI mode** for interactive debugging: `npm run test:e2e:ui`
2. **Enable traces** for failure analysis: `trace: 'on-first-retry'`
3. **Use debug mode** for step-by-step execution: `npx playwright test --debug`
4. **Take screenshots** on assertions: `screenshot: 'only-on-failure'`

## Related Documentation

- [Playwright Documentation](https://playwright.dev/docs/intro)
- [WebAuthn API](../iam/authentication.md)
- [User Registration](../iam/user-registration.md)
- [API Reference](../api/rest-reference.md)
