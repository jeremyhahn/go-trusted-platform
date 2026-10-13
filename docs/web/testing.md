# Web Frontend Testing

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [engineering.md](engineering.md) §9. Commands are `npm run`, not yarn; `e2e/fixtures/auth-fixture.ts` does not exist (the fixtures are `auth-setup.ts`, `api-mock.ts` and siblings).

Comprehensive testing guide for the Trusted Platform Web Frontend using Playwright.

## Overview

The web frontend uses Playwright for end-to-end (E2E) testing. Tests are designed to run in CI environments with WebAuthn mocking to simulate passkey authentication without hardware authenticators.

## Test Structure

```
web/
├── e2e/                        # E2E test directory
│   ├── fixtures/               # Test fixtures and mocks
│   │   └── webauthn-mock.ts    # WebAuthn mock implementation
│   ├── auth.spec.ts            # Authentication flow tests
│   ├── invitations.spec.ts     # Invitation management tests
│   └── tenant.spec.ts          # Tenant dashboard tests
├── playwright.config.ts        # Playwright configuration
└── playwright-report/          # HTML test reports (generated)
```

## Running Tests

### Local Development

```bash
cd web

# Run all tests headless
yarn test:e2e

# Run tests with Playwright UI
yarn test:e2e:ui

# Run tests in headed browser
yarn test:e2e:headed
```

### Specific Test File

```bash
# Run only auth tests
npx playwright test auth.spec.ts

# Run only invitation tests
npx playwright test invitations.spec.ts
```

### Specific Browser

```bash
# Chrome only
npx playwright test --project=chromium

# Firefox only
npx playwright test --project=firefox

# Safari only
npx playwright test --project=webkit
```

### Debug Mode

```bash
# Run with Playwright Inspector
npx playwright test --debug

# Run specific test with debug
npx playwright test auth.spec.ts --debug
```

## Playwright Configuration

### Browser Matrix

| Browser | Device | Purpose |
|---------|--------|---------|
| Chromium | Desktop Chrome | Primary browser |
| Firefox | Desktop Firefox | Cross-browser |
| WebKit | Desktop Safari | Safari compatibility |
| Chromium | Pixel 5 | Android mobile |
| WebKit | iPhone 12 | iOS mobile |

### Test Settings

```typescript
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
});
```

### Development Server

Playwright automatically starts the development server:

```typescript
webServer: {
  command: 'npm run dev',
  url: 'http://localhost:3000',
  reuseExistingServer: !process.env.CI,
  timeout: 120000,
},
```

## WebAuthn Mocking

### Why Mock WebAuthn

WebAuthn requires:
- Hardware authenticator (security key) or platform authenticator (TouchID, FaceID)
- Secure context (HTTPS or localhost)
- User interaction

In CI environments, these aren't available. The mock simulates successful WebAuthn operations.

### Mock Implementation

The mock is located at `e2e/fixtures/webauthn-mock.ts`:

```typescript
import { Page } from '@playwright/test';

export interface WebAuthnMockOptions {
  userHandle?: string;
  credentialId?: string;
  publicKey?: string;
}

export async function mockWebAuthn(
  page: Page,
  options: WebAuthnMockOptions = {}
) {
  const {
    userHandle = 'mock-user-handle',
    credentialId = 'mock-credential-id',
    publicKey = 'mock-public-key',
  } = options;

  await page.addInitScript((opts) => {
    // Mock PublicKeyCredential
    if (!window.PublicKeyCredential) {
      (window as any).PublicKeyCredential = class {
        static isUserVerifyingPlatformAuthenticatorAvailable() {
          return Promise.resolve(true);
        }
        static isConditionalMediationAvailable() {
          return Promise.resolve(true);
        }
      };
    }

    // Mock navigator.credentials.create
    const originalCreate = navigator.credentials.create;
    navigator.credentials.create = async function (options: any) {
      if (options.publicKey) {
        return {
          id: opts.credentialId,
          rawId: new TextEncoder().encode(opts.credentialId).buffer,
          type: 'public-key',
          response: {
            clientDataJSON: new TextEncoder().encode(JSON.stringify({
              type: 'webauthn.create',
              challenge: btoa('mock-challenge'),
              origin: window.location.origin,
            })).buffer,
            attestationObject: new TextEncoder().encode('mock-attestation').buffer,
            getTransports: () => ['internal'],
            getAuthenticatorData: () => new Uint8Array(0).buffer,
            getPublicKey: () => new TextEncoder().encode(opts.publicKey).buffer,
            getPublicKeyAlgorithm: () => -7,
          },
          getClientExtensionResults: () => ({}),
        };
      }
      return originalCreate.call(this, options);
    };

    // Mock navigator.credentials.get (similar pattern)
    // ...
  }, { userHandle, credentialId, publicKey });
}
```

### Using the Mock

```typescript
import { test, expect } from '@playwright/test';
import { mockWebAuthn } from './fixtures/webauthn-mock';

test.describe('Authentication Flow', () => {
  test.beforeEach(async ({ page }) => {
    // Install WebAuthn mocks before each test
    await mockWebAuthn(page);
  });

  test('should register with WebAuthn', async ({ page }) => {
    await page.goto('/auth/webauthn?status=not_registered');
    // Test registration flow
  });
});
```

### Mock Limitations

The mock:
- Does NOT verify signatures (server must handle this)
- Returns static credential data
- Does NOT test actual biometric prompts
- Requires backend to accept mock credentials for full E2E

## Test Examples

### Authentication Flow Tests

```typescript
// e2e/auth.spec.ts
import { test, expect } from '@playwright/test';
import { mockWebAuthn } from './fixtures/webauthn-mock';

test.describe('Authentication Flow', () => {
  test.beforeEach(async ({ page }) => {
    await mockWebAuthn(page);
  });

  test('should display registration form by default', async ({ page }) => {
    await page.goto('/auth/webauthn?status=not_registered');

    await expect(page.locator('h2')).toContainText('Register');
    await expect(page.getByPlaceholder('Enter your email')).toBeVisible();
    await expect(page.getByRole('button', { name: /register/i })).toBeVisible();
  });

  test('should toggle between registration and login forms', async ({ page }) => {
    await page.goto('/auth/webauthn?status=not_registered');

    // Should show registration form
    await expect(page.locator('h2')).toContainText('Register');

    // Click to switch to login
    await page.click('text=Already have an account? Log In');
    await expect(page.locator('h2')).toContainText('Login');

    // Click to switch back to registration
    await page.click('text=Don\'t have an account? Register');
    await expect(page.locator('h2')).toContainText('Register');
  });

  test('should validate username input', async ({ page }) => {
    await page.goto('/auth/webauthn?status=not_registered');

    // Click register without entering username
    await page.click('button:has-text("Register")');

    // Should show validation error
    await expect(page.getByText(/please enter your email address/i)).toBeVisible();
  });
});
```

### Protected Route Tests

```typescript
test.describe('Protected Routes', () => {
  test('should redirect to login when not authenticated', async ({ page }) => {
    await page.goto('/admin/tenant');

    // Should be redirected to login
    await expect(page).toHaveURL(/\/auth\/webauthn/);
  });
});
```

### Invitation Flow Tests

```typescript
test('should show invitation UI when invitation token is present', async ({ page }) => {
  await page.goto('/auth/webauthn?invitation=mock-token&tenant_name=Test%20Workspace');

  await expect(page.locator('h2')).toContainText('Join Workspace');
  await expect(page.getByText(/invited to join Test Workspace/i)).toBeVisible();
});
```

## CI Integration

### GitHub Actions Example

```yaml
name: E2E Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install dependencies
        working-directory: ./web
        run: yarn install --frozen-lockfile

      - name: Install Playwright browsers
        working-directory: ./web
        run: npx playwright install --with-deps

      - name: Run E2E tests
        working-directory: ./web
        run: yarn test:e2e

      - name: Upload test report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: playwright-report
          path: web/playwright-report/
```

### CI Configuration

When `CI=true`:
- `forbidOnly: true` - Fail if `test.only` is present
- `retries: 2` - Retry failed tests twice
- `workers: 1` - Single worker for stability
- `reporter: 'github'` - GitHub Actions reporter

## Test Fixtures and Helpers

### Creating Custom Fixtures

```typescript
// e2e/fixtures/auth-fixture.ts
import { test as base, expect } from '@playwright/test';
import { mockWebAuthn } from './webauthn-mock';

// Create authenticated page fixture
export const test = base.extend({
  authenticatedPage: async ({ page }, use) => {
    await mockWebAuthn(page);

    // Set up mock JWT cookie
    await page.context().addCookies([{
      name: 'jwt',
      value: 'mock-jwt-token',
      domain: 'localhost',
      path: '/',
    }]);

    await use(page);
  },
});

export { expect };
```

### Using Custom Fixtures

```typescript
import { test, expect } from './fixtures/auth-fixture';

test.describe('Authenticated Tests', () => {
  test('should access tenant dashboard', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/admin/tenant');
    await expect(authenticatedPage.locator('h1')).toContainText('Tenant Dashboard');
  });
});
```

## Visual Testing

### Screenshot Comparison

```typescript
test('should match visual snapshot', async ({ page }) => {
  await page.goto('/auth/webauthn?status=not_registered');

  // Full page screenshot comparison
  await expect(page).toHaveScreenshot('auth-registration.png');

  // Component screenshot comparison
  await expect(page.locator('.card')).toHaveScreenshot('registration-card.png');
});
```

### Update Snapshots

```bash
# Update all snapshots
npx playwright test --update-snapshots
```

## Test Reports

### HTML Report

After running tests:

```bash
# View HTML report
npx playwright show-report
```

Report location: `web/playwright-report/`

### Traces

Traces are captured on first retry. View them:

```bash
# Open trace viewer
npx playwright show-trace trace.zip
```

## Best Practices

### Test Organization

1. Group related tests with `test.describe`
2. Use meaningful test names
3. One assertion per test when possible
4. Use page object pattern for complex pages

### Test Stability

1. Avoid hard waits (`page.waitForTimeout`)
2. Use locator strategies that survive UI changes
3. Mock external dependencies
4. Use retries for flaky network tests

### Test Performance

1. Run tests in parallel when possible
2. Reuse browser context when appropriate
3. Skip slow tests in development
4. Use test isolation to avoid state leakage
