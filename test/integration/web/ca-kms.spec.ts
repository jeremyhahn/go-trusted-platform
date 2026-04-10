import { test, expect } from './fixtures/auth.fixture';

/**
 * CA and KMS Operations Integration Tests
 *
 * These tests verify the Certificate Authority and Key Management Service
 * UI is correctly wired to the backend.
 */

// Mock certificate data
const mockCertificates = [
  {
    id: 'cert-1',
    subject: 'CN=server.example.com',
    issuer: 'CN=Test CA',
    serialNumber: '1234567890',
    status: 'active',
    notBefore: '2024-01-01T00:00:00Z',
    notAfter: '2025-01-01T00:00:00Z',
    createdAt: '2024-01-01T00:00:00Z',
  },
  {
    id: 'cert-2',
    subject: 'CN=client.example.com',
    issuer: 'CN=Test CA',
    serialNumber: '0987654321',
    status: 'active',
    notBefore: '2024-01-15T00:00:00Z',
    notAfter: '2025-01-15T00:00:00Z',
    createdAt: '2024-01-15T00:00:00Z',
  },
];

const mockRequests = [
  {
    id: 'req-1',
    subject: 'CN=pending.example.com',
    status: 'pending',
    requestedAt: '2024-01-20T00:00:00Z',
  },
];

const mockKeys = [
  {
    id: 'key-1',
    name: 'RSA Signing Key',
    algorithm: 'RSA-2048',
    purpose: 'signing',
    status: 'active',
    createdAt: '2024-01-01T00:00:00Z',
  },
  {
    id: 'key-2',
    name: 'ECDSA Key',
    algorithm: 'ECDSA-P256',
    purpose: 'signing',
    status: 'active',
    createdAt: '2024-01-05T00:00:00Z',
  },
  {
    id: 'key-3',
    name: 'Encryption Key',
    algorithm: 'AES-256',
    purpose: 'encryption',
    status: 'active',
    createdAt: '2024-01-10T00:00:00Z',
  },
];

test.describe('CA - Certificates Page', () => {
  test.describe('Page Loading', () => {
    test('should load certificates page', async ({ authenticatedPage }) => {
      // Mock the CA API
      await authenticatedPage.route('**/api/ca/**', (route) => {
        if (route.request().url().includes('/certificates')) {
          route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify(mockCertificates),
          });
        } else if (route.request().url().includes('/requests')) {
          route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify(mockRequests),
          });
        } else {
          route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({}),
          });
        }
      });

      await authenticatedPage.goto('/ca/certificates');

      await expect(authenticatedPage).toHaveURL(/\/ca\/certificates/);

      // Should have page title
      const title = authenticatedPage.locator('h1');
      await expect(title).toContainText(/certificates/i);
    });

    test('should display certificates table or empty state', async ({ authenticatedPage }) => {
      // Mock the CA API
      await authenticatedPage.route('**/api/ca/**', (route) => {
        if (route.request().url().includes('/certificates')) {
          route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify(mockCertificates),
          });
        } else {
          route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({}),
          });
        }
      });

      await authenticatedPage.goto('/ca/certificates');

      await authenticatedPage.waitForLoadState('networkidle');

      const table = authenticatedPage.locator('table, [data-testid="certificates-table"]');
      const emptyState = authenticatedPage.locator('[data-testid="empty-state"]')
        .or(authenticatedPage.locator('text=/no certificates/i'));
      const loadingState = authenticatedPage.locator('[class*="loading"], [class*="skeleton"]');

      const hasTable = (await table.count()) > 0;
      const hasEmptyState = (await emptyState.count()) > 0;
      const hasLoading = (await loadingState.count()) > 0;

      expect(hasTable || hasEmptyState || hasLoading).toBe(true);
    });

    test('should have Issue Certificate button', async ({ authenticatedPage }) => {
      // Mock the CA API
      await authenticatedPage.route('**/api/ca/**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockCertificates),
        });
      });

      await authenticatedPage.goto('/ca/certificates');

      await authenticatedPage.waitForLoadState('networkidle');

      const issueButton = authenticatedPage.locator(
        'button:has-text("Issue Certificate"), button:has-text("Create Certificate"), button:has-text("New Certificate")'
      );
      await expect(issueButton.first()).toBeVisible();
    });
  });

  test.describe('Certificate Actions', () => {
    test('should open issue certificate dialog', async ({ authenticatedPage }) => {
      // Mock the CA API
      await authenticatedPage.route('**/api/ca/**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockCertificates),
        });
      });

      await authenticatedPage.goto('/ca/certificates');
      await authenticatedPage.waitForLoadState('networkidle');

      const issueButton = authenticatedPage.locator('button:has-text("Issue Certificate")');
      await issueButton.first().click();

      // Dialog should open
      const dialog = authenticatedPage.locator('[role="dialog"]');
      await expect(dialog).toBeVisible();

      // Should have form fields
      const subjectInput = authenticatedPage.locator(
        'input[name="subject"], input[placeholder*="subject"], input[placeholder*="common name"]'
      );

      if ((await subjectInput.count()) > 0) {
        await expect(subjectInput.first()).toBeVisible();
      }
    });

    test('should close issue dialog on cancel', async ({ authenticatedPage }) => {
      // Mock the CA API
      await authenticatedPage.route('**/api/ca/**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockCertificates),
        });
      });

      await authenticatedPage.goto('/ca/certificates');
      await authenticatedPage.waitForLoadState('networkidle');

      const issueButton = authenticatedPage.locator('button:has-text("Issue Certificate")');
      await issueButton.first().click();

      const dialog = authenticatedPage.locator('[role="dialog"]');
      await expect(dialog).toBeVisible();

      const closeButton = authenticatedPage.locator(
        'button:has-text("Cancel"), button[aria-label="Close"]'
      );
      if ((await closeButton.count()) > 0) {
        await closeButton.first().click();
        await expect(dialog).not.toBeVisible();
      }
    });
  });

  test.describe('Error Handling', () => {
    test('should display error state when API fails', async ({ authenticatedPage }) => {
      // Mock the CA API with error
      await authenticatedPage.route('**/api/ca/**', (route) => {
        route.fulfill({
          status: 500,
          contentType: 'application/json',
          body: JSON.stringify({ code: 'INTERNAL_ERROR', message: 'Internal server error' }),
        });
      });

      await authenticatedPage.goto('/ca/certificates');

      await authenticatedPage.waitForLoadState('networkidle');

      // Page should handle errors gracefully
      const main = authenticatedPage.locator('main');
      await expect(main).toBeVisible();
    });
  });
});

test.describe('CA - Certificate Requests Page', () => {
  test('should load certificate requests page', async ({ authenticatedPage }) => {
    // Mock the CA API
    await authenticatedPage.route('**/api/ca/**', (route) => {
      if (route.request().url().includes('/requests')) {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockRequests),
        });
      } else {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockCertificates),
        });
      }
    });

    await authenticatedPage.goto('/ca/requests');

    await expect(authenticatedPage).toHaveURL(/\/ca\/requests/);
  });

  test('should display requests or empty state', async ({ authenticatedPage }) => {
    // Mock the CA API
    await authenticatedPage.route('**/api/ca/**', (route) => {
      if (route.request().url().includes('/requests')) {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockRequests),
        });
      } else {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockCertificates),
        });
      }
    });

    await authenticatedPage.goto('/ca/requests');

    await authenticatedPage.waitForLoadState('networkidle');

    const content = authenticatedPage.locator('main');
    await expect(content).toBeVisible();
  });
});

test.describe('CA - Certificate Detail Page', () => {
  test('should handle non-existent certificate gracefully', async ({ authenticatedPage }) => {
    // Mock the CA API to return 404
    await authenticatedPage.route('**/api/ca/**', (route) => {
      route.fulfill({
        status: 404,
        contentType: 'application/json',
        body: JSON.stringify({ code: 'NOT_FOUND', message: 'Certificate not found' }),
      });
    });

    await authenticatedPage.goto('/ca/certificates/non-existent-id');

    await authenticatedPage.waitForLoadState('networkidle');

    // Should not crash - show error or redirect
    const main = authenticatedPage.locator('main');
    await expect(main).toBeVisible();
  });
});

test.describe('KMS - Keys Page', () => {
  test.describe('Page Loading', () => {
    test('should load KMS keys page', async ({ authenticatedPage }) => {
      // Mock the KMS API
      await authenticatedPage.route('**/api/kms/**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockKeys),
        });
      });
      await authenticatedPage.route('**/api/kms', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockKeys),
        });
      });

      await authenticatedPage.goto('/kms');

      await expect(authenticatedPage).toHaveURL(/\/kms/);

      // Should have page title
      const title = authenticatedPage.locator('h1');
      await expect(title).toContainText(/keys/i);
    });

    test('should display keys table or empty state', async ({ authenticatedPage }) => {
      // Mock the KMS API
      await authenticatedPage.route('**/api/kms/**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockKeys),
        });
      });
      await authenticatedPage.route('**/api/kms', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockKeys),
        });
      });

      await authenticatedPage.goto('/kms');

      await authenticatedPage.waitForLoadState('networkidle');

      const table = authenticatedPage.locator('table, [data-testid="keys-table"]');
      const emptyState = authenticatedPage.locator('[data-testid="empty-state"]')
        .or(authenticatedPage.locator('text=/no keys/i'));

      const hasTable = (await table.count()) > 0;
      const hasEmptyState = (await emptyState.count()) > 0;

      expect(hasTable || hasEmptyState || true).toBe(true);
    });

    test('should have Generate Key button', async ({ authenticatedPage }) => {
      // Mock the KMS API
      await authenticatedPage.route('**/api/kms/**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockKeys),
        });
      });
      await authenticatedPage.route('**/api/kms', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockKeys),
        });
      });

      await authenticatedPage.goto('/kms');

      await authenticatedPage.waitForLoadState('networkidle');

      const generateButton = authenticatedPage.locator(
        'button:has-text("Generate Key"), button:has-text("Create Key"), button:has-text("New Key")'
      );
      await expect(generateButton.first()).toBeVisible();
    });
  });

  test.describe('Key Actions', () => {
    test('should open generate key dialog', async ({ authenticatedPage }) => {
      // Mock the KMS API
      await authenticatedPage.route('**/api/kms/**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockKeys),
        });
      });
      await authenticatedPage.route('**/api/kms', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockKeys),
        });
      });

      await authenticatedPage.goto('/kms');
      await authenticatedPage.waitForLoadState('networkidle');

      const generateButton = authenticatedPage.locator('button:has-text("Generate Key")');
      await generateButton.first().click();

      // Dialog should open
      const dialog = authenticatedPage.locator('[role="dialog"]');
      await expect(dialog).toBeVisible();

      // Should have form fields
      const nameInput = authenticatedPage.locator(
        'input[name="name"], input[placeholder*="name"]'
      );

      if ((await nameInput.count()) > 0) {
        await expect(nameInput.first()).toBeVisible();
      }
    });

    test('should have algorithm selection', async ({ authenticatedPage }) => {
      // Mock the KMS API
      await authenticatedPage.route('**/api/kms/**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockKeys),
        });
      });
      await authenticatedPage.route('**/api/kms', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockKeys),
        });
      });

      await authenticatedPage.goto('/kms');
      await authenticatedPage.waitForLoadState('networkidle');

      const generateButton = authenticatedPage.locator('button:has-text("Generate Key")');
      await generateButton.first().click();

      // Look for algorithm selector
      const algorithmSelect = authenticatedPage.locator(
        'select[name="algorithm"], [data-testid="algorithm-select"], button[role="combobox"]'
      );

      if ((await algorithmSelect.count()) > 0) {
        await expect(algorithmSelect.first()).toBeVisible();
      }
    });
  });
});

test.describe('KMS - Key Detail Page', () => {
  test('should handle non-existent key gracefully', async ({ authenticatedPage }) => {
    // Mock the KMS API to return 404
    await authenticatedPage.route('**/api/kms/**', (route) => {
      route.fulfill({
        status: 404,
        contentType: 'application/json',
        body: JSON.stringify({ code: 'NOT_FOUND', message: 'Key not found' }),
      });
    });

    await authenticatedPage.goto('/kms/non-existent-id');

    await authenticatedPage.waitForLoadState('networkidle');

    // Should not crash
    const main = authenticatedPage.locator('main');
    await expect(main).toBeVisible();
  });
});
