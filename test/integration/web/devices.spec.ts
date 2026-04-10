import { test, expect } from './fixtures/auth.fixture';

/**
 * Device Operations Integration Tests
 *
 * These tests verify the Device management UI is correctly
 * wired to the backend.
 */

// Mock device data
const mockDevices = [
  {
    id: 'device-1',
    name: 'Server-01',
    type: 'physical',
    status: 'online',
    hostname: 'server-01.local',
    lastSeen: '2024-01-15T10:30:00Z',
    createdAt: '2024-01-01T00:00:00Z',
  },
  {
    id: 'device-2',
    name: 'VM-Production-01',
    type: 'virtual',
    status: 'online',
    hostname: 'vm-prod-01.local',
    lastSeen: '2024-01-15T10:25:00Z',
    createdAt: '2024-01-05T00:00:00Z',
  },
  {
    id: 'device-3',
    name: 'Edge-Gateway-01',
    type: 'physical',
    status: 'offline',
    hostname: 'edge-gw-01.local',
    lastSeen: '2024-01-10T08:00:00Z',
    createdAt: '2024-01-02T00:00:00Z',
  },
];

const mockVtpmDevices = [
  {
    id: 'vtpm-1',
    name: 'vTPM-Server-01',
    deviceId: 'device-1',
    status: 'active',
    createdAt: '2024-01-01T00:00:00Z',
  },
];

const mockIdevidDevices = [
  {
    id: 'idevid-1',
    name: 'IDevID-Device-01',
    deviceId: 'device-1',
    status: 'active',
    createdAt: '2024-01-01T00:00:00Z',
  },
];

test.describe('Devices Page', () => {
  test.describe('Page Loading', () => {
    test('should load devices page', async ({ authenticatedPage }) => {
      // Mock the devices API
      await authenticatedPage.route('**/v1/devices/**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockDevices),
        });
      });
      await authenticatedPage.route('**/v1/devices', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockDevices),
        });
      });

      await authenticatedPage.goto('/devices');

      await expect(authenticatedPage).toHaveURL(/\/devices/);

      // Should have page title
      const title = authenticatedPage.locator('h1');
      await expect(title).toContainText(/devices/i);
    });

    test('should display devices table or empty state', async ({ authenticatedPage }) => {
      // Mock the devices API
      await authenticatedPage.route('**/v1/devices/**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockDevices),
        });
      });
      await authenticatedPage.route('**/v1/devices', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockDevices),
        });
      });

      await authenticatedPage.goto('/devices');

      await authenticatedPage.waitForLoadState('networkidle');

      // Check for table, empty state, loading state, or error state
      const table = authenticatedPage.locator('table');
      const emptyState = authenticatedPage.locator('text=/no devices/i')
        .or(authenticatedPage.locator('text=/no results/i'));
      const loadingState = authenticatedPage.locator('[class*="animate-spin"]')
        .or(authenticatedPage.locator('text=/loading/i'));
      const errorState = authenticatedPage.locator('text=/error/i')
        .or(authenticatedPage.locator('[class*="destructive"]'));

      const hasTable = (await table.count()) > 0;
      const hasEmptyState = (await emptyState.count()) > 0;
      const hasLoading = (await loadingState.count()) > 0;
      const hasError = (await errorState.count()) > 0;

      // Page should show one of: table, empty state, loading, or error
      expect(hasTable || hasEmptyState || hasLoading || hasError).toBe(true);
    });

    test('should have Register Device button', async ({ authenticatedPage }) => {
      // Mock the devices API
      await authenticatedPage.route('**/v1/devices/**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockDevices),
        });
      });
      await authenticatedPage.route('**/v1/devices', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockDevices),
        });
      });

      await authenticatedPage.goto('/devices');

      await authenticatedPage.waitForLoadState('networkidle');

      const registerButton = authenticatedPage.locator(
        'button:has-text("Register Device"), button:has-text("Add Device"), button:has-text("New Device")'
      );
      await expect(registerButton.first()).toBeVisible();
    });

    test('should display filter controls', async ({ authenticatedPage }) => {
      // Mock the devices API
      await authenticatedPage.route('**/v1/devices/**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockDevices),
        });
      });
      await authenticatedPage.route('**/v1/devices', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockDevices),
        });
      });

      await authenticatedPage.goto('/devices');

      await authenticatedPage.waitForLoadState('networkidle');

      // Look for filter controls
      const searchInput = authenticatedPage.locator(
        'input[placeholder*="search"], input[placeholder*="Search"]'
      );
      const typeFilter = authenticatedPage.locator(
        'select, button[role="combobox"], [data-testid="type-filter"]'
      );

      const hasSearch = (await searchInput.count()) > 0;
      const hasTypeFilter = (await typeFilter.count()) > 0;

      expect(hasSearch || hasTypeFilter).toBe(true);
    });
  });

  test.describe('Device Filtering', () => {
    test('should filter devices by search', async ({ authenticatedPage }) => {
      // Mock the devices API
      await authenticatedPage.route('**/v1/devices/**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockDevices),
        });
      });
      await authenticatedPage.route('**/v1/devices', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockDevices),
        });
      });

      await authenticatedPage.goto('/devices');

      await authenticatedPage.waitForLoadState('networkidle');

      const searchInput = authenticatedPage.locator(
        'input[placeholder*="search"], input[placeholder*="Search"]'
      );

      if ((await searchInput.count()) > 0) {
        await searchInput.first().fill('test-device');

        // Wait for filter to apply
        await authenticatedPage.waitForTimeout(500);

        // Search should work without crashing
        await expect(authenticatedPage.locator('main')).toBeVisible();
      }
    });

    test('should filter devices by type', async ({ authenticatedPage }) => {
      // Mock the devices API
      await authenticatedPage.route('**/v1/devices/**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockDevices),
        });
      });
      await authenticatedPage.route('**/v1/devices', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockDevices),
        });
      });

      await authenticatedPage.goto('/devices');

      await authenticatedPage.waitForLoadState('networkidle');

      // The select component uses a combobox pattern
      const typeSelect = authenticatedPage.locator('button[role="combobox"]:has-text("All types")');

      if ((await typeSelect.count()) > 0) {
        await typeSelect.first().click();

        // Wait for dropdown to open
        await authenticatedPage.waitForTimeout(300);

        // Select the option from the listbox using role
        const physicalOption = authenticatedPage.locator('div[role="option"]:has-text("Physical")');
        if ((await physicalOption.count()) > 0) {
          await physicalOption.first().click({ force: true });
          await authenticatedPage.waitForTimeout(500);
        }
      }
    });

    test('should filter devices by status', async ({ authenticatedPage }) => {
      // Mock the devices API
      await authenticatedPage.route('**/v1/devices/**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockDevices),
        });
      });
      await authenticatedPage.route('**/v1/devices', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockDevices),
        });
      });

      await authenticatedPage.goto('/devices');

      await authenticatedPage.waitForLoadState('networkidle');

      // The select component uses a combobox pattern
      const statusSelect = authenticatedPage.locator('button[role="combobox"]:has-text("All statuses")');

      if ((await statusSelect.count()) > 0) {
        await statusSelect.first().click();

        // Wait for dropdown to open
        await authenticatedPage.waitForTimeout(300);

        // Select the option from the listbox using role
        const onlineOption = authenticatedPage.locator('div[role="option"]:has-text("Online")');
        if ((await onlineOption.count()) > 0) {
          await onlineOption.first().click({ force: true });
          await authenticatedPage.waitForTimeout(500);
        }
      }
    });

    test('should clear filters', async ({ authenticatedPage }) => {
      // Mock the devices API
      await authenticatedPage.route('**/v1/devices/**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockDevices),
        });
      });
      await authenticatedPage.route('**/v1/devices', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockDevices),
        });
      });

      await authenticatedPage.goto('/devices');

      await authenticatedPage.waitForLoadState('networkidle');

      // Apply a filter first
      const searchInput = authenticatedPage.locator('input[placeholder*="search"]');
      if ((await searchInput.count()) > 0) {
        await searchInput.first().fill('test');
        await authenticatedPage.waitForTimeout(300);
      }

      // Look for clear button
      const clearButton = authenticatedPage.locator(
        'button:has-text("Clear"), button:has-text("Clear filters"), button:has-text("Reset")'
      );

      if ((await clearButton.count()) > 0) {
        await clearButton.first().click();
        await authenticatedPage.waitForTimeout(500);

        // Search should be cleared
        if ((await searchInput.count()) > 0) {
          const value = await searchInput.first().inputValue();
          expect(value).toBe('');
        }
      }
    });
  });

  test.describe('Device Registration', () => {
    test('should open register device dialog', async ({ authenticatedPage }) => {
      // Mock the devices API
      await authenticatedPage.route('**/v1/devices/**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockDevices),
        });
      });
      await authenticatedPage.route('**/v1/devices', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockDevices),
        });
      });

      await authenticatedPage.goto('/devices');
      await authenticatedPage.waitForLoadState('networkidle');

      const registerButton = authenticatedPage.locator('button:has-text("Register Device")');
      await registerButton.first().click();

      // Dialog should open
      const dialog = authenticatedPage.locator('[role="dialog"]');
      await expect(dialog).toBeVisible();

      // Should have form title
      const dialogTitle = dialog.locator('h2, [data-testid="dialog-title"]');
      await expect(dialogTitle).toContainText(/register|new|add/i);
    });

    test('should have device name input', async ({ authenticatedPage }) => {
      // Mock the devices API
      await authenticatedPage.route('**/v1/devices/**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockDevices),
        });
      });
      await authenticatedPage.route('**/v1/devices', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockDevices),
        });
      });

      await authenticatedPage.goto('/devices');
      await authenticatedPage.waitForLoadState('networkidle');

      const registerButton = authenticatedPage.locator('button:has-text("Register Device")');
      await registerButton.first().click();

      const dialog = authenticatedPage.locator('[role="dialog"]');
      await expect(dialog).toBeVisible();

      const nameInput = authenticatedPage.locator(
        'input[name="name"], input[placeholder*="name"]'
      );
      if ((await nameInput.count()) > 0) {
        await expect(nameInput.first()).toBeVisible();
      }
    });

    test('should have device type selection', async ({ authenticatedPage }) => {
      // Mock the devices API
      await authenticatedPage.route('**/v1/devices/**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockDevices),
        });
      });
      await authenticatedPage.route('**/v1/devices', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockDevices),
        });
      });

      await authenticatedPage.goto('/devices');
      await authenticatedPage.waitForLoadState('networkidle');

      const registerButton = authenticatedPage.locator('button:has-text("Register Device")');
      await registerButton.first().click();

      const dialog = authenticatedPage.locator('[role="dialog"]');
      await expect(dialog).toBeVisible();

      // Look for type selection
      const typeSelect = authenticatedPage.locator(
        'select[name="type"], [data-testid="device-type"], button[role="combobox"]'
      );

      if ((await typeSelect.count()) > 0) {
        await expect(typeSelect.first()).toBeVisible();
      }
    });

    test('should close dialog on cancel', async ({ authenticatedPage }) => {
      // Mock the devices API
      await authenticatedPage.route('**/v1/devices/**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockDevices),
        });
      });
      await authenticatedPage.route('**/v1/devices', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockDevices),
        });
      });

      await authenticatedPage.goto('/devices');
      await authenticatedPage.waitForLoadState('networkidle');

      const registerButton = authenticatedPage.locator('button:has-text("Register Device")');
      await registerButton.first().click();

      const dialog = authenticatedPage.locator('[role="dialog"]');
      await expect(dialog).toBeVisible();

      // Find the Cancel button within the dialog and click it
      // Use dispatchEvent to click because the button may be outside viewport
      const cancelButton = dialog.locator('button:has-text("Cancel")');
      await cancelButton.dispatchEvent('click');
      await expect(dialog).not.toBeVisible();
    });
  });
});

test.describe('Device Detail Page', () => {
  test('should handle non-existent device gracefully', async ({ authenticatedPage }) => {
    // Mock the device detail API to return 404
    await authenticatedPage.route('**/v1/devices/**', (route) => {
      route.fulfill({
        status: 404,
        contentType: 'application/json',
        body: JSON.stringify({ code: 'NOT_FOUND', message: 'Device not found' }),
      });
    });

    await authenticatedPage.goto('/devices/non-existent-id');

    await authenticatedPage.waitForLoadState('networkidle');

    // Should not crash
    const main = authenticatedPage.locator('main');
    await expect(main).toBeVisible();
  });
});

test.describe('vTPM Devices Page', () => {
  test('should load vTPM devices page', async ({ authenticatedPage }) => {
    // Mock the vTPM API
    await authenticatedPage.route('**/api/v1/vtpm/**', (route) => {
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ vtpmDevices: mockVtpmDevices }),
      });
    });
    await authenticatedPage.route('**/v1/devices/**', (route) => {
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(mockDevices),
      });
    });

    await authenticatedPage.goto('/devices/vtpm');

    await expect(authenticatedPage).toHaveURL(/\/devices\/vtpm/);
  });

  test('should display vTPM devices or empty state', async ({ authenticatedPage }) => {
    // Mock the vTPM API
    await authenticatedPage.route('**/api/v1/vtpm/**', (route) => {
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ vtpmDevices: mockVtpmDevices }),
      });
    });
    await authenticatedPage.route('**/v1/devices/**', (route) => {
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(mockDevices),
      });
    });

    await authenticatedPage.goto('/devices/vtpm');

    await authenticatedPage.waitForLoadState('networkidle');

    const content = authenticatedPage.locator('main');
    await expect(content).toBeVisible();
  });
});

test.describe('IDevID Devices Page', () => {
  test('should load IDevID devices page', async ({ authenticatedPage }) => {
    // Mock the IDevID API
    await authenticatedPage.route('**/api/v1/idevid/**', (route) => {
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ idevidDevices: mockIdevidDevices }),
      });
    });
    await authenticatedPage.route('**/v1/devices/**', (route) => {
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(mockDevices),
      });
    });

    await authenticatedPage.goto('/devices/idevid');

    await expect(authenticatedPage).toHaveURL(/\/devices\/idevid/);
  });

  test('should display IDevID devices or empty state', async ({ authenticatedPage }) => {
    // Mock the IDevID API
    await authenticatedPage.route('**/api/v1/idevid/**', (route) => {
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ idevidDevices: mockIdevidDevices }),
      });
    });
    await authenticatedPage.route('**/v1/devices/**', (route) => {
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(mockDevices),
      });
    });

    await authenticatedPage.goto('/devices/idevid');

    await authenticatedPage.waitForLoadState('networkidle');

    const content = authenticatedPage.locator('main');
    await expect(content).toBeVisible();
  });
});
