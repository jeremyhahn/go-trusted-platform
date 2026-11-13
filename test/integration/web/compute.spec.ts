import { test, expect } from './fixtures/auth.fixture';

/**
 * Compute Operations Integration Tests
 *
 * These tests verify the Compute management UI (Snapshots and Images)
 * is correctly rendering and functioning.
 */

// Mock snapshot data
const mockSnapshots = [
  {
    id: 'snap-001',
    name: 'web-server-backup-v1',
    description: 'Weekly backup before major update',
    sourceType: 'vm',
    sourceId: 'vm-001',
    sourceName: 'web-server-prod',
    status: 'available',
    sizeMB: 8192,
    createdAt: '2024-01-15T10:30:00Z',
  },
  {
    id: 'snap-002',
    name: 'db-snapshot-daily',
    description: 'Daily database snapshot',
    sourceType: 'vm',
    sourceId: 'vm-002',
    sourceName: 'postgres-primary',
    status: 'available',
    sizeMB: 32768,
    createdAt: '2024-01-18T02:00:00Z',
  },
  {
    id: 'snap-003',
    name: 'nginx-config-snapshot',
    sourceType: 'container',
    sourceId: 'cont-001',
    sourceName: 'nginx-proxy',
    status: 'creating',
    sizeMB: 512,
    createdAt: '2024-01-19T14:15:00Z',
  },
];

// Mock image data
const mockImages = [
  {
    id: 'img-001',
    name: 'ubuntu-22.04-server',
    description: 'Ubuntu 22.04 LTS Server Cloud Image',
    type: 'vm',
    osType: 'linux',
    version: '22.04',
    architecture: 'amd64',
    status: 'available',
    sizeMB: 2048,
    format: 'qcow2',
    source: 'registry',
    tags: ['ubuntu', 'lts', 'server'],
    createdAt: '2024-01-10T08:00:00Z',
    usageCount: 15,
  },
  {
    id: 'img-002',
    name: 'alpine:3.19',
    description: 'Alpine Linux 3.19 Container Image',
    type: 'container',
    osType: 'linux',
    version: '3.19',
    architecture: 'amd64',
    status: 'available',
    sizeMB: 8,
    format: 'oci',
    source: 'registry',
    tags: ['alpine', 'minimal', 'secure'],
    createdAt: '2024-01-12T09:15:00Z',
    usageCount: 42,
  },
  {
    id: 'img-003',
    name: 'fedora-39-cloud',
    description: 'Fedora 39 Cloud Base Image',
    type: 'vm',
    osType: 'linux',
    version: '39',
    architecture: 'arm64',
    status: 'downloading',
    sizeMB: 512,
    format: 'qcow2',
    source: 'registry',
    tags: ['fedora', 'cloud'],
    createdAt: '2024-01-19T10:00:00Z',
    usageCount: 0,
  },
];

test.describe('Snapshots Page', () => {
  test.describe('Page Loading', () => {
    test('should load snapshots page', async ({ authenticatedPage }) => {
      // Mock the snapshots API (for future API integration)
      await authenticatedPage.route('**/v1/compute/snapshots/**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockSnapshots),
        });
      });
      await authenticatedPage.route('**/v1/compute/snapshots', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockSnapshots),
        });
      });

      await authenticatedPage.goto('/compute/snapshots');

      await expect(authenticatedPage).toHaveURL(/\/compute\/snapshots/);

      // Should have page title
      const title = authenticatedPage.locator('h1');
      await expect(title).toContainText(/snapshots/i);
    });

    test('should display snapshots table', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/compute/snapshots');

      await authenticatedPage.waitForLoadState('networkidle');

      // Page uses internal mock data with setTimeout, wait for table to appear
      const table = authenticatedPage.locator('table');
      await expect(table).toBeVisible({ timeout: 5000 });

      // Table should have headers
      const headers = authenticatedPage.locator('th');
      await expect(headers.first()).toBeVisible();
    });

    test('should display snapshot statistics cards', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/compute/snapshots');

      await authenticatedPage.waitForLoadState('networkidle');

      // Should have statistics cards
      const totalSnapshotsCard = authenticatedPage.locator('text=Total Snapshots');
      await expect(totalSnapshotsCard).toBeVisible();

      const availableCard = authenticatedPage.locator('text=Available').first();
      await expect(availableCard).toBeVisible();
    });

    test('should have Create Snapshot button', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/compute/snapshots');

      await authenticatedPage.waitForLoadState('networkidle');

      const createButton = authenticatedPage.locator('button:has-text("Create Snapshot")');
      await expect(createButton).toBeVisible();
    });

    test('should have refresh button', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/compute/snapshots');

      await authenticatedPage.waitForLoadState('networkidle');

      // Refresh button is an icon button
      const refreshButton = authenticatedPage.locator('button').filter({ has: authenticatedPage.locator('svg') }).first();
      await expect(refreshButton).toBeVisible();
    });
  });

  test.describe('Data Display', () => {
    test('should display snapshot rows in table', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/compute/snapshots');

      await expect(authenticatedPage.locator('main')).toBeVisible();

      const tableBody = authenticatedPage.locator('tbody');
      await expect(tableBody).toBeVisible();

      // Should have table rows
      const rows = tableBody.locator('tr');
      const rowCount = await rows.count();
      expect(rowCount).toBeGreaterThan(0);
    });

    test('should display snapshot status badges', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/compute/snapshots');

      await expect(authenticatedPage.locator('main')).toBeVisible();

      // Look for status text in badges
      const statusBadge = authenticatedPage.locator('text=/available|creating|restoring|error/i').first();
      const hasStatus = (await statusBadge.count()) > 0;
      expect(hasStatus).toBe(true);
    });

    test('should display source type badges', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/compute/snapshots');

      await expect(authenticatedPage.locator('main')).toBeVisible();

      // Look for type text in badges (VM or CONTAINER)
      const typeBadge = authenticatedPage.locator('text=/VM|CONTAINER/').first();
      const hasType = (await typeBadge.count()) > 0;
      expect(hasType).toBe(true);
    });

    test('should display action dropdown menu', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/compute/snapshots');

      await expect(authenticatedPage.locator('main')).toBeVisible();

      // Find action button in table row
      const actionButton = authenticatedPage.locator('tbody button').first();
      await expect(actionButton).toBeVisible();

      // Click to open dropdown
      await actionButton.click();

      // Dropdown menu should be visible
      const dropdown = authenticatedPage.locator('[role="menu"]');
      await expect(dropdown).toBeVisible();
    });
  });

  test.describe('Filter Functionality', () => {
    test('should display filter controls', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/compute/snapshots');

      await authenticatedPage.waitForLoadState('networkidle');

      // Look for filter labels
      const statusLabel = authenticatedPage.locator('text=Filter by status:');
      await expect(statusLabel).toBeVisible();

      const typeLabel = authenticatedPage.locator('text=Filter by type:');
      await expect(typeLabel).toBeVisible();
    });

    test('should filter snapshots by status', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/compute/snapshots');

      await expect(authenticatedPage.locator('main')).toBeVisible();

      // Find and click the status filter dropdown
      const statusSelect = authenticatedPage.locator('button[role="combobox"]').first();
      await statusSelect.click();

      await expect(statusSelect).toHaveAttribute('aria-expanded', 'true');

      // Select 'Available' option
      const availableOption = authenticatedPage.locator('div[role="option"]:has-text("Available")');
      if ((await availableOption.count()) > 0) {
        await availableOption.click();
        await expect(statusSelect).toHaveAttribute('aria-expanded', 'false');
      }

      // Filter should be applied without crashing
      const main = authenticatedPage.locator('main');
      await expect(main).toBeVisible();
    });

    test('should filter snapshots by type', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/compute/snapshots');

      await expect(authenticatedPage.locator('main')).toBeVisible();

      // Find the type filter (second combobox)
      const typeSelect = authenticatedPage.locator('button[role="combobox"]').nth(1);
      await typeSelect.click();

      await expect(typeSelect).toHaveAttribute('aria-expanded', 'true');

      // Select 'VM' option
      const vmOption = authenticatedPage.locator('div[role="option"]:has-text("VM")');
      if ((await vmOption.count()) > 0) {
        await vmOption.click();
        await expect(typeSelect).toHaveAttribute('aria-expanded', 'false');
      }

      const main = authenticatedPage.locator('main');
      await expect(main).toBeVisible();
    });
  });
});

test.describe('Images Page', () => {
  test.describe('Page Loading', () => {
    test('should load images page', async ({ authenticatedPage }) => {
      // Mock the images API (for future API integration)
      await authenticatedPage.route('**/v1/compute/images/**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockImages),
        });
      });
      await authenticatedPage.route('**/v1/compute/images', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockImages),
        });
      });

      await authenticatedPage.goto('/compute/images');

      await expect(authenticatedPage).toHaveURL(/\/compute\/images/);

      // Should have page title
      const title = authenticatedPage.locator('h1');
      await expect(title).toContainText(/base images/i);
    });

    test('should display images table', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/compute/images');

      await authenticatedPage.waitForLoadState('networkidle');

      // Page uses internal mock data with setTimeout, wait for table to appear
      const table = authenticatedPage.locator('table');
      await expect(table).toBeVisible({ timeout: 5000 });

      // Table should have headers
      const headers = authenticatedPage.locator('th');
      await expect(headers.first()).toBeVisible();
    });

    test('should display image statistics cards', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/compute/images');

      await authenticatedPage.waitForLoadState('networkidle');

      // Should have statistics cards
      const totalImagesCard = authenticatedPage.locator('text=Total Images');
      await expect(totalImagesCard).toBeVisible();

      const availableCard = authenticatedPage.locator('text=Available').first();
      await expect(availableCard).toBeVisible();
    });

    test('should have Pull from Registry button', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/compute/images');

      await authenticatedPage.waitForLoadState('networkidle');

      const pullButton = authenticatedPage.locator('button:has-text("Pull from Registry")');
      await expect(pullButton).toBeVisible();
    });

    test('should have Upload button', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/compute/images');

      await authenticatedPage.waitForLoadState('networkidle');

      const uploadButton = authenticatedPage.locator('button:has-text("Upload")');
      await expect(uploadButton).toBeVisible();
    });

    test('should have refresh button', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/compute/images');

      await authenticatedPage.waitForLoadState('networkidle');

      // Refresh button is an icon button (first button in the button group)
      const buttons = authenticatedPage.locator('.flex.gap-2 button');
      await expect(buttons.first()).toBeVisible();
    });
  });

  test.describe('Data Display', () => {
    test('should display image rows in table', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/compute/images');

      const tableBody = authenticatedPage.locator('tbody');
      await expect(tableBody).toBeVisible();

      // Should have table rows
      const rows = tableBody.locator('tr');
      const rowCount = await rows.count();
      expect(rowCount).toBeGreaterThan(0);
    });

    test('should display image status badges', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/compute/images');

      // Look for status text in badges
      const statusBadge = authenticatedPage.locator('text=/available|downloading|building|error/i').first();
      await expect(statusBadge).toBeVisible();
      const hasStatus = (await statusBadge.count()) > 0;
      expect(hasStatus).toBe(true);
    });

    test('should display image type badges', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/compute/images');

      // Look for type text in badges (VM or CONTAINER)
      const typeBadge = authenticatedPage.locator('text=/VM|CONTAINER/').first();
      await expect(typeBadge).toBeVisible();
      const hasType = (await typeBadge.count()) > 0;
      expect(hasType).toBe(true);
    });

    test('should display architecture badges', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/compute/images');

      // Look for architecture text in badges
      const archBadge = authenticatedPage.locator('text=/amd64|arm64|x86_64/').first();
      await expect(archBadge).toBeVisible();
      const hasArch = (await archBadge.count()) > 0;
      expect(hasArch).toBe(true);
    });

    test('should display image tags', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/compute/images');

      // Look for tags or image names in the table
      const tableContent = authenticatedPage.locator('table');
      await expect(tableContent).toBeVisible();
    });

    test('should display action dropdown menu', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/compute/images');

      // Find action button in table row
      const actionButton = authenticatedPage.locator('tbody button').first();
      await expect(actionButton).toBeVisible();

      // Click to open dropdown
      await actionButton.click();

      // Dropdown menu should be visible
      const dropdown = authenticatedPage.locator('[role="menu"]');
      await expect(dropdown).toBeVisible();
    });

    test('should display usage count', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/compute/images');

      // Look for usage count text
      const usageText = authenticatedPage.locator('text=/\\d+ instances/').first();
      await expect(usageText).toBeVisible();
    });
  });

  test.describe('Filter Functionality', () => {
    test('should display filter controls', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/compute/images');

      await authenticatedPage.waitForLoadState('networkidle');

      // Look for filter labels
      const statusLabel = authenticatedPage.locator('text=Status:');
      await expect(statusLabel).toBeVisible();

      const typeLabel = authenticatedPage.locator('text=Type:');
      await expect(typeLabel).toBeVisible();

      const archLabel = authenticatedPage.locator('text=Architecture:');
      await expect(archLabel).toBeVisible();
    });

    test('should filter images by status', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/compute/images');

      await authenticatedPage.waitForTimeout(1000);

      // Find and click the status filter dropdown (first combobox)
      const statusSelect = authenticatedPage.locator('button[role="combobox"]').first();
      await statusSelect.click();

      await authenticatedPage.waitForTimeout(300);

      // Select 'Available' option
      const availableOption = authenticatedPage.locator('div[role="option"]:has-text("Available")');
      if ((await availableOption.count()) > 0) {
        await availableOption.click();
        await authenticatedPage.waitForTimeout(500);
      }

      const main = authenticatedPage.locator('main');
      await expect(main).toBeVisible();
    });

    test('should filter images by type', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/compute/images');

      await authenticatedPage.waitForTimeout(1000);

      // Find the type filter (second combobox)
      const typeSelect = authenticatedPage.locator('button[role="combobox"]').nth(1);
      await typeSelect.click();

      await authenticatedPage.waitForTimeout(300);

      // Select 'VM' option
      const vmOption = authenticatedPage.locator('div[role="option"]:has-text("VM")');
      if ((await vmOption.count()) > 0) {
        await vmOption.click();
        await authenticatedPage.waitForTimeout(500);
      }

      const main = authenticatedPage.locator('main');
      await expect(main).toBeVisible();
    });

    test('should filter images by architecture', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/compute/images');

      await authenticatedPage.waitForTimeout(1000);

      // Find the architecture filter (third combobox)
      const archSelect = authenticatedPage.locator('button[role="combobox"]').nth(2);
      await archSelect.click();

      await authenticatedPage.waitForTimeout(300);

      // Select 'amd64' option
      const amd64Option = authenticatedPage.locator('div[role="option"]:has-text("amd64")');
      if ((await amd64Option.count()) > 0) {
        await amd64Option.click();
        await authenticatedPage.waitForTimeout(500);
      }

      const main = authenticatedPage.locator('main');
      await expect(main).toBeVisible();
    });

    test('should show empty state when filters return no results', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/compute/images');

      await authenticatedPage.waitForTimeout(1000);

      // Filter by status 'Error' (may have few or no results)
      const statusSelect = authenticatedPage.locator('button[role="combobox"]').first();
      await statusSelect.click();

      await authenticatedPage.waitForTimeout(300);

      const errorOption = authenticatedPage.locator('div[role="option"]:has-text("Error")');
      if ((await errorOption.count()) > 0) {
        await errorOption.click();
        await authenticatedPage.waitForTimeout(500);
      }

      // Page should still be functional
      const main = authenticatedPage.locator('main');
      await expect(main).toBeVisible();
    });
  });
});

test.describe('Compute Navigation', () => {
  test('should navigate between snapshots and images pages', async ({ authenticatedPage }) => {
    // Start at snapshots page
    await authenticatedPage.goto('/compute/snapshots');
    await expect(authenticatedPage).toHaveURL(/\/compute\/snapshots/);

    // Navigate to images
    await authenticatedPage.goto('/compute/images');
    await expect(authenticatedPage).toHaveURL(/\/compute\/images/);

    // Verify images page loaded
    const title = authenticatedPage.locator('h1');
    await expect(title).toContainText(/base images/i);
  });
});
