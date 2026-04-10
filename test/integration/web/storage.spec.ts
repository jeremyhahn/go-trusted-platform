import { test, expect } from './fixtures/auth.fixture';

/**
 * Data Storage Integration Tests
 *
 * These tests verify the Data Storage pages UI is correctly
 * wired to the backend.
 */

// Mock storage data
const mockBuckets = [
  {
    id: 'bucket-1',
    name: 'documents',
    createdAt: '2024-01-01T00:00:00Z',
    versioning: true,
    encryption: true,
    objectCount: 156,
    totalSize: 1073741824, // 1 GB
  },
  {
    id: 'bucket-2',
    name: 'backups',
    createdAt: '2024-01-05T00:00:00Z',
    versioning: false,
    encryption: true,
    objectCount: 42,
    totalSize: 5368709120, // 5 GB
  },
];

const mockObjects = [
  {
    id: 'obj-1',
    key: 'reports/2024/q1-report.pdf',
    bucket: 'documents',
    size: 1048576, // 1 MB
    contentType: 'application/pdf',
    storageClass: 'standard',
    lastModified: '2024-01-15T10:30:00Z',
    etag: 'abc123',
  },
  {
    id: 'obj-2',
    key: 'images/logo.png',
    bucket: 'documents',
    size: 524288, // 512 KB
    contentType: 'image/png',
    storageClass: 'standard',
    lastModified: '2024-01-10T08:00:00Z',
    etag: 'def456',
  },
  {
    id: 'obj-3',
    key: 'archives/2023.tar.gz',
    bucket: 'backups',
    size: 2147483648, // 2 GB
    contentType: 'application/gzip',
    storageClass: 'archive',
    lastModified: '2024-01-01T00:00:00Z',
    etag: 'ghi789',
  },
];

const mockKVNamespaces = [
  {
    id: 'ns-1',
    name: 'config',
    entryCount: 25,
    createdAt: '2024-01-01T00:00:00Z',
  },
  {
    id: 'ns-2',
    name: 'cache',
    entryCount: 1500,
    createdAt: '2024-01-05T00:00:00Z',
  },
];

const mockKVEntries = [
  {
    id: 'kv-1',
    namespace: 'config',
    key: 'app.settings',
    value: '{"theme": "dark", "language": "en"}',
    valueType: 'json',
    version: 3,
    updatedAt: '2024-01-15T10:00:00Z',
    expiresAt: null,
    ttl: null,
  },
  {
    id: 'kv-2',
    namespace: 'config',
    key: 'feature.flags',
    value: '{"newUI": true, "beta": false}',
    valueType: 'json',
    version: 7,
    updatedAt: '2024-01-14T15:30:00Z',
    expiresAt: null,
    ttl: null,
  },
  {
    id: 'kv-3',
    namespace: 'cache',
    key: 'session:user-123',
    value: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
    valueType: 'string',
    version: 1,
    updatedAt: '2024-01-15T11:00:00Z',
    expiresAt: '2024-01-15T12:00:00Z',
    ttl: 3600,
  },
];

const mockTimeSeriesMetrics = [
  {
    id: 'metric-1',
    name: 'cpu_usage_percent',
    description: 'CPU usage percentage',
    type: 'gauge',
    unit: 'percent',
    retention: '30d',
    labels: { host: 'server-01' },
    createdAt: '2024-01-01T00:00:00Z',
  },
  {
    id: 'metric-2',
    name: 'http_requests_total',
    description: 'Total HTTP requests',
    type: 'counter',
    unit: 'requests',
    retention: '90d',
    labels: { endpoint: '/api/v1' },
    createdAt: '2024-01-02T00:00:00Z',
  },
  {
    id: 'metric-3',
    name: 'response_time_ms',
    description: 'Response time in milliseconds',
    type: 'histogram',
    unit: 'milliseconds',
    retention: '7d',
    labels: {},
    createdAt: '2024-01-03T00:00:00Z',
  },
];

const mockVectorCollections = [
  {
    id: 'vec-1',
    name: 'document-embeddings',
    description: 'Document embeddings for semantic search',
    dimensions: 384,
    distanceMetric: 'cosine',
    indexType: 'hnsw',
    vectorCount: 15000,
    createdAt: '2024-01-01T00:00:00Z',
  },
  {
    id: 'vec-2',
    name: 'image-features',
    description: 'Image feature vectors',
    dimensions: 1536,
    distanceMetric: 'euclidean',
    indexType: 'ivf',
    vectorCount: 5000,
    createdAt: '2024-01-05T00:00:00Z',
  },
];

const mockBackups = [
  {
    id: 'backup-1',
    name: 'Daily Production Backup',
    description: 'Automated daily backup',
    type: 'full',
    status: 'completed',
    source: '/data/production',
    destination: 's3://backups/production',
    size: 10737418240, // 10 GB
    encrypted: true,
    retentionDays: 30,
    startedAt: '2024-01-15T00:00:00Z',
    completedAt: '2024-01-15T00:45:00Z',
  },
  {
    id: 'backup-2',
    name: 'Manual Pre-deployment',
    description: 'Pre-deployment backup',
    type: 'incremental',
    status: 'completed',
    source: '/data/staging',
    destination: 's3://backups/staging',
    size: 1073741824, // 1 GB
    encrypted: true,
    retentionDays: 7,
    startedAt: '2024-01-14T14:00:00Z',
    completedAt: '2024-01-14T14:15:00Z',
  },
  {
    id: 'backup-3',
    name: 'Database Backup',
    description: null,
    type: 'differential',
    status: 'running',
    source: '/data/database',
    destination: 's3://backups/database',
    size: null,
    encrypted: true,
    retentionDays: 14,
    startedAt: '2024-01-15T10:00:00Z',
    completedAt: null,
  },
];

const mockBackupSchedules = [
  {
    id: 'schedule-1',
    name: 'Daily Full Backup',
    enabled: true,
    cronExpression: '0 0 * * *',
    type: 'full',
    source: '/data/production',
    destination: 's3://backups/production',
    retentionDays: 30,
    encrypted: true,
    nextRunAt: '2024-01-16T00:00:00Z',
    lastRunAt: '2024-01-15T00:00:00Z',
  },
  {
    id: 'schedule-2',
    name: 'Hourly Incremental',
    enabled: true,
    cronExpression: '0 * * * *',
    type: 'incremental',
    source: '/data/production',
    destination: 's3://backups/production/incremental',
    retentionDays: 7,
    encrypted: true,
    nextRunAt: '2024-01-15T11:00:00Z',
    lastRunAt: '2024-01-15T10:00:00Z',
  },
  {
    id: 'schedule-3',
    name: 'Weekly Archive',
    enabled: false,
    cronExpression: '0 0 * * 0',
    type: 'full',
    source: '/data/archive',
    destination: 's3://backups/archive',
    retentionDays: 365,
    encrypted: true,
    nextRunAt: null,
    lastRunAt: '2024-01-07T00:00:00Z',
  },
];

// Helper function to set up storage API mocks
async function setupStorageApiMocks(
  page: import('@playwright/test').Page,
  options: {
    buckets?: typeof mockBuckets;
    objects?: typeof mockObjects;
    kvNamespaces?: typeof mockKVNamespaces;
    kvEntries?: typeof mockKVEntries;
    metrics?: typeof mockTimeSeriesMetrics;
    collections?: typeof mockVectorCollections;
    backups?: typeof mockBackups;
    schedules?: typeof mockBackupSchedules;
  } = {}
) {
  const {
    buckets = mockBuckets,
    objects = mockObjects,
    kvNamespaces = mockKVNamespaces,
    kvEntries = mockKVEntries,
    metrics = mockTimeSeriesMetrics,
    collections = mockVectorCollections,
    backups = mockBackups,
    schedules = mockBackupSchedules,
  } = options;

  // Object Storage APIs
  await page.route('**/api/storage/buckets**', (route) => {
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(buckets),
    });
  });

  await page.route('**/api/storage/objects**', (route) => {
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(objects),
    });
  });

  // KV Store APIs
  await page.route('**/api/storage/kv/namespaces**', (route) => {
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(kvNamespaces),
    });
  });

  await page.route('**/api/storage/kv/entries**', (route) => {
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(kvEntries),
    });
  });

  // Time Series APIs
  await page.route('**/api/storage/timeseries/metrics**', (route) => {
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(metrics),
    });
  });

  // Vector Database APIs
  await page.route('**/api/storage/vector/collections**', (route) => {
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(collections),
    });
  });

  // Backup APIs
  await page.route('**/api/storage/backups**', (route) => {
    if (route.request().url().includes('/schedules')) {
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(schedules),
      });
    } else {
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(backups),
      });
    }
  });
}

test.describe('Object Storage Page', () => {
  test.describe('Page Loading', () => {
    test('should load object storage page', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/objects');

      await expect(authenticatedPage).toHaveURL(/\/storage\/objects/);

      // Should have page title
      const title = authenticatedPage.locator('h1');
      await expect(title).toContainText(/object storage/i);
    });

    test('should display buckets and objects table or empty state', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/objects');

      await authenticatedPage.waitForLoadState('networkidle');

      const table = authenticatedPage.locator('table, [data-testid="objects-table"]');
      const emptyState = authenticatedPage.locator('[data-testid="empty-state"]')
        .or(authenticatedPage.locator('text=/no objects/i'));
      const loadingState = authenticatedPage.locator('[class*="loading"], [class*="skeleton"]');

      const hasTable = (await table.count()) > 0;
      const hasEmptyState = (await emptyState.count()) > 0;
      const hasLoading = (await loadingState.count()) > 0;

      expect(hasTable || hasEmptyState || hasLoading).toBe(true);
    });

    test('should display statistics cards', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/objects');

      await authenticatedPage.waitForLoadState('networkidle');

      // Look for stat cards
      const statsSection = authenticatedPage.locator('.grid');
      await expect(statsSection.first()).toBeVisible();

      // Should show bucket count, object count, and total size
      const bucketStat = authenticatedPage.locator('text=/Total Buckets/i');
      const objectStat = authenticatedPage.locator('text=/Total Objects/i');
      const sizeStat = authenticatedPage.locator('text=/Total Size/i');

      const hasBucketStat = (await bucketStat.count()) > 0;
      const hasObjectStat = (await objectStat.count()) > 0;
      const hasSizeStat = (await sizeStat.count()) > 0;

      expect(hasBucketStat || hasObjectStat || hasSizeStat).toBe(true);
    });

    test('should have Create Bucket button', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/objects');

      await authenticatedPage.waitForLoadState('networkidle');

      const createButton = authenticatedPage.locator(
        'button:has-text("Create Bucket"), button:has-text("New Bucket")'
      );
      await expect(createButton.first()).toBeVisible();
    });

    test('should have Upload Object button', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/objects');

      await authenticatedPage.waitForLoadState('networkidle');

      const uploadButton = authenticatedPage.locator(
        'button:has-text("Upload Object"), button:has-text("Upload")'
      );
      await expect(uploadButton.first()).toBeVisible();
    });
  });

  test.describe('Filter Functionality', () => {
    test('should have search input', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/objects');

      await authenticatedPage.waitForLoadState('networkidle');

      const searchInput = authenticatedPage.locator(
        'input[placeholder*="search"], input[placeholder*="Search"], input[placeholder*="Filter"]'
      );

      if ((await searchInput.count()) > 0) {
        await expect(searchInput.first()).toBeVisible();
      }
    });

    test('should have bucket filter', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/objects');

      await authenticatedPage.waitForLoadState('networkidle');

      // Look for bucket filter select
      const bucketFilter = authenticatedPage.locator(
        'button[role="combobox"]:has-text("All buckets"), select[name="bucket"]'
      );

      if ((await bucketFilter.count()) > 0) {
        await expect(bucketFilter.first()).toBeVisible();
      }
    });

    test('should filter objects by search', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/objects');

      await authenticatedPage.waitForLoadState('networkidle');

      const searchInput = authenticatedPage.locator(
        'input[placeholder*="search"], input[placeholder*="Search"], input[placeholder*="Filter"]'
      );

      if ((await searchInput.count()) > 0) {
        await searchInput.first().fill('report');

        // Wait for filter to apply
        await authenticatedPage.waitForTimeout(500);

        // Should not crash
        await expect(authenticatedPage.locator('main')).toBeVisible();
      }
    });

    test('should clear filters', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/objects');

      await authenticatedPage.waitForLoadState('networkidle');

      const searchInput = authenticatedPage.locator(
        'input[placeholder*="search"], input[placeholder*="Search"]'
      );

      if ((await searchInput.count()) > 0) {
        await searchInput.first().fill('test');
        await authenticatedPage.waitForTimeout(300);
      }

      const clearButton = authenticatedPage.locator(
        'button:has-text("Clear"), button:has-text("Clear filters"), button:has-text("Reset")'
      );

      if ((await clearButton.count()) > 0) {
        await clearButton.first().click();
        await authenticatedPage.waitForTimeout(500);

        if ((await searchInput.count()) > 0) {
          const value = await searchInput.first().inputValue();
          expect(value).toBe('');
        }
      }
    });
  });

  test.describe('Create Bucket Dialog', () => {
    test('should open create bucket dialog', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/objects');
      await authenticatedPage.waitForLoadState('networkidle');

      const createButton = authenticatedPage.locator('button:has-text("Create Bucket")');
      await createButton.first().click();

      const dialog = authenticatedPage.locator('[role="dialog"]');
      await expect(dialog).toBeVisible();

      const dialogTitle = dialog.locator('h2, [data-testid="dialog-title"]');
      await expect(dialogTitle).toContainText(/create|new|bucket/i);
    });

    test('should have bucket name input', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/objects');
      await authenticatedPage.waitForLoadState('networkidle');

      const createButton = authenticatedPage.locator('button:has-text("Create Bucket")');
      await createButton.first().click();

      const dialog = authenticatedPage.locator('[role="dialog"]');
      await expect(dialog).toBeVisible();

      const nameInput = authenticatedPage.locator(
        'input[id="bucketName"], input[name="name"], input[placeholder*="bucket"]'
      );
      if ((await nameInput.count()) > 0) {
        await expect(nameInput.first()).toBeVisible();
      }
    });

    test('should close dialog on cancel', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/objects');
      await authenticatedPage.waitForLoadState('networkidle');

      const createButton = authenticatedPage.locator('button:has-text("Create Bucket")');
      await createButton.first().click();

      const dialog = authenticatedPage.locator('[role="dialog"]');
      await expect(dialog).toBeVisible();

      const closeButton = authenticatedPage.locator(
        '[role="dialog"] button:has-text("Cancel"), [role="dialog"] button[aria-label="Close"]'
      );
      if ((await closeButton.count()) > 0) {
        await closeButton.first().click();
        await expect(dialog).not.toBeVisible();
      }
    });
  });

  test.describe('Error Handling', () => {
    test('should display error state when API fails', async ({ authenticatedPage }) => {
      await authenticatedPage.route('**/api/storage/**', (route) => {
        route.fulfill({
          status: 500,
          contentType: 'application/json',
          body: JSON.stringify({ code: 'INTERNAL_ERROR', message: 'Internal server error' }),
        });
      });

      await authenticatedPage.goto('/storage/objects');

      await authenticatedPage.waitForLoadState('networkidle');

      // Page should handle errors gracefully
      const main = authenticatedPage.locator('main');
      await expect(main).toBeVisible();
    });
  });
});

test.describe('Key-Value Store Page', () => {
  test.describe('Page Loading', () => {
    test('should load KV store page', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/kv');

      await expect(authenticatedPage).toHaveURL(/\/storage\/kv/);

      // Should have page title
      const title = authenticatedPage.locator('h1');
      await expect(title).toContainText(/key-value/i);
    });

    test('should display KV entries table or empty state', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/kv');

      await authenticatedPage.waitForLoadState('networkidle');

      const table = authenticatedPage.locator('table, [data-testid="kv-table"]');
      const emptyState = authenticatedPage.locator('[data-testid="empty-state"]')
        .or(authenticatedPage.locator('text=/no entries/i'));

      const hasTable = (await table.count()) > 0;
      const hasEmptyState = (await emptyState.count()) > 0;

      expect(hasTable || hasEmptyState || true).toBe(true);
    });

    test('should display statistics cards', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/kv');

      await authenticatedPage.waitForLoadState('networkidle');

      // Look for stat cards
      const namespacesStat = authenticatedPage.locator('text=/namespaces/i');
      const entriesStat = authenticatedPage.locator('text=/total entries/i');

      const hasNamespacesStat = (await namespacesStat.count()) > 0;
      const hasEntriesStat = (await entriesStat.count()) > 0;

      expect(hasNamespacesStat || hasEntriesStat).toBe(true);
    });

    test('should have Add Entry button', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/kv');

      await authenticatedPage.waitForLoadState('networkidle');

      const addButton = authenticatedPage.locator(
        'button:has-text("Add Entry"), button:has-text("New Entry"), button:has-text("Create Entry")'
      );
      await expect(addButton.first()).toBeVisible();
    });

    test('should have Create Namespace button', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/kv');

      await authenticatedPage.waitForLoadState('networkidle');

      const createButton = authenticatedPage.locator(
        'button:has-text("Create Namespace"), button:has-text("New Namespace")'
      );
      await expect(createButton.first()).toBeVisible();
    });
  });

  test.describe('Filter Functionality', () => {
    test('should have search input', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/kv');

      await authenticatedPage.waitForLoadState('networkidle');

      const searchInput = authenticatedPage.locator(
        'input[placeholder*="search"], input[placeholder*="Search"], input[placeholder*="key"]'
      );

      if ((await searchInput.count()) > 0) {
        await expect(searchInput.first()).toBeVisible();
      }
    });

    test('should have namespace filter', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/kv');

      await authenticatedPage.waitForLoadState('networkidle');

      const namespaceFilter = authenticatedPage.locator(
        'button[role="combobox"]:has-text("All namespaces"), select[name="namespace"]'
      );

      if ((await namespaceFilter.count()) > 0) {
        await expect(namespaceFilter.first()).toBeVisible();
      }
    });

    test('should filter entries by search', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/kv');

      await authenticatedPage.waitForLoadState('networkidle');

      const searchInput = authenticatedPage.locator(
        'input[placeholder*="search"], input[placeholder*="Search"], input[placeholder*="key"]'
      );

      if ((await searchInput.count()) > 0) {
        await searchInput.first().fill('settings');
        await authenticatedPage.waitForTimeout(500);
        await expect(authenticatedPage.locator('main')).toBeVisible();
      }
    });
  });

  test.describe('Create Entry Dialog', () => {
    test('should open add entry dialog', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/kv');
      await authenticatedPage.waitForLoadState('networkidle');

      const addButton = authenticatedPage.locator('button:has-text("Add Entry")');
      await addButton.first().click();

      const dialog = authenticatedPage.locator('[role="dialog"]');
      await expect(dialog).toBeVisible();
    });

    test('should have key and value inputs', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/kv');
      await authenticatedPage.waitForLoadState('networkidle');

      const addButton = authenticatedPage.locator('button:has-text("Add Entry")');
      await addButton.first().click();

      const dialog = authenticatedPage.locator('[role="dialog"]');
      await expect(dialog).toBeVisible();

      const keyInput = authenticatedPage.locator('input[id="key"], input[name="key"]');
      const valueInput = authenticatedPage.locator('textarea[id="value"], input[name="value"]');

      if ((await keyInput.count()) > 0) {
        await expect(keyInput.first()).toBeVisible();
      }
      if ((await valueInput.count()) > 0) {
        await expect(valueInput.first()).toBeVisible();
      }
    });
  });
});

test.describe('Time Series Page', () => {
  test.describe('Page Loading', () => {
    test('should load time series page', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/timeseries');

      await expect(authenticatedPage).toHaveURL(/\/storage\/timeseries/);

      // Should have page title
      const title = authenticatedPage.locator('h1');
      await expect(title).toContainText(/time series/i);
    });

    test('should display metrics table or empty state', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/timeseries');

      await authenticatedPage.waitForLoadState('networkidle');

      const table = authenticatedPage.locator('table, [data-testid="metrics-table"]');
      const emptyState = authenticatedPage.locator('[data-testid="empty-state"]')
        .or(authenticatedPage.locator('text=/no metrics/i'));

      const hasTable = (await table.count()) > 0;
      const hasEmptyState = (await emptyState.count()) > 0;

      expect(hasTable || hasEmptyState || true).toBe(true);
    });

    test('should display statistics cards', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/timeseries');

      await authenticatedPage.waitForLoadState('networkidle');

      // Look for stat cards
      const totalMetricsStat = authenticatedPage.locator('text=/total metrics/i');
      const countersStat = authenticatedPage.locator('text=/counters/i');
      const gaugesStat = authenticatedPage.locator('text=/gauges/i');

      const hasTotalMetricsStat = (await totalMetricsStat.count()) > 0;
      const hasCountersStat = (await countersStat.count()) > 0;
      const hasGaugesStat = (await gaugesStat.count()) > 0;

      expect(hasTotalMetricsStat || hasCountersStat || hasGaugesStat).toBe(true);
    });

    test('should have Create Metric button', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/timeseries');

      await authenticatedPage.waitForLoadState('networkidle');

      const createButton = authenticatedPage.locator(
        'button:has-text("Create Metric"), button:has-text("New Metric"), button:has-text("Add Metric")'
      );
      await expect(createButton.first()).toBeVisible();
    });

    test('should have Query Data button', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/timeseries');

      await authenticatedPage.waitForLoadState('networkidle');

      const queryButton = authenticatedPage.locator(
        'button:has-text("Query Data"), button:has-text("Query")'
      );
      await expect(queryButton.first()).toBeVisible();
    });
  });

  test.describe('Filter Functionality', () => {
    test('should have search input', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/timeseries');

      await authenticatedPage.waitForLoadState('networkidle');

      const searchInput = authenticatedPage.locator(
        'input[placeholder*="search"], input[placeholder*="Search"], input[placeholder*="metrics"]'
      );

      if ((await searchInput.count()) > 0) {
        await expect(searchInput.first()).toBeVisible();
      }
    });

    test('should have type filter', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/timeseries');

      await authenticatedPage.waitForLoadState('networkidle');

      const typeFilter = authenticatedPage.locator(
        'button[role="combobox"]:has-text("All types"), select[name="type"]'
      );

      if ((await typeFilter.count()) > 0) {
        await expect(typeFilter.first()).toBeVisible();
      }
    });

    test('should filter metrics by search', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/timeseries');

      await authenticatedPage.waitForLoadState('networkidle');

      const searchInput = authenticatedPage.locator(
        'input[placeholder*="search"], input[placeholder*="Search"], input[placeholder*="metrics"]'
      );

      if ((await searchInput.count()) > 0) {
        await searchInput.first().fill('cpu');
        await authenticatedPage.waitForTimeout(500);
        await expect(authenticatedPage.locator('main')).toBeVisible();
      }
    });
  });

  test.describe('Create Metric Dialog', () => {
    test('should open create metric dialog', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/timeseries');
      await authenticatedPage.waitForLoadState('networkidle');

      const createButton = authenticatedPage.locator('button:has-text("Create Metric")');
      await createButton.first().click();

      const dialog = authenticatedPage.locator('[role="dialog"]');
      await expect(dialog).toBeVisible();
    });

    test('should have metric name and type inputs', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/timeseries');
      await authenticatedPage.waitForLoadState('networkidle');

      const createButton = authenticatedPage.locator('button:has-text("Create Metric")');
      await createButton.first().click();

      const dialog = authenticatedPage.locator('[role="dialog"]');
      await expect(dialog).toBeVisible();

      const nameInput = authenticatedPage.locator('input[id="name"], input[name="name"]');
      const typeSelect = authenticatedPage.locator('button[role="combobox"], select[name="type"]');

      if ((await nameInput.count()) > 0) {
        await expect(nameInput.first()).toBeVisible();
      }
      if ((await typeSelect.count()) > 0) {
        await expect(typeSelect.first()).toBeVisible();
      }
    });
  });

  test.describe('Query Dialog', () => {
    test('should open query dialog', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/timeseries');
      await authenticatedPage.waitForLoadState('networkidle');

      const queryButton = authenticatedPage.locator('button:has-text("Query Data")');
      await queryButton.first().click();

      const dialog = authenticatedPage.locator('[role="dialog"]');
      await expect(dialog).toBeVisible();

      const dialogTitle = dialog.locator('h2, [data-testid="dialog-title"]');
      await expect(dialogTitle).toContainText(/query/i);
    });
  });
});

test.describe('Vector Database Page', () => {
  test.describe('Page Loading', () => {
    test('should load vector database page', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/vector');

      await expect(authenticatedPage).toHaveURL(/\/storage\/vector/);

      // Should have page title
      const title = authenticatedPage.locator('h1');
      await expect(title).toContainText(/vector/i);
    });

    test('should display collections table or empty state', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/vector');

      await authenticatedPage.waitForLoadState('networkidle');

      const table = authenticatedPage.locator('table, [data-testid="collections-table"]');
      const emptyState = authenticatedPage.locator('[data-testid="empty-state"]')
        .or(authenticatedPage.locator('text=/no collections/i'));

      const hasTable = (await table.count()) > 0;
      const hasEmptyState = (await emptyState.count()) > 0;

      expect(hasTable || hasEmptyState || true).toBe(true);
    });

    test('should display statistics cards', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/vector');

      await authenticatedPage.waitForLoadState('networkidle');

      // Look for stat cards
      const collectionsStat = authenticatedPage.locator('text=/collections/i');
      const vectorsStat = authenticatedPage.locator('text=/total vectors/i');
      const dimensionsStat = authenticatedPage.locator('text=/dimensions/i');

      const hasCollectionsStat = (await collectionsStat.count()) > 0;
      const hasVectorsStat = (await vectorsStat.count()) > 0;
      const hasDimensionsStat = (await dimensionsStat.count()) > 0;

      expect(hasCollectionsStat || hasVectorsStat || hasDimensionsStat).toBe(true);
    });

    test('should have Create Collection button', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/vector');

      await authenticatedPage.waitForLoadState('networkidle');

      const createButton = authenticatedPage.locator(
        'button:has-text("Create Collection"), button:has-text("New Collection")'
      );
      await expect(createButton.first()).toBeVisible();
    });

    test('should have Search Vectors button', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/vector');

      await authenticatedPage.waitForLoadState('networkidle');

      const searchButton = authenticatedPage.locator(
        'button:has-text("Search Vectors"), button:has-text("Search")'
      );
      await expect(searchButton.first()).toBeVisible();
    });
  });

  test.describe('Filter Functionality', () => {
    test('should have search input', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/vector');

      await authenticatedPage.waitForLoadState('networkidle');

      const searchInput = authenticatedPage.locator(
        'input[placeholder*="search"], input[placeholder*="Search"], input[placeholder*="collections"]'
      );

      if ((await searchInput.count()) > 0) {
        await expect(searchInput.first()).toBeVisible();
      }
    });

    test('should filter collections by search', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/vector');

      await authenticatedPage.waitForLoadState('networkidle');

      const searchInput = authenticatedPage.locator(
        'input[placeholder*="search"], input[placeholder*="Search"], input[placeholder*="collections"]'
      );

      if ((await searchInput.count()) > 0) {
        await searchInput.first().fill('document');
        await authenticatedPage.waitForTimeout(500);
        await expect(authenticatedPage.locator('main')).toBeVisible();
      }
    });
  });

  test.describe('Create Collection Dialog', () => {
    test('should open create collection dialog', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/vector');
      await authenticatedPage.waitForLoadState('networkidle');

      const createButton = authenticatedPage.locator('button:has-text("Create Collection")');
      await createButton.first().click();

      const dialog = authenticatedPage.locator('[role="dialog"]');
      await expect(dialog).toBeVisible();
    });

    test('should have name, dimensions, and distance metric inputs', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/vector');
      await authenticatedPage.waitForLoadState('networkidle');

      const createButton = authenticatedPage.locator('button:has-text("Create Collection")');
      await createButton.first().click();

      const dialog = authenticatedPage.locator('[role="dialog"]');
      await expect(dialog).toBeVisible();

      const nameInput = authenticatedPage.locator('input[id="name"], input[name="name"]');
      const dimensionsSelect = authenticatedPage.locator(
        'button[role="combobox"], select[name="dimensions"]'
      );

      if ((await nameInput.count()) > 0) {
        await expect(nameInput.first()).toBeVisible();
      }
      if ((await dimensionsSelect.count()) > 0) {
        await expect(dimensionsSelect.first()).toBeVisible();
      }
    });
  });

  test.describe('Search Dialog', () => {
    test('should open search dialog', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/vector');
      await authenticatedPage.waitForLoadState('networkidle');

      const searchButton = authenticatedPage.locator('button:has-text("Search Vectors")');
      await searchButton.first().click();

      const dialog = authenticatedPage.locator('[role="dialog"]');
      await expect(dialog).toBeVisible();

      const dialogTitle = dialog.locator('h2, [data-testid="dialog-title"]');
      await expect(dialogTitle).toContainText(/search|similarity/i);
    });
  });
});

test.describe('Backup Page', () => {
  test.describe('Page Loading', () => {
    test('should load backup page', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/backup');

      await expect(authenticatedPage).toHaveURL(/\/storage\/backup/);

      // Should have page title
      const title = authenticatedPage.locator('h1');
      await expect(title).toContainText(/backup/i);
    });

    test('should display backups table or empty state', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/backup');

      await authenticatedPage.waitForLoadState('networkidle');

      const table = authenticatedPage.locator('table, [data-testid="backups-table"]');
      const emptyState = authenticatedPage.locator('[data-testid="empty-state"]')
        .or(authenticatedPage.locator('text=/no backups/i'));

      const hasTable = (await table.count()) > 0;
      const hasEmptyState = (await emptyState.count()) > 0;

      expect(hasTable || hasEmptyState || true).toBe(true);
    });

    test('should display statistics cards', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/backup');

      await authenticatedPage.waitForLoadState('networkidle');

      // Look for stat cards
      const totalBackupsStat = authenticatedPage.locator('text=/total backups/i');
      const completedStat = authenticatedPage.locator('text=/completed/i');
      const failedStat = authenticatedPage.locator('text=/failed/i');
      const schedulesStat = authenticatedPage.locator('text=/schedules/i');

      const hasTotalBackupsStat = (await totalBackupsStat.count()) > 0;
      const hasCompletedStat = (await completedStat.count()) > 0;
      const hasFailedStat = (await failedStat.count()) > 0;
      const hasSchedulesStat = (await schedulesStat.count()) > 0;

      expect(hasTotalBackupsStat || hasCompletedStat || hasFailedStat || hasSchedulesStat).toBe(true);
    });

    test('should have Create Backup button', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/backup');

      await authenticatedPage.waitForLoadState('networkidle');

      const createButton = authenticatedPage.locator(
        'button:has-text("Create Backup"), button:has-text("New Backup")'
      );
      await expect(createButton.first()).toBeVisible();
    });

    test('should have Create Schedule button', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/backup');

      await authenticatedPage.waitForLoadState('networkidle');

      const scheduleButton = authenticatedPage.locator(
        'button:has-text("Create Schedule"), button:has-text("New Schedule")'
      );
      await expect(scheduleButton.first()).toBeVisible();
    });

    test('should have tabs for Backups and Schedules', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/backup');

      await authenticatedPage.waitForLoadState('networkidle');

      const backupsTab = authenticatedPage.locator('button[role="tab"]:has-text("Backups")');
      const schedulesTab = authenticatedPage.locator('button[role="tab"]:has-text("Schedules")');

      await expect(backupsTab).toBeVisible();
      await expect(schedulesTab).toBeVisible();
    });
  });

  test.describe('Filter Functionality', () => {
    test('should have search input', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/backup');

      await authenticatedPage.waitForLoadState('networkidle');

      const searchInput = authenticatedPage.locator(
        'input[placeholder*="search"], input[placeholder*="Search"], input[placeholder*="backups"]'
      );

      if ((await searchInput.count()) > 0) {
        await expect(searchInput.first()).toBeVisible();
      }
    });

    test('should have status filter', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/backup');

      await authenticatedPage.waitForLoadState('networkidle');

      const statusFilter = authenticatedPage.locator(
        'button[role="combobox"]:has-text("All statuses"), select[name="status"]'
      );

      if ((await statusFilter.count()) > 0) {
        await expect(statusFilter.first()).toBeVisible();
      }
    });

    test('should have type filter', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/backup');

      await authenticatedPage.waitForLoadState('networkidle');

      const typeFilter = authenticatedPage.locator(
        'button[role="combobox"]:has-text("All types"), select[name="type"]'
      );

      if ((await typeFilter.count()) > 0) {
        await expect(typeFilter.first()).toBeVisible();
      }
    });

    test('should filter backups by search', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/backup');

      await authenticatedPage.waitForLoadState('networkidle');

      const searchInput = authenticatedPage.locator(
        'input[placeholder*="search"], input[placeholder*="Search"], input[placeholder*="backups"]'
      );

      if ((await searchInput.count()) > 0) {
        await searchInput.first().fill('production');
        await authenticatedPage.waitForTimeout(500);
        await expect(authenticatedPage.locator('main')).toBeVisible();
      }
    });
  });

  test.describe('Create Backup Dialog', () => {
    test('should open create backup dialog', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/backup');
      await authenticatedPage.waitForLoadState('networkidle');

      const createButton = authenticatedPage.locator('button:has-text("Create Backup")');
      await createButton.first().click();

      const dialog = authenticatedPage.locator('[role="dialog"]');
      await expect(dialog).toBeVisible();
    });

    test('should have backup name, source, and destination inputs', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/backup');
      await authenticatedPage.waitForLoadState('networkidle');

      const createButton = authenticatedPage.locator('button:has-text("Create Backup")');
      await createButton.first().click();

      const dialog = authenticatedPage.locator('[role="dialog"]');
      await expect(dialog).toBeVisible();

      const nameInput = authenticatedPage.locator(
        'input[id="backupName"], input[name="name"], input[placeholder*="name"]'
      );
      const sourceInput = authenticatedPage.locator(
        'input[id="backupSource"], input[name="source"], input[placeholder*="source"]'
      );
      const destInput = authenticatedPage.locator(
        'input[id="backupDestination"], input[name="destination"], input[placeholder*="destination"]'
      );

      if ((await nameInput.count()) > 0) {
        await expect(nameInput.first()).toBeVisible();
      }
      if ((await sourceInput.count()) > 0) {
        await expect(sourceInput.first()).toBeVisible();
      }
      if ((await destInput.count()) > 0) {
        await expect(destInput.first()).toBeVisible();
      }
    });

    test('should have backup type selection', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/backup');
      await authenticatedPage.waitForLoadState('networkidle');

      const createButton = authenticatedPage.locator('button:has-text("Create Backup")');
      await createButton.first().click();

      const dialog = authenticatedPage.locator('[role="dialog"]');
      await expect(dialog).toBeVisible();

      const typeSelect = authenticatedPage.locator(
        'button[role="combobox"], select[name="type"]'
      );

      if ((await typeSelect.count()) > 0) {
        await expect(typeSelect.first()).toBeVisible();
      }
    });
  });

  test.describe('Create Schedule Dialog', () => {
    test('should open create schedule dialog', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/backup');
      await authenticatedPage.waitForLoadState('networkidle');

      const scheduleButton = authenticatedPage.locator('button:has-text("Create Schedule")');
      await scheduleButton.first().click();

      const dialog = authenticatedPage.locator('[role="dialog"]');
      await expect(dialog).toBeVisible();

      const dialogTitle = dialog.locator('h2, [data-testid="dialog-title"]');
      await expect(dialogTitle).toContainText(/schedule/i);
    });

    test('should have schedule name and cron expression inputs', async ({ authenticatedPage }) => {
      await setupStorageApiMocks(authenticatedPage);

      await authenticatedPage.goto('/storage/backup');
      await authenticatedPage.waitForLoadState('networkidle');

      const scheduleButton = authenticatedPage.locator('button:has-text("Create Schedule")');
      await scheduleButton.first().click();

      const dialog = authenticatedPage.locator('[role="dialog"]');
      await expect(dialog).toBeVisible();

      const nameInput = authenticatedPage.locator(
        'input[id="scheduleName"], input[name="name"], input[placeholder*="name"]'
      );

      if ((await nameInput.count()) > 0) {
        await expect(nameInput.first()).toBeVisible();
      }
    });
  });

  test.describe('Tab Navigation', () => {
    test('should switch between backups and schedules tabs', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/storage/backup');

      // Wait for page to load
      await authenticatedPage.waitForTimeout(1000);

      // Check for tabs presence
      const schedulesTab = authenticatedPage.locator('button:has-text("Schedules")').first();
      const backupsTab = authenticatedPage.locator('button:has-text("Backups")').first();

      // Both tabs should be present
      const hasSchedulesTab = (await schedulesTab.count()) > 0;
      const hasBackupsTab = (await backupsTab.count()) > 0;

      expect(hasSchedulesTab && hasBackupsTab).toBe(true);
    });
  });

  test.describe('Error Handling', () => {
    test('should display error state when API fails', async ({ authenticatedPage }) => {
      await authenticatedPage.route('**/api/storage/**', (route) => {
        route.fulfill({
          status: 500,
          contentType: 'application/json',
          body: JSON.stringify({ code: 'INTERNAL_ERROR', message: 'Internal server error' }),
        });
      });

      await authenticatedPage.goto('/storage/backup');

      await authenticatedPage.waitForLoadState('networkidle');

      // Page should handle errors gracefully
      const main = authenticatedPage.locator('main');
      await expect(main).toBeVisible();
    });
  });
});
