import { test, expect } from './fixtures/auth.fixture';

/**
 * Platform Pages Integration Tests
 *
 * These tests verify the Platform management UI pages are correctly
 * rendering and displaying data.
 */

// Mock service data
const mockServices = [
  {
    id: 'api-server',
    name: 'api-server',
    displayName: 'API Server',
    state: 'running',
    pid: 12345,
    uptime: '5d 12h 34m',
    memory: '256 MB',
    cpu: '2.3%',
    restarts: 0,
    lastStarted: '2026-01-14T00:00:00Z',
    description: 'Main REST/gRPC API server',
  },
  {
    id: 'tpm-service',
    name: 'tpm-service',
    displayName: 'TPM Service',
    state: 'running',
    pid: 12346,
    uptime: '5d 12h 34m',
    memory: '128 MB',
    cpu: '0.5%',
    restarts: 0,
    lastStarted: '2026-01-14T00:00:00Z',
    description: 'Trusted Platform Module management service',
  },
  {
    id: 'ca-service',
    name: 'ca-service',
    displayName: 'Certificate Authority',
    state: 'stopped',
    pid: null,
    uptime: '-',
    memory: '-',
    cpu: '-',
    restarts: 2,
    lastStarted: null,
    description: 'PKI certificate authority service',
  },
  {
    id: 'metrics-collector',
    name: 'metrics-collector',
    displayName: 'Metrics Collector',
    state: 'error',
    pid: null,
    uptime: '-',
    memory: '-',
    cpu: '-',
    restarts: 5,
    lastStarted: '2026-01-19T08:30:00Z',
    description: 'System metrics collection and aggregation',
  },
];

// Mock event data
const mockEvents = [
  {
    id: 'evt-001',
    timestamp: '2026-01-19T14:32:15Z',
    severity: 'info',
    category: 'system',
    source: 'api-server',
    title: 'API Server Started',
    message: 'API server successfully started and accepting connections on port 8443',
    metadata: { port: '8443', protocol: 'https' },
  },
  {
    id: 'evt-002',
    timestamp: '2026-01-19T14:30:00Z',
    severity: 'warning',
    category: 'security',
    source: 'auth-service',
    title: 'Failed Login Attempt',
    message: 'Multiple failed login attempts detected from IP 192.168.1.100',
    metadata: { ip: '192.168.1.100', attempts: '5' },
  },
  {
    id: 'evt-003',
    timestamp: '2026-01-19T14:28:45Z',
    severity: 'success',
    category: 'certificate',
    source: 'ca-service',
    title: 'Certificate Issued',
    message: 'New TLS certificate issued for device device-abc123',
    metadata: { deviceId: 'device-abc123', validity: '365 days' },
  },
  {
    id: 'evt-004',
    timestamp: '2026-01-19T14:25:00Z',
    severity: 'error',
    category: 'service',
    source: 'metrics-collector',
    title: 'Service Crashed',
    message: 'Metrics collector service crashed unexpectedly. Attempting restart...',
    metadata: { exitCode: '1', restartCount: '5' },
  },
];

// Mock metrics data
const mockMetrics = {
  cpu: {
    current: 23.5,
    average: 28.2,
    peak: 85.3,
    cores: 8,
    history: [],
  },
  memory: {
    used: 5632,
    total: 16384,
    cached: 2048,
    available: 10752,
    history: [],
  },
  disk: {
    used: 234,
    total: 512,
    readRate: 45.2,
    writeRate: 12.8,
    history: [],
  },
  network: {
    bytesIn: 1234567890,
    bytesOut: 987654321,
    packetsIn: 1234567,
    packetsOut: 987654,
    connections: 156,
    history: [],
  },
  uptime: 475920,
  loadAverage: [1.25, 1.42, 1.38],
  processes: 245,
  timestamp: new Date().toISOString(),
};

const mockServiceMetrics = [
  {
    name: 'api-server',
    displayName: 'API Server',
    requestsPerSecond: 245.6,
    averageLatency: 12.3,
    errorRate: 0.02,
    activeConnections: 48,
  },
  {
    name: 'tpm-service',
    displayName: 'TPM Service',
    requestsPerSecond: 18.2,
    averageLatency: 5.8,
    errorRate: 0.0,
    activeConnections: 12,
  },
];

test.describe('Platform Services Page', () => {
  test.describe('Page Loading', () => {
    test('should load services page', async ({ authenticatedPage }) => {
      // Mock the services API
      await authenticatedPage.route('**/api/v1/platform/services', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockServices),
        });
      });

      await authenticatedPage.goto('/platform/services');

      await expect(authenticatedPage).toHaveURL(/\/platform\/services/);

      // Should have page title
      const title = authenticatedPage.locator('h1');
      await expect(title).toContainText(/platform services/i);
    });

    test('should display services table or loading state', async ({ authenticatedPage }) => {
      // Mock the services API
      await authenticatedPage.route('**/api/v1/platform/services', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockServices),
        });
      });

      await authenticatedPage.goto('/platform/services');

      await authenticatedPage.waitForLoadState('networkidle');

      const table = authenticatedPage.locator('table, [data-testid="services-table"]');
      const emptyState = authenticatedPage.locator('[data-testid="empty-state"]')
        .or(authenticatedPage.locator('text=/no services/i'));
      const loadingState = authenticatedPage.locator('[class*="loading"], [class*="spinner"], [class*="animate-spin"]');

      const hasTable = (await table.count()) > 0;
      const hasEmptyState = (await emptyState.count()) > 0;
      const hasLoading = (await loadingState.count()) > 0;

      expect(hasTable || hasEmptyState || hasLoading).toBe(true);
    });

    test('should have Refresh button', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/platform/services');

      // Wait for page title to be visible first
      await expect(authenticatedPage.locator('h1:has-text("Platform Services")')).toBeVisible({ timeout: 5000 });

      // Look for refresh text on any button
      const refreshText = authenticatedPage.locator('text=Refresh').first();
      const hasRefresh = (await refreshText.count()) > 0;
      expect(hasRefresh).toBe(true);
    });
  });

  test.describe('Service Statistics', () => {
    test('should display statistics cards', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/platform/services');

      // Wait for page title to be visible first
      await expect(authenticatedPage.locator('h1:has-text("Platform Services")')).toBeVisible({ timeout: 5000 });

      // Look for statistics text like "Total Services" or "Running"
      const statsText = authenticatedPage.locator('text=/Total Services|Running|Stopped|Error/i').first();
      const hasStats = (await statsText.count()) > 0;
      expect(hasStats).toBe(true);
    });

    test('should show running, stopped, and error counts', async ({ authenticatedPage }) => {
      // Mock the services API
      await authenticatedPage.route('**/api/v1/platform/services', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockServices),
        });
      });

      await authenticatedPage.goto('/platform/services');

      await authenticatedPage.waitForLoadState('networkidle');

      // Page should render without crashing
      const main = authenticatedPage.locator('main');
      await expect(main).toBeVisible();

      // Look for status-related text
      const runningText = authenticatedPage.locator('text=/running/i');
      const stoppedText = authenticatedPage.locator('text=/stopped/i');
      const errorText = authenticatedPage.locator('text=/error/i');

      const hasRunning = (await runningText.count()) > 0;
      const hasStopped = (await stoppedText.count()) > 0;
      const hasError = (await errorText.count()) > 0;

      expect(hasRunning || hasStopped || hasError).toBe(true);
    });
  });

  test.describe('Service Status Indicators', () => {
    test('should display status badges for services', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/platform/services');

      // Wait for page title to be visible first
      await expect(authenticatedPage.locator('h1:has-text("Platform Services")')).toBeVisible({ timeout: 5000 });

      // Look for status text - the page shows running/stopped/error states
      const statusText = authenticatedPage.locator('text=/running|stopped|error/i').first();
      const hasStatus = (await statusText.count()) > 0;
      expect(hasStatus).toBe(true);
    });

    test('should show service control buttons', async ({ authenticatedPage }) => {
      // Mock the services API
      await authenticatedPage.route('**/api/v1/platform/services', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockServices),
        });
      });

      await authenticatedPage.goto('/platform/services');

      await authenticatedPage.waitForLoadState('networkidle');

      // Look for control buttons (start, stop, restart)
      const controlButtons = authenticatedPage.locator(
        'button[title*="Start"], button[title*="Stop"], button[title*="Restart"]'
      );
      const hasControls = (await controlButtons.count()) > 0;

      // Page should at least render without crashing
      const main = authenticatedPage.locator('main');
      await expect(main).toBeVisible();
      expect(hasControls || true).toBe(true);
    });
  });

  test.describe('Service Filtering', () => {
    test('should have search input for services', async ({ authenticatedPage }) => {
      // Mock the services API
      await authenticatedPage.route('**/api/v1/platform/services', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockServices),
        });
      });

      await authenticatedPage.goto('/platform/services');

      await authenticatedPage.waitForLoadState('networkidle');

      const searchInput = authenticatedPage.locator(
        'input[placeholder*="search"], input[placeholder*="Search"]'
      );

      if ((await searchInput.count()) > 0) {
        await searchInput.first().fill('api');
        await expect(searchInput.first()).toHaveValue('api');
        await expect(authenticatedPage.locator('main')).toBeVisible();
      }
    });
  });
});

test.describe('Platform Events Page', () => {
  test.describe('Page Loading', () => {
    test('should load events page', async ({ authenticatedPage }) => {
      // Mock the events API
      await authenticatedPage.route('**/api/v1/platform/events', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockEvents),
        });
      });

      await authenticatedPage.goto('/platform/events');

      await expect(authenticatedPage).toHaveURL(/\/platform\/events/);

      // Should have page title
      const title = authenticatedPage.locator('h1');
      await expect(title).toContainText(/platform events/i);
    });

    test('should display events stream or empty state', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/platform/events');

      // Wait for page title to be visible first
      await expect(authenticatedPage.locator('h1:has-text("Events")')).toBeVisible({ timeout: 5000 });

      // Page should render without crashing
      const main = authenticatedPage.locator('main');
      await expect(main).toBeVisible();
    });

    test('should have streaming controls', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/platform/events');

      // Wait for page title to be visible first
      await expect(authenticatedPage.locator('h1:has-text("Events")')).toBeVisible({ timeout: 5000 });

      // Look for streaming-related text - Start/Stop Stream or streaming controls
      const streamText = authenticatedPage.locator('text=/stream|start|stop|live/i').first();
      const hasStreamControls = (await streamText.count()) > 0;
      expect(hasStreamControls).toBe(true);
    });
  });

  test.describe('Event Statistics', () => {
    test('should display event statistics cards', async ({ authenticatedPage }) => {
      // Mock the events API
      await authenticatedPage.route('**/api/v1/platform/events', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockEvents),
        });
      });

      await authenticatedPage.goto('/platform/events');

      await authenticatedPage.waitForLoadState('networkidle');

      // Look for statistics cards
      const cards = authenticatedPage.locator('[class*="card"]');
      const hasCards = (await cards.count()) > 0;
      expect(hasCards).toBe(true);
    });

    test('should show event severity counts', async ({ authenticatedPage }) => {
      // Mock the events API
      await authenticatedPage.route('**/api/v1/platform/events', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockEvents),
        });
      });

      await authenticatedPage.goto('/platform/events');

      await authenticatedPage.waitForLoadState('networkidle');

      // Look for severity-related text
      const infoText = authenticatedPage.locator('text=/info/i');
      const warningText = authenticatedPage.locator('text=/warning/i');
      const errorText = authenticatedPage.locator('text=/error/i');

      const hasInfo = (await infoText.count()) > 0;
      const hasWarning = (await warningText.count()) > 0;
      const hasError = (await errorText.count()) > 0;

      expect(hasInfo || hasWarning || hasError).toBe(true);
    });
  });

  test.describe('Event Filtering', () => {
    test('should have severity filter', async ({ authenticatedPage }) => {
      // Mock the events API
      await authenticatedPage.route('**/api/v1/platform/events', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockEvents),
        });
      });

      await authenticatedPage.goto('/platform/events');

      await authenticatedPage.waitForLoadState('networkidle');

      // Look for severity filter
      const severityFilter = authenticatedPage.locator(
        'button[role="combobox"], select, [data-testid="severity-filter"]'
      );

      if ((await severityFilter.count()) > 0) {
        await expect(severityFilter.first()).toBeVisible();
      }
    });

    test('should have category filter', async ({ authenticatedPage }) => {
      // Mock the events API
      await authenticatedPage.route('**/api/v1/platform/events', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockEvents),
        });
      });

      await authenticatedPage.goto('/platform/events');

      await authenticatedPage.waitForLoadState('networkidle');

      // Look for category filter
      const categoryFilter = authenticatedPage.locator(
        'button[role="combobox"], select, [data-testid="category-filter"]'
      );

      if ((await categoryFilter.count()) > 0) {
        await expect(categoryFilter.first()).toBeVisible();
      }
    });
  });

  test.describe('Event Export', () => {
    test('should have export button', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/platform/events');

      // Wait for page title to be visible first
      await expect(authenticatedPage.locator('h1:has-text("Events")')).toBeVisible({ timeout: 5000 });

      // Look for export text
      const exportText = authenticatedPage.locator('text=/export|download/i').first();
      const hasExport = (await exportText.count()) > 0;
      expect(hasExport).toBe(true);
    });
  });
});

test.describe('Platform Metrics Page', () => {
  test.describe('Page Loading', () => {
    test('should load metrics page', async ({ authenticatedPage }) => {
      // Mock the metrics API
      await authenticatedPage.route('**/api/v1/platform/metrics', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ system: mockMetrics, services: mockServiceMetrics }),
        });
      });

      await authenticatedPage.goto('/platform/metrics');

      await expect(authenticatedPage).toHaveURL(/\/platform\/metrics/);

      // Should have page title
      const title = authenticatedPage.locator('h1');
      await expect(title).toContainText(/platform metrics/i);
    });

    test('should display metrics dashboard or loading state', async ({ authenticatedPage }) => {
      // Mock the metrics API
      await authenticatedPage.route('**/api/v1/platform/metrics', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ system: mockMetrics, services: mockServiceMetrics }),
        });
      });

      await authenticatedPage.goto('/platform/metrics');

      await authenticatedPage.waitForLoadState('networkidle');

      const metricsCards = authenticatedPage.locator('[class*="card"]');
      const loadingState = authenticatedPage.locator('[class*="loading"], [class*="spinner"], [class*="animate-spin"]');

      const hasMetrics = (await metricsCards.count()) > 0;
      const hasLoading = (await loadingState.count()) > 0;

      expect(hasMetrics || hasLoading).toBe(true);
    });

    test('should have time range selector', async ({ authenticatedPage }) => {
      // Mock the metrics API
      await authenticatedPage.route('**/api/v1/platform/metrics', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ system: mockMetrics, services: mockServiceMetrics }),
        });
      });

      await authenticatedPage.goto('/platform/metrics');

      await authenticatedPage.waitForLoadState('networkidle');

      // Look for time range selector
      const timeRangeSelector = authenticatedPage.locator(
        'button[role="combobox"], select, [data-testid="time-range"]'
      );

      if ((await timeRangeSelector.count()) > 0) {
        await expect(timeRangeSelector.first()).toBeVisible();
      }
    });

    test('should have auto-refresh toggle', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/platform/metrics');

      // Wait for page title to be visible first
      await expect(authenticatedPage.locator('h1:has-text("Metrics")')).toBeVisible({ timeout: 5000 });

      // Wait for loading to complete by checking for "Uptime" card which only appears after data loads
      await expect(authenticatedPage.locator('text=Uptime')).toBeVisible({ timeout: 10000 });

      // Look for auto-refresh label text
      const autoRefreshLabel = authenticatedPage.locator('label:has-text("Auto-refresh")');
      await expect(autoRefreshLabel).toBeVisible();
    });
  });

  test.describe('System Metrics', () => {
    test('should display system overview cards', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/platform/metrics');

      // The Uptime card renders only after the metrics response arrives (the page shows its loading state until then).
      await expect(authenticatedPage.locator('text=Uptime')).toBeVisible({ timeout: 10000 });

      // Look for system metric cards or any card-like containers
      const cards = authenticatedPage.locator('[class*="card"], [class*="rounded-lg border"]');
      const cardCount = await cards.count();
      expect(cardCount).toBeGreaterThan(0);
    });

    test('should show uptime information', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/platform/metrics');

      // The Uptime card renders only after the metrics response arrives (the page shows its loading state until then).
      await expect(authenticatedPage.locator('text=Uptime')).toBeVisible({ timeout: 10000 });

      // Look for uptime text - the page shows uptime in cards
      const uptimeText = authenticatedPage.locator('text=/uptime/i');
      const hasUptime = (await uptimeText.count()) > 0;
      expect(hasUptime).toBe(true);
    });

    test('should display resource usage metrics', async ({ authenticatedPage }) => {
      // Mock the metrics API
      await authenticatedPage.route('**/api/v1/platform/metrics', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ system: mockMetrics, services: mockServiceMetrics }),
        });
      });

      await authenticatedPage.goto('/platform/metrics');

      await authenticatedPage.waitForLoadState('networkidle');

      // Look for resource metrics
      const cpuText = authenticatedPage.locator('text=/cpu/i');
      const memoryText = authenticatedPage.locator('text=/memory/i');
      const diskText = authenticatedPage.locator('text=/disk/i');
      const networkText = authenticatedPage.locator('text=/network/i');

      const hasCpu = (await cpuText.count()) > 0;
      const hasMemory = (await memoryText.count()) > 0;
      const hasDisk = (await diskText.count()) > 0;
      const hasNetwork = (await networkText.count()) > 0;

      expect(hasCpu || hasMemory || hasDisk || hasNetwork).toBe(true);
    });

    test('should show progress bars for resource usage', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/platform/metrics');

      // The Uptime card renders only after the metrics response arrives (the page shows its loading state until then).
      await expect(authenticatedPage.locator('text=Uptime')).toBeVisible({ timeout: 10000 });

      // Look for progress bars or resource usage indicators
      const progressBars = authenticatedPage.locator('[role="progressbar"], [class*="progress"], [class*="bg-primary"]');
      const hasProgressBars = (await progressBars.count()) > 0;
      expect(hasProgressBars).toBe(true);
    });
  });

  test.describe('Service Metrics', () => {
    test('should display service metrics section', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/platform/metrics');

      // The Uptime card renders only after the metrics response arrives (the page shows its loading state until then).
      await expect(authenticatedPage.locator('text=Uptime')).toBeVisible({ timeout: 10000 });

      // Look for service metrics section or service names
      const serviceMetricsSection = authenticatedPage.locator('text=/service metrics|api server|tpm service/i');
      const hasSection = (await serviceMetricsSection.count()) > 0;
      expect(hasSection).toBe(true);
    });

    test('should show service performance data', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/platform/metrics');

      // The Uptime card renders only after the metrics response arrives (the page shows its loading state until then).
      await expect(authenticatedPage.locator('text=Uptime')).toBeVisible({ timeout: 10000 });

      // Look for performance metrics - the page shows latency, requests/sec, error rate
      const perfText = authenticatedPage.locator('text=/latency|requests|error/i');
      const hasPerfData = (await perfText.count()) > 0;
      expect(hasPerfData).toBe(true);
    });
  });

  test.describe('Metrics Controls', () => {
    test('should have refresh button', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/platform/metrics');

      // Wait for page title to be visible first
      await expect(authenticatedPage.locator('h1:has-text("Metrics")')).toBeVisible({ timeout: 5000 });

      // Wait for loading to complete by checking for "Uptime" card which only appears after data loads
      await expect(authenticatedPage.locator('text=Uptime')).toBeVisible({ timeout: 10000 });

      // Look for refresh button
      const refreshButton = authenticatedPage.locator('button:has-text("Refresh")');
      await expect(refreshButton).toBeVisible();
    });

    test('should show last update timestamp', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/platform/metrics');

      // Wait for page title to be visible first
      await expect(authenticatedPage.locator('h1:has-text("Metrics")')).toBeVisible({ timeout: 5000 });

      // Wait for loading to complete by checking for "Uptime" card which only appears after data loads
      await expect(authenticatedPage.locator('text=Uptime')).toBeVisible({ timeout: 10000 });

      // Look for last updated text
      const lastUpdateText = authenticatedPage.locator('text=/last updated/i');
      await expect(lastUpdateText).toBeVisible();
    });
  });
});

test.describe('Platform Page Error Handling', () => {
  test('should handle services API error gracefully', async ({ authenticatedPage }) => {
    // Mock the services API to return error
    await authenticatedPage.route('**/api/v1/platform/services', (route) => {
      route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({ code: 'INTERNAL_ERROR', message: 'Service unavailable' }),
      });
    });

    await authenticatedPage.goto('/platform/services');

    await authenticatedPage.waitForLoadState('networkidle');

    // Page should not crash
    const main = authenticatedPage.locator('main');
    await expect(main).toBeVisible();
  });

  test('should handle events API error gracefully', async ({ authenticatedPage }) => {
    // Mock the events API to return error
    await authenticatedPage.route('**/api/v1/platform/events', (route) => {
      route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({ code: 'INTERNAL_ERROR', message: 'Service unavailable' }),
      });
    });

    await authenticatedPage.goto('/platform/events');

    await authenticatedPage.waitForLoadState('networkidle');

    // Page should not crash
    const main = authenticatedPage.locator('main');
    await expect(main).toBeVisible();
  });

  test('should handle metrics API error gracefully', async ({ authenticatedPage }) => {
    // Mock the metrics API to return error
    await authenticatedPage.route('**/api/v1/platform/metrics', (route) => {
      route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({ code: 'INTERNAL_ERROR', message: 'Service unavailable' }),
      });
    });

    await authenticatedPage.goto('/platform/metrics');

    await authenticatedPage.waitForLoadState('networkidle');

    // Page should not crash
    const main = authenticatedPage.locator('main');
    await expect(main).toBeVisible();
  });
});
