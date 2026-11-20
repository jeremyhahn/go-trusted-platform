/**
 * Platform pages against the real-server harness (#2036, epic #1665).
 *
 * Ported from web/e2e/platform.spec.ts. Health and system info are read from
 * the server through the SDK first, and the pages are held to that answer.
 * Mocked cases with no server behaviour behind them (unhealthy services made
 * up on cue, injected 503s on health and metrics, artificial latency, a member
 * session, the skipped logs and configuration placeholders) are listed as
 * gaps in the PR body.
 */
import { test, expect } from './fixtures';

interface Result<T> {
  success: boolean;
  data?: T;
  error?: unknown;
}

interface ServiceHealth {
  name: string;
  healthy: boolean;
  status?: string;
}

/** The part of the SDK's PlatformService these specs drive. */
interface PlatformSdk {
  platform: {
    getHealth(): Promise<Result<{ health: { healthy: boolean; services: ServiceHealth[] } }>>;
  };
}

/** The UI title-cases service names ("api-server" shows as "Api Server"). */
function serviceText(name: string): RegExp {
  const words = name.split(/[-_\s]+/).map((w) => w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  return new RegExp(words.join('.?'), 'i');
}

async function readHealth(sdk: unknown) {
  const res = await (sdk as PlatformSdk).platform.getHealth();
  expect(res.success, JSON.stringify(res.error)).toBe(true);
  return res.data!.health;
}

function countHealthReads(page: import('@playwright/test').Page): () => number {
  let n = 0;
  page.on('request', (req) => {
    if (req.method() === 'GET' && /\/api\/v1\/platform\/health/.test(req.url())) n++;
  });
  return () => n;
}

test.describe('Platform Management', () => {
  test.describe('Health Page', () => {
    test('shows the overall health the server reports', async ({ adminPage, sdk }) => {
      const health = await readHealth(sdk);

      await adminPage.goto('/platform/health');

      await expect(adminPage.getByRole('heading', { name: /system health/i })).toBeVisible();
      if (health.healthy) {
        await expect(adminPage.getByText(/healthy/i).first()).toBeVisible();
      } else {
        await expect(adminPage.getByText(/degraded|down|unhealthy/i).first()).toBeVisible();
      }
    });

    test('shows a card per service the server reports', async ({ adminPage, sdk }) => {
      const health = await readHealth(sdk);
      expect(health.services.length).toBeGreaterThan(0);

      await adminPage.goto('/platform/health');

      await expect(adminPage.getByRole('heading', { name: /services/i })).toBeVisible();
      for (const service of health.services) {
        await expect(adminPage.getByText(serviceText(service.name)).first()).toBeVisible();
      }
      if (health.services.some((s) => !s.healthy && s.status !== 'degraded')) {
        await expect(adminPage.getByText(/down/i).first()).toBeVisible();
      }
    });

    test('toggles auto-refresh', async ({ adminPage }) => {
      await adminPage.goto('/platform/health');

      const toggle = adminPage.getByRole('switch', { name: /auto.?refresh/i });
      await expect(toggle).toBeVisible();
      const initial = await toggle.isChecked();
      await toggle.click();

      await expect(toggle).toHaveAttribute('aria-checked', String(!initial));
    });

    test('reads health from the server again on manual refresh', async ({ adminPage }) => {
      const reads = countHealthReads(adminPage);

      await adminPage.goto('/platform/health');
      await expect(adminPage.getByRole('heading', { name: /services/i })).toBeVisible();
      const before = reads();

      await adminPage.getByRole('button', { name: /refresh/i }).click();

      await expect.poll(reads).toBeGreaterThan(before);
    });

    test('keeps auto-refresh enabled once switched on', async ({ adminPage }) => {
      await adminPage.goto('/platform/health');
      await expect(adminPage.getByRole('heading', { name: /services/i })).toBeVisible();

      const toggle = adminPage.getByRole('switch', { name: /auto.?refresh/i });
      if (!(await toggle.isChecked())) {
        await toggle.click();
      }

      await expect(toggle).toBeChecked();
    });
  });

  test.describe('Metrics Page', () => {
    test('shows the metrics dashboard with resource and system cards', async ({ adminPage }) => {
      await adminPage.goto('/platform/metrics');

      await expect(adminPage.getByRole('heading', { name: /platform metrics/i })).toBeVisible();
      await expect(adminPage.getByText(/cpu usage/i)).toBeVisible();
      await expect(adminPage.getByText(/memory usage/i)).toBeVisible();
      await expect(adminPage.getByText(/disk usage/i)).toBeVisible();
      await expect(adminPage.getByText(/uptime/i)).toBeVisible();
      await expect(adminPage.getByText(/hostname/i)).toBeVisible();
      await expect(adminPage.getByText(/connections/i).first()).toBeVisible();
    });

    test('shows the time range selector', async ({ adminPage }) => {
      await adminPage.goto('/platform/metrics');

      await expect(
        adminPage.locator('button, [role="combobox"]').filter({ hasText: /hour|last/i }).first()
      ).toBeVisible();
    });
  });

  test.describe('Events Page', () => {
    test('shows the event stream and statistics derived from server health', async ({ adminPage, sdk }) => {
      await readHealth(sdk);

      await adminPage.goto('/platform/events');

      await expect(adminPage.getByRole('heading', { name: /platform events/i })).toBeVisible();
      await expect(adminPage.getByText(/event stream/i)).toBeVisible();
      await expect(adminPage.getByText(/total events/i)).toBeVisible();
    });

    test('has a severity filter', async ({ adminPage }) => {
      await adminPage.goto('/platform/events');

      await expect(
        adminPage.locator('[role="combobox"]').filter({ hasText: /all|severity/i }).first()
      ).toBeVisible();
    });

    test('toggles event streaming', async ({ adminPage }) => {
      await adminPage.goto('/platform/events');
      await expect(adminPage.locator('h1').filter({ hasText: /events/i })).toBeVisible();

      const stream = adminPage.locator('button').filter({ hasText: /stream/i }).first();
      await expect(stream).toBeVisible();
      const before = (await stream.textContent()) ?? '';
      await stream.click();

      await expect(adminPage.locator('button').filter({ hasText: /stream/i }).first()).not.toHaveText(before);
    });
  });

  test.describe('Access Control', () => {
    test('lets the admin open the health page', async ({ adminPage }) => {
      await adminPage.goto('/platform/health');

      await expect(adminPage.getByRole('heading', { name: /system health/i })).toBeVisible();
    });

    test('redirects an unauthenticated browser to login', async ({ browser }) => {
      const context = await browser.newContext();
      const page = await context.newPage();
      try {
        await page.goto('/platform/health');
        await expect(page).toHaveURL(/\/auth\/webauthn/);
      } finally {
        await context.close();
      }
    });
  });

  test.describe('Navigation', () => {
    test('navigates between platform pages via the sidebar', async ({ adminPage }) => {
      await adminPage.goto('/platform/health');
      await expect(adminPage.getByRole('heading', { name: /system health/i })).toBeVisible();

      for (const [name, url] of [
        [/metrics/i, /\/platform\/metrics/],
        [/services/i, /\/platform\/services/],
        [/events/i, /\/platform\/events/],
      ] as const) {
        await adminPage.getByRole('link', { name }).first().click();
        await expect(adminPage).toHaveURL(url);
      }
    });
  });
});
