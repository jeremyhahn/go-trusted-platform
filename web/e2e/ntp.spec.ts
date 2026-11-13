import { test, expect, Page, Route, Request } from '@playwright/test';
import { createTenantOwnerSession } from './fixtures/auth-setup';
import { mockTenantApi, errorEnvelope, ApiError } from './fixtures/api-mock';

/**
 * NTP E2E Tests (#1682)
 *
 * GetStatus, ListSources and Step on /networking/ntp, against mocked
 * `GET /api/v1/ntp/status`, `GET /api/v1/ntp/sources` and
 * `POST /api/v1/ntp/step` (docs/ntp/api.md §4: protojson, lowerCamelCase).
 */

function mockStatus(overrides: Record<string, unknown> = {}) {
  return {
    synced: true,
    stratum: 3,
    leapStatus: 'normal',
    offsetSeconds: 0.000125,
    rootDispersion: 0.001,
    rootDelay: 0.002,
    lastSyncUnix: '1762905600',
    mode: 'client',
    referenceId: 'C0A80001',
    referenceName: 'time-ref-a',
    sourcesReachable: 2,
    sourcesTotal: 3,
    anomaly: false,
    anomalyReason: '',
    ...overrides,
  };
}

function mockSource(address: string, overrides: Record<string, unknown> = {}) {
  return {
    address,
    mode: 'server',
    state: 'selected',
    stratum: 2,
    pollSeconds: 64,
    reach: 255,
    lastRxSeconds: '12',
    offsetSeconds: 0.0002,
    reachable: true,
    ...overrides,
  };
}

interface NTPMockConfig {
  status?: ReturnType<typeof mockStatus>;
  sources?: ReturnType<typeof mockSource>[];
  stepError?: ApiError;
  sourcesError?: ApiError;
  /** Per-call status responses: null answers 200, an ApiError answers that error; the last entry repeats. */
  statusSequence?: (ApiError | null)[];
  /** Called per status request (statusSequence is then ignored): null answers 200, an ApiError answers that error. May be async to hold the response. */
  statusResponder?: () => ApiError | null | Promise<ApiError | null>;
}

async function mockNTPApi(page: Page, config: NTPMockConfig = {}) {
  const calls = { status: 0, sources: 0, step: 0 };
  const status = config.status ?? mockStatus();
  const sources = config.sources ?? [mockSource('ntp-src-a'), mockSource('ntp-src-b', { state: 'unreachable', reach: 0, reachable: false })];

  await page.route('**/api/v1/ntp/status', async (route: Route) => {
    calls.status++;
    const seq = config.statusSequence;
    const statusError = config.statusResponder
      ? await config.statusResponder()
      : seq && seq.length > 0
        ? seq[Math.min(calls.status, seq.length) - 1]
        : null;
    if (statusError) {
      await route.fulfill({
        status: statusError.status,
        contentType: 'application/json',
        body: errorEnvelope(statusError),
      });
      return;
    }
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ status }) });
  });

  await page.route('**/api/v1/ntp/sources', async (route: Route) => {
    calls.sources++;
    if (config.sourcesError) {
      await route.fulfill({
        status: config.sourcesError.status,
        contentType: 'application/json',
        body: errorEnvelope(config.sourcesError),
      });
      return;
    }
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ sources }) });
  });

  await page.route('**/api/v1/ntp/step', async (route: Route, request: Request) => {
    if (request.method() !== 'POST') {
      await route.fulfill({ status: 405, contentType: 'application/json', body: '{}' });
      return;
    }
    calls.step++;
    if (config.stepError) {
      await route.fulfill({
        status: config.stepError.status,
        contentType: 'application/json',
        body: errorEnvelope(config.stepError),
      });
      return;
    }
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ status: mockStatus({ stratum: 2, referenceName: 'time-ref-stepped' }) }),
    });
  });

  return calls;
}

test.describe('NTP', () => {
  test.beforeEach(async ({ page }) => {
    await createTenantOwnerSession(page.context());
    await mockTenantApi(page);
  });

  test('shows the NTP status (GetStatus)', async ({ page }) => {
    const calls = await mockNTPApi(page);

    await page.goto('/networking/ntp');

    await expect(page.getByRole('heading', { name: /^ntp$/i })).toBeVisible();
    const card = page.getByTestId('ntp-status-card');
    await expect(card.getByText('Synced', { exact: true })).toBeVisible();
    await expect(card.getByText('time-ref-a')).toBeVisible();
    await expect(card.getByText('2 / 3')).toBeVisible();
    expect(calls.status).toBeGreaterThan(0);
  });

  test('lists the NTP sources (ListSources)', async ({ page }) => {
    const calls = await mockNTPApi(page);

    await page.goto('/networking/ntp');

    const table = page.getByTestId('ntp-sources-table');
    await expect(table.getByText('ntp-src-a')).toBeVisible();
    await expect(table.getByText('ntp-src-b')).toBeVisible();
    await expect(table.getByText('unreachable')).toBeVisible();
    expect(calls.sources).toBeGreaterThan(0);
  });

  test('shows an error, not an empty configuration, when ListSources fails (503)', async ({ page }) => {
    const calls = await mockNTPApi(page, {
      sourcesError: { status: 503, error: 'ntp: chronyd unavailable', errorCode: 'UNAVAILABLE' } as ApiError,
    });

    await page.goto('/networking/ntp');

    const table = page.getByTestId('ntp-sources-table');
    await expect(table.getByTestId('ntp-sources-error')).toBeVisible();
    await expect(table.getByText('No sources configured')).toHaveCount(0);
    expect(calls.sources).toBeGreaterThan(0);
  });

  test('keeps the status stale from a failed refresh (503) until a successful read', async ({ page }) => {
    const unavailable = { status: 503, error: 'ntp: chronyd unavailable', errorCode: 'UNAVAILABLE' } as ApiError;
    let phase: 'ok' | 'fail' | 'held' = 'ok';
    let release: () => void = () => {};
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    let heldCalls = 0;
    const calls = await mockNTPApi(page, {
      statusResponder: async () => {
        if (phase === 'fail') return unavailable;
        if (phase === 'held') {
          heldCalls++;
          await held;
        }
        return null;
      },
    });

    await page.goto('/networking/ntp');

    const card = page.getByTestId('ntp-status-card');
    const stale = card.getByTestId('ntp-status-stale');
    await expect(card.getByText('Synced', { exact: true })).toBeVisible();
    await expect(stale).toHaveCount(0);

    // The refresh fails (the client retries the 503 before giving up).
    phase = 'fail';
    await page.getByRole('button', { name: 'Refresh' }).click();
    await expect(stale).toBeVisible({ timeout: 20_000 });
    await expect(card.getByText(/Status refresh failed/)).toBeVisible();

    // A retry starts and is held: the cached status stays marked stale while it is pending.
    phase = 'held';
    await page.getByRole('button', { name: 'Refresh' }).click();
    await expect.poll(() => heldCalls).toBeGreaterThan(0);
    await expect(stale).toBeVisible();
    await expect(card.getByText(/Status refresh failed/)).toBeVisible();
    await expect(card.getByText('Synced', { exact: true })).toBeVisible();

    // The retry succeeds: the stale mark clears.
    release();
    await expect(stale).toHaveCount(0);
    await expect(card.getByText(/Status refresh failed/)).toHaveCount(0);
    await expect(card.getByText('Synced', { exact: true })).toBeVisible();
    expect(calls.status).toBeGreaterThan(2);
  });

  test('steps the clock after confirmation (Step)', async ({ page }) => {
    const calls = await mockNTPApi(page);

    await page.goto('/networking/ntp');
    await expect(page.getByTestId('ntp-status-card').getByText('time-ref-a')).toBeVisible();

    await page.getByRole('button', { name: /step clock/i }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog.getByText(/step the clock\?/i)).toBeVisible();

    // Cancel sends nothing.
    await dialog.getByRole('button', { name: /cancel/i }).click();
    await expect(page.getByRole('dialog')).toBeHidden();
    expect(calls.step).toBe(0);

    await page.getByRole('button', { name: /step clock/i }).click();
    await page.getByRole('dialog').getByRole('button', { name: /confirm step/i }).click();

    await expect(page.getByRole('dialog')).toBeHidden();
    await expect(page.getByTestId('ntp-status-card').getByText('time-ref-stepped')).toBeVisible();
    expect(calls.step).toBe(1);
  });

  test('starts no overlapping refresh while a status read is pending', async ({ page }) => {
    let hold = false;
    let release: () => void = () => {};
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    const calls = await mockNTPApi(page, {
      statusResponder: async () => {
        if (hold) await held;
        return null;
      },
    });

    await page.goto('/networking/ntp');
    const card = page.getByTestId('ntp-status-card');
    await expect(card.getByText('Synced', { exact: true })).toBeVisible();
    const refresh = page.getByRole('button', { name: 'Refresh' });
    await expect(refresh).toBeEnabled();

    // The first refresh is held: a second one must not start, or the older
    // response could land after the newer one and overwrite it.
    hold = true;
    const before = calls.status;
    await refresh.click();
    await expect.poll(() => calls.status).toBe(before + 1);
    await expect(refresh).toBeDisabled();
    await refresh.click({ force: true });
    expect(calls.status).toBe(before + 1);

    release();
    await expect(refresh).toBeEnabled();
    expect(calls.status).toBe(before + 1);
  });

  test('keeps the dialog open when the step is refused (Step, 409)', async ({ page }) => {
    const calls = await mockNTPApi(page, {
      stepError: { status: 409, error: 'ntp: no reachable source', errorCode: 'ABORTED' } as ApiError,
    });

    await page.goto('/networking/ntp');
    await page.getByRole('button', { name: /step clock/i }).click();
    await page.getByRole('dialog').getByRole('button', { name: /confirm step/i }).click();

    await expect(page.getByText(/failed to step the clock/i).first()).toBeVisible();
    await expect(page.getByRole('dialog')).toBeVisible();
    expect(calls.step).toBe(1);
  });
});
