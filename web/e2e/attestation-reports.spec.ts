import { test, expect, Page } from '@playwright/test';
import { createTenantOwnerSession } from './fixtures/auth-setup';
import { mockTenantApi, errorEnvelope } from './fixtures/api-mock';
import { mockDeviceApi, createMockDevice, createMockDeviceDetail } from './fixtures/device-api-mock';
import type { Device, DeviceDetail } from './fixtures/device-api-mock';

/** A registry row with a TPM (the wire name is attest_pub; the row menu offers Refresh only for TPM devices). */
function tpmDevice(id: number, serial: string): Device {
  return { ...createMockDevice({ id, serial, model: serial }), attest_pub: 'mock-attest-pub-key', ek_cert: 'mock-ek-certificate' } as unknown as Device;
}

/**
 * Device attestation reports in the console (#428, #226 slice E).
 *
 * The control plane's collector serves a cached verdict WITH its age
 * (docs/attestation/api.md §5.3). These walk the four states the acceptance
 * list on #226 names and pin that each renders distinctly:
 *
 *   1. fresh pass          — verdict + age, fresh
 *   2. stale pass          — still shown, visibly stale, with its age
 *   3. cryptographic fail  — a failed verdict: which check failed, and that it
 *                            failed rather than could not run
 *   4. never collected     — a 404 from the report route, NOT a failed verdict
 *
 * plus: a TOFU baseline does not render like a signed one; "Refresh
 * attestation" enqueues (202) and the page re-reads the report and shows the
 * new age; the fleet table shows every verdict beside its age; the device
 * detail page shows last_heartbeat_addr.
 *
 * The API is mocked at the route layer like the rest of this suite; the
 * shapes are the ones the server emits (`reporting.View`, the platform error
 * envelope), asserted against the response-shape gate in the SDK
 * (`classifyDeviceReport`).
 */

interface ReportOverrides {
  device_id?: string;
  verified?: boolean;
  ak_certificate_verified?: boolean;
  signature_valid?: boolean;
  nonce_valid?: boolean;
  pcrs_valid?: boolean;
  cryptographic_failure?: boolean;
  pcr_baseline_source?: 'signed' | 'tofu';
  pcr_baseline_recorded_at?: string;
  fresh?: boolean;
  age_seconds?: number;
  message?: string;
}

/** A report exactly as `GET /api/v1/attestation/reports/{id}` emits it. */
function report(o: ReportOverrides = {}) {
  const now = new Date();
  const age = o.age_seconds ?? 120;
  const attested = new Date(now.getTime() - age * 1000).toISOString();
  return {
    device_id: o.device_id ?? '1',
    serial: 'SN-00000001',
    model: 'Device-1',
    verified: o.verified ?? true,
    ak_certificate_verified: o.ak_certificate_verified ?? true,
    signature_valid: o.signature_valid ?? true,
    nonce_valid: o.nonce_valid ?? true,
    pcrs_valid: o.pcrs_valid ?? true,
    cryptographic_failure: o.cryptographic_failure ?? false,
    pcr_baseline_source: o.pcr_baseline_source ?? 'signed',
    pcr_baseline_recorded_at: o.pcr_baseline_recorded_at ?? '2026-08-30T00:00:00Z',
    pcr_baseline_captured: false,
    status: o.verified === false ? 'registered' : 'attested',
    message: o.message,
    attested_at: attested,
    collected_at: attested,
    fresh: o.fresh ?? true,
    age_seconds: age,
    as_of: now.toISOString(),
  };
}

type Report = ReturnType<typeof report>;

/** Platform success envelope: `{code, success, payload}`; the SDK unwraps `payload`. */
function envelope(payload: unknown, code = 200): string {
  return JSON.stringify({ code, success: true, payload });
}

/**
 * Mocks the three report routes. `byDevice` is the collector's cache: a device
 * absent from it is "never collected" (404). Refresh answers 202 and, when a
 * `afterRefresh` report is given, the cache serves that report afterwards so
 * the page can be seen re-reading the new age.
 */
async function mockReportsApi(
  page: Page,
  byDevice: Record<string, Report>,
  options: { afterRefresh?: Record<string, Report>; notConfigured?: boolean } = {}
) {
  const cache: Record<string, Report> = { ...byDevice };
  const refreshes: string[] = [];

  await page.route('**/api/v1/attestation/reports/*/refresh', async (route) => {
    if (options.notConfigured) {
      await route.fulfill({ status: 503, contentType: 'application/json', body: errorEnvelope({ status: 503, error: 'attestation: the reporting service is not configured on this node' }) });
      return;
    }
    const id = route.request().url().match(/reports\/([^/]+)\/refresh/)?.[1] ?? '';
    refreshes.push(id);
    if (options.afterRefresh?.[id]) {
      cache[id] = options.afterRefresh[id];
    }
    await route.fulfill({
      status: 202,
      contentType: 'application/json',
      body: envelope({ device_id: id, enqueued: true, note: 'collection enqueued with the collector; read the report for the verdict and its age' }, 202),
    });
  });

  await page.route('**/api/v1/attestation/reports/*', async (route) => {
    if (route.request().method() !== 'GET') {
      await route.continue();
      return;
    }
    if (options.notConfigured) {
      await route.fulfill({ status: 503, contentType: 'application/json', body: errorEnvelope({ status: 503, error: 'attestation: the reporting service is not configured on this node' }) });
      return;
    }
    const id = route.request().url().match(/reports\/([^/?]+)/)?.[1] ?? '';
    const r = cache[id];
    if (!r) {
      await route.fulfill({ status: 404, contentType: 'application/json', body: errorEnvelope({ status: 404, error: `attestation: no report has been collected for device ${id}` }) });
      return;
    }
    await route.fulfill({ status: 200, contentType: 'application/json', body: envelope(r) });
  });

  await page.route('**/api/v1/attestation/reports', async (route) => {
    if (options.notConfigured) {
      await route.fulfill({ status: 503, contentType: 'application/json', body: errorEnvelope({ status: 503, error: 'attestation: the reporting service is not configured on this node' }) });
      return;
    }
    const reports = Object.values(cache);
    await route.fulfill({ status: 200, contentType: 'application/json', body: envelope({ reports, count: reports.length }) });
  });

  return { refreshes };
}

/**
 * The device detail route is a static export: the build emits one page for the
 * `__placeholder__` id and the client resolves the real id from the URL
 * (src/utils/dynamic-route.ts). The production server rewrites any
 * `/devices/{id}` onto that page; the Next dev server does not, so the test
 * loads the placeholder page and moves the URL the way the router would.
 */
async function openDetail(page: Page, deviceId: number, extra: Record<string, unknown> = {}) {
  const detail = {
    ...createMockDeviceDetail({ id: deviceId, model: `Device-${deviceId}` }),
    attest_pub: 'mock-attest-pub-key',
    ek_cert: 'mock-ek-certificate',
    ...extra,
  };
  await mockDeviceApi(page, { initialDevices: [detail as unknown as Device], deviceDetail: detail as unknown as DeviceDetail });
  await mockTenantApi(page);
  await page.goto('/devices/__placeholder__/');
  // pushState is only router-integrated once the app has hydrated.
  await page.getByText('Loading device details').waitFor();
  await page.waitForLoadState('networkidle');
  await page.evaluate((id) => window.history.pushState(null, '', `/devices/${id}/`), deviceId);
  await expect(page.getByTestId('device-report-card')).toBeVisible();
}

test.describe('Device attestation report (#428)', () => {
  test.beforeEach(async ({ page }) => {
    await createTenantOwnerSession(page.context());
  });

  test('state 1: a fresh pass shows the verdict beside its age, every check, and the baseline source', async ({ page }) => {
    await mockReportsApi(page, { '1': report({ age_seconds: 90, pcr_baseline_source: 'signed' }) });
    await openDetail(page, 1);

    await expect(page.getByTestId('report-verdict')).toHaveText('Verified');
    await expect(page.getByTestId('report-age')).toContainText('old');
    await expect(page.getByTestId('report-age')).not.toContainText('stale');
    await expect(page.getByTestId('report-state-report')).toHaveAttribute('data-fresh', 'true');
    await expect(page.getByTestId('report-baseline-source')).toContainText('Signed baseline');
    for (const check of ['ak_certificate_verified', 'signature_valid', 'nonce_valid', 'pcrs_valid']) {
      await expect(page.getByTestId(`check-${check}`)).toContainText('passed');
    }
    await page.screenshot({ path: 'test-results/attestation-report-fresh-pass.png', fullPage: true });
  });

  test('state 2: a stale pass is still shown, visibly stale, with its age', async ({ page }) => {
    await mockReportsApi(page, { '1': report({ fresh: false, age_seconds: 3 * 3600 }) });
    await openDetail(page, 1);

    await expect(page.getByTestId('report-verdict')).toHaveText('Verified');
    await expect(page.getByTestId('report-age')).toContainText('stale');
    await expect(page.getByTestId('report-age')).toContainText('3 hours');
    await expect(page.getByTestId('report-state-report')).toHaveAttribute('data-fresh', 'false');
    await page.screenshot({ path: 'test-results/attestation-report-stale-pass.png', fullPage: true });
  });

  test('state 3: a cryptographic failure names the failed check and that it failed rather than could not run', async ({ page }) => {
    await mockReportsApi(page, {
      '1': report({
        verified: false, pcrs_valid: false, cryptographic_failure: true,
        pcr_baseline_source: 'tofu', message: 'PCR 7 does not match the profile baseline',
      }),
    });
    await openDetail(page, 1);

    await expect(page.getByTestId('report-verdict')).toHaveText('Failed');
    await expect(page.getByTestId('check-pcrs_valid')).toContainText('failed');
    await expect(page.getByTestId('check-signature_valid')).toContainText('passed');
    await expect(page.getByTestId('report-failure-class')).toContainText('ran and failed');
    await expect(page.getByText('PCR 7 does not match the profile baseline')).toBeVisible();
    await expect(page.getByTestId('report-baseline-source')).toContainText('TOFU baseline');
    await page.screenshot({ path: 'test-results/attestation-report-cryptographic-fail.png', fullPage: true });
  });

  test('a check that could not run is denied but rendered as "Not verified", not "Failed"', async ({ page }) => {
    await mockReportsApi(page, {
      '1': report({
        verified: false, ak_certificate_verified: false, cryptographic_failure: false,
        message: 'no attestation certificate enrolled for device; tcg-cap-verifiedTPMRestricted cannot be checked (TCG DevID §8.2)',
      }),
    });
    await openDetail(page, 1);

    await expect(page.getByTestId('report-verdict')).toHaveText('Not verified');
    await expect(page.getByTestId('check-ak_certificate_verified')).toContainText('failed');
    await expect(page.getByTestId('report-failure-class')).toContainText('could not run');
  });

  test('state 4: never collected (404) is distinct from a failed verdict', async ({ page }) => {
    await mockReportsApi(page, {});
    await openDetail(page, 1);

    await expect(page.getByTestId('report-state-never-collected')).toBeVisible();
    await expect(page.getByTestId('report-state-never-collected')).toContainText('Never collected');
    await expect(page.getByTestId('report-verdict')).toHaveCount(0);
    await expect(page.getByText('Failed', { exact: true })).toHaveCount(0);
    await page.screenshot({ path: 'test-results/attestation-report-never-collected.png', fullPage: true });
  });

  test('reporting not configured (503) is named as such and disables the refresh control', async ({ page }) => {
    await mockReportsApi(page, {}, { notConfigured: true });
    await openDetail(page, 1);

    await expect(page.getByTestId('report-state-not-configured')).toContainText('Reporting not configured');
    await expect(page.getByRole('button', { name: /refresh attestation/i })).toBeDisabled();
  });

  test('a TOFU pass does not render like a signed pass', async ({ page }) => {
    await mockReportsApi(page, { '1': report({ pcr_baseline_source: 'tofu' }) });
    await openDetail(page, 1);

    const badge = page.getByTestId('report-baseline-source');
    await expect(badge).toContainText('TOFU baseline');
    await expect(badge).not.toContainText('Signed');
  });

  test('"Refresh attestation" enqueues (202) and the page re-reads the report and shows the new age', async ({ page }) => {
    const { refreshes } = await mockReportsApi(
      page,
      { '1': report({ fresh: false, age_seconds: 2 * 3600 }) },
      { afterRefresh: { '1': report({ fresh: true, age_seconds: 5 }) } }
    );
    await openDetail(page, 1);
    await expect(page.getByTestId('report-age')).toContainText('stale');

    await page.getByRole('button', { name: /refresh attestation/i }).click();

    await expect(page.getByText('Collection enqueued')).toBeVisible();
    expect(refreshes).toEqual(['1']);
    await expect(page.getByTestId('report-age')).not.toContainText('stale');
    await expect(page.getByTestId('report-age')).toContainText('5 seconds old');
    await page.screenshot({ path: 'test-results/attestation-report-after-refresh.png', fullPage: true });
  });

  test('the device detail page shows where the last heartbeat came from', async ({ page }) => {
    await mockReportsApi(page, {});
    await openDetail(page, 1, { last_heartbeat_at: new Date().toISOString(), last_heartbeat_addr: '198.51.100.103:49152' });

    await expect(page.getByTestId('last-heartbeat-addr')).toHaveText('198.51.100.103:49152');
  });
});

test.describe('Fleet table attestation column (#428)', () => {
  test.beforeEach(async ({ page }) => {
    await createTenantOwnerSession(page.context());
  });

  test('every row shows its verdict beside its age; never collected is neither green nor red', async ({ page }) => {
    const devices = [
      tpmDevice(1, 'Fresh-Pass'),
      tpmDevice(2, 'Stale-Pass'),
      tpmDevice(3, 'Crypto-Fail'),
      tpmDevice(4, 'Never-Collected'),
    ];
    await mockReportsApi(page, {
      '1': report({ device_id: '1', age_seconds: 60 }),
      '2': report({ device_id: '2', fresh: false, age_seconds: 7200 }),
      '3': report({ device_id: '3', verified: false, nonce_valid: false, cryptographic_failure: true }),
    });
    await mockDeviceApi(page, { initialDevices: devices });
    await mockTenantApi(page);
    await page.goto('/devices');

    await expect(page.getByRole('columnheader', { name: 'Attestation' })).toBeVisible();

    const rowFor = (name: string) => page.getByRole('row').filter({ hasText: name });
    await expect(rowFor('Fresh-Pass').getByTestId('fleet-report')).toContainText('Verified');
    await expect(rowFor('Fresh-Pass').getByTestId('fleet-report')).toContainText('old');
    await expect(rowFor('Fresh-Pass').getByTestId('fleet-report')).toHaveAttribute('data-fresh', 'true');

    await expect(rowFor('Stale-Pass').getByTestId('fleet-report')).toContainText('stale');
    await expect(rowFor('Stale-Pass').getByTestId('fleet-report')).toContainText('2 hours');

    await expect(rowFor('Crypto-Fail').getByTestId('fleet-report')).toContainText('Failed');

    await expect(rowFor('Never-Collected').getByTestId('fleet-never-collected')).toContainText('Never collected');
    await expect(rowFor('Never-Collected').getByTestId('fleet-report')).toHaveCount(0);

    await page.screenshot({ path: 'test-results/attestation-fleet-table.png', fullPage: true });
  });

  test('"Refresh attestation" from the row menu enqueues and re-reads the fleet', async ({ page }) => {
    const { refreshes } = await mockReportsApi(
      page,
      { '1': report({ device_id: '1', fresh: false, age_seconds: 7200 }) },
      { afterRefresh: { '1': report({ device_id: '1', fresh: true, age_seconds: 3 }) } }
    );
    await mockDeviceApi(page, { initialDevices: [tpmDevice(1, 'Refresh-Me')] });
    await mockTenantApi(page);
    await page.goto('/devices');

    const row = page.getByRole('row').filter({ hasText: 'Refresh-Me' });
    await expect(row.getByTestId('fleet-report')).toContainText('stale');
    await row.getByRole('button', { name: 'Open menu' }).click();
    await page.getByRole('menuitem', { name: /refresh attestation/i }).click();

    await expect(page.getByText('Collection enqueued')).toBeVisible();
    expect(refreshes).toEqual(['1']);
    await expect(row.getByTestId('fleet-report')).not.toContainText('stale');
  });

  test('a node without the reporting service says so instead of showing every device as never collected', async ({ page }) => {
    await mockReportsApi(page, {}, { notConfigured: true });
    await mockDeviceApi(page, { initialDevices: [tpmDevice(1, 'No-Reporting')] });
    await mockTenantApi(page);
    await page.goto('/devices');

    const row = page.getByRole('row').filter({ hasText: 'No-Reporting' });
    await expect(row.getByText('Reporting not configured')).toBeVisible();
    await expect(row.getByTestId('fleet-never-collected')).toHaveCount(0);
  });
});
