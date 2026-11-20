import type { Page, Response } from '@playwright/test';
import { test, expect } from './fixtures';

/**
 * Device attestation reports in the console (#428, #226 slice E), against the
 * real-server harness (#2035).
 *
 * The collector serves a cached verdict with its age, a 404 for a device it
 * never collected, and a 503 when the node runs no reporting service
 * (docs/attestation/api.md §5.3). The devices are seeded through the SDK; the
 * collector has no report for them unless it ran, so each case reads what the
 * server answered the page and asserts the page renders exactly that state.
 */

interface WireReport {
  verified?: boolean;
  cryptographic_failure?: boolean;
  fresh?: boolean;
  pcr_baseline_source?: string;
  time_synced?: boolean;
}

/** The part of the SDK client the seeding uses (the fixture's `sdk` satisfies it). */
interface DeviceSeeder {
  device: {
    createDevice(request: { device: { serial: string; model?: string } }): Promise<{
      success: boolean;
      data?: { device?: { id?: string | number } };
    }>;
  };
}

function unwrap<T>(body: unknown): T {
  const b = body as { payload?: T } | null;
  return (b && typeof b === 'object' && 'payload' in b ? b.payload : body) as T;
}

function isReportRead(id: string) {
  return (r: Response) =>
    r.request().method() === 'GET' && new URL(r.url()).pathname.endsWith(`/api/v1/attestation/reports/${id}`);
}

function isReportList(r: Response): boolean {
  return r.request().method() === 'GET' && new URL(r.url()).pathname.endsWith('/api/v1/attestation/reports');
}

/** Opens the static-export detail page and returns the report read it made. */
async function openDetail(page: Page, id: string): Promise<Response> {
  const read = page.waitForResponse(isReportRead(id));
  await page.goto('/devices/__placeholder__/');
  await page.getByText('Loading device details').waitFor();
  await page.waitForLoadState('networkidle');
  await page.evaluate((deviceId) => window.history.pushState(null, '', `/devices/${deviceId}/`), id);
  await expect(page.getByTestId('device-report-card')).toBeVisible();
  return read;
}

test.describe('Device attestation report (#428), real server', () => {
  const ids: string[] = [];

  async function seedDevice(sdk: DeviceSeeder, label: string): Promise<string> {
    const serial = `e2e-${label}-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;
    const res = await sdk.device.createDevice({ device: { serial, model: serial } });
    expect(res.success).toBe(true);
    const id = String(res.data?.device?.id ?? '');
    expect(id).not.toBe('');
    ids.push(id);
    return id;
  }

  test.afterEach(async ({ sdk }) => {
    for (const id of ids.splice(0)) await sdk.device.deleteDevice(id).catch(() => undefined);
  });

  test('the report card renders the state the collector holds for the device', async ({ adminPage, sdk }) => {
    const id = await seedDevice(sdk, 'report');
    const res = await openDetail(adminPage, id);

    if (res.status() === 404) {
      // Never collected is distinct from a failed verdict.
      await expect(adminPage.getByTestId('report-state-never-collected')).toContainText('Never collected');
      await expect(adminPage.getByTestId('report-verdict')).toHaveCount(0);
      await expect(adminPage.getByText('Failed', { exact: true })).toHaveCount(0);
    } else if (res.status() === 503) {
      await expect(adminPage.getByTestId('report-state-not-configured')).toContainText('Reporting not configured');
      await expect(adminPage.getByRole('button', { name: /refresh attestation/i })).toBeDisabled();
    } else {
      expect(res.ok()).toBe(true);
      const report = unwrap<WireReport>(await res.json());
      const verdict = report.verified ? 'Verified' : report.cryptographic_failure ? 'Failed' : 'Not verified';
      await expect(adminPage.getByTestId('report-verdict')).toHaveText(verdict);
      await expect(adminPage.getByTestId('report-state-report')).toHaveAttribute('data-fresh', String(Boolean(report.fresh)));
      await expect(adminPage.getByTestId('report-age')).toContainText('old');
      const baseline = report.pcr_baseline_source === 'tofu' ? 'TOFU baseline' : 'Signed baseline';
      await expect(adminPage.getByTestId('report-baseline-source')).toContainText(baseline);
      const clock = report.time_synced === undefined ? 'Clock unknown' : report.time_synced ? 'Clock synced' : 'Clock unsynced';
      await expect(adminPage.getByTestId('report-clock')).toHaveText(clock);
    }
  });

  test('"Refresh attestation" sends POST /reports/{id}/refresh and shows the answer', async ({ adminPage, sdk }) => {
    const id = await seedDevice(sdk, 'refresh');
    const read = await openDetail(adminPage, id);
    const button = adminPage.getByRole('button', { name: /refresh attestation/i });
    if (read.status() === 503) {
      await expect(button).toBeDisabled();
      return;
    }

    const answer = adminPage.waitForResponse(
      (r) => r.request().method() === 'POST' && new URL(r.url()).pathname.endsWith(`/api/v1/attestation/reports/${id}/refresh`)
    );
    await button.click();
    const res = await answer;
    if (res.status() === 202) {
      await expect(adminPage.getByText('Collection enqueued')).toBeVisible();
    } else {
      await expect(adminPage.getByText('Collection enqueued')).toHaveCount(0);
    }
  });
});

test.describe('Fleet table attestation column (#428), real server', () => {
  test('every seeded row shows the collector state the server listed', async ({ adminPage, sdk }) => {
    const serials = [0, 1].map((n) => `e2e-fleet-${n}-${Date.now()}-${Math.floor(Math.random() * 1e6)}`);
    const ids: string[] = [];
    for (const serial of serials) {
      const res = await sdk.device.createDevice({ device: { serial, model: serial } });
      expect(res.success).toBe(true);
      ids.push(String(res.data?.device?.id ?? ''));
    }

    try {
      const list = adminPage.waitForResponse(isReportList);
      await adminPage.goto('/devices');
      const res = await list;
      await expect(adminPage.getByRole('columnheader', { name: 'Attestation' })).toBeVisible();

      const reported = new Set<string>();
      if (res.ok()) {
        const body = unwrap<{ reports?: Array<{ device_id?: string }> }>(await res.json());
        for (const r of body.reports ?? []) reported.add(String(r.device_id));
      }

      for (const [i, serial] of serials.entries()) {
        const row = adminPage.getByRole('row').filter({ hasText: serial });
        if (res.status() === 503) {
          // A node without the reporting service says so instead of showing
          // every device as never collected.
          await expect(row.getByText('Reporting not configured')).toBeVisible();
          await expect(row.getByTestId('fleet-never-collected')).toHaveCount(0);
        } else if (!reported.has(ids[i])) {
          await expect(row.getByTestId('fleet-never-collected')).toContainText('Never collected');
          await expect(row.getByTestId('fleet-report')).toHaveCount(0);
        } else {
          await expect(row.getByTestId('fleet-report')).toContainText('old');
        }
      }
    } finally {
      for (const id of ids) await sdk.device.deleteDevice(id).catch(() => undefined);
    }
  });
});
