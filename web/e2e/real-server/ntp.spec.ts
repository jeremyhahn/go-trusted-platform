/**
 * NTP page against the real-server harness (#2058, ruling 972), run by
 * `make web-e2e`.
 *
 * No page.route and no api-mock: the harness's adminPage carries a
 * server-issued session, and the test reads GET /api/v1/capabilities and
 * the NTP routes from the running server. The test daemon may run with NTP
 * enabled or without it, so the spec accepts the status card or the
 * not-enabled card, and the sources table read from GET /api/v1/ntp/sources
 * or the Sources card's not-offered reason. With NTP enabled but no chronyd
 * reachable (the test daemon has none), the status and sources routes answer
 * 503 with a reason and the Sources table shows its error row. The clock is
 * never stepped: the confirm dialog is opened and cancelled.
 */

import type { Response } from '@playwright/test';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

interface Capability {
  op: string;
  kind?: string;
  enabled: boolean;
  reason?: string;
}

function isGet(path: string) {
  return (r: Response) => new URL(r.url()).pathname === path && r.request().method() === 'GET';
}

// The error reason of a refused NTP read: the body's `error` string, or its
// `error.message`, or its `message`.
async function errorText(r: Response): Promise<string> {
  const body = (await r.json()) as { error?: unknown; message?: unknown };
  const err = body.error;
  if (typeof err === 'string') return err;
  if (typeof err === 'object' && err !== null) {
    const m = (err as { message?: unknown }).message;
    if (typeof m === 'string') return m;
  }
  return typeof body.message === 'string' ? body.message : '';
}

test.describe('NTP page', () => {
  test('shows the status card or the not-enabled card, the ListSources rows or their reason, with Step Clock gated', async ({
    adminPage: page,
  }) => {
    const capsResponse = page.waitForResponse(isGet('/api/v1/capabilities'));
    const statusResponse = page
      .waitForResponse(isGet('/api/v1/ntp/status'), { timeout: 15_000 })
      .catch(() => null);
    const sourcesResponse = page
      .waitForResponse(isGet('/api/v1/ntp/sources'), { timeout: 15_000 })
      .catch(() => null);
    const requested: string[] = [];
    page.on('request', (req) => requested.push(new URL(req.url()).pathname));
    await page.goto('/networking/ntp');

    const r = await capsResponse;
    expect(r.status()).toBe(200);
    const list: Capability[] =
      unwrapPayload<{ capabilities?: Capability[] }>(await r.json()).capabilities ?? [];
    expect(list.length).toBeGreaterThan(0);

    const enabled = (op: string) => list.find((c) => c.op === op)?.enabled === true;
    // The reason the page shows for a disabled op: the server's, or the
    // capabilities hook's "not offered" one when the op is not in the list.
    const reasonOf = (op: string) => {
      const cap = list.find((c) => c.op === op);
      return cap ? cap.reason : 'not offered by this server';
    };
    const statusEnabled = enabled('GET /api/v1/ntp/status');
    const sourcesEnabled = enabled('GET /api/v1/ntp/sources');
    const stepEnabled = enabled('POST /api/v1/ntp/step');

    const statusCard = page.locator('[data-testid="ntp-status-card"]');
    const notEnabled = page.locator('[data-testid="ntp-not-enabled"]');
    if (statusEnabled) {
      const status = await statusResponse;
      expect(status, 'GET /api/v1/ntp/status was not read').not.toBeNull();
      // The route is served; a daemon whose chronyd control socket is not
      // reachable (the test daemon has no chronyd) answers 503 with a reason.
      expect([200, 503], 'GET /api/v1/ntp/status: 200, or 503 without chronyd').toContain(
        status!.status()
      );
      if (status!.status() === 503) {
        expect(await errorText(status!), 'the 503 carries its reason').not.toBe('');
      }
      await expect(statusCard).toBeVisible();
      await expect(notEnabled).toHaveCount(0);
    } else {
      await expect(notEnabled).toBeVisible();
    }

    // ListSources: the table follows GET /api/v1/ntp/sources's answer, or the
    // Sources card shows the capability's reason and the page never reads it.
    const sourcesNotEnabled = page.locator('[data-testid="ntp-sources-not-enabled"]');
    if (sourcesEnabled) {
      const sources = await sourcesResponse;
      expect(sources, 'GET /api/v1/ntp/sources was not read').not.toBeNull();
      expect([200, 503], 'GET /api/v1/ntp/sources: 200, or 503 without chronyd').toContain(
        sources!.status()
      );
      if (sources!.status() === 503) {
        const reason = await errorText(sources!);
        expect(reason, 'the 503 carries its reason').not.toBe('');
        await expect(page.locator('[data-testid="ntp-sources-error"]')).toBeVisible();
        await expect(page.locator('[data-testid="ntp-sources-error"]')).toContainText(
          'Failed to load NTP sources'
        );
      } else {
        const rows =
          unwrapPayload<{ sources?: { address: string }[] }>(await sources!.json()).sources ?? [];
        const tableRows = page.locator('[data-testid="ntp-sources-table"] tbody tr');
        if (rows.length === 0) {
          await expect(tableRows).toHaveCount(1);
          await expect(tableRows).toContainText('No sources configured');
        } else {
          await expect(tableRows).toHaveCount(rows.length);
          for (const row of rows) {
            await expect(
              page
                .locator('[data-testid="ntp-sources-table"]')
                .getByText(row.address, { exact: true })
            ).toBeVisible();
          }
        }
      }
      await expect(sourcesNotEnabled).toHaveCount(0);
    } else {
      await expect(sourcesNotEnabled).toBeVisible();
      await expect(sourcesNotEnabled).toHaveText(reasonOf('GET /api/v1/ntp/sources') ?? '');
      expect(requested.filter((p) => p === '/api/v1/ntp/sources')).toHaveLength(0);
    }

    const step = page.getByRole('button', { name: 'Step Clock' });
    await expect(step).toHaveAttribute('data-capability-op', 'POST /api/v1/ntp/step');
    await expect(step).toHaveAttribute('data-capability-enabled', String(stepEnabled));
    const stepReason = reasonOf('POST /api/v1/ntp/step');
    if (!stepEnabled && stepReason) {
      await expect(step).toHaveAttribute('title', stepReason);
    }

    if (stepEnabled) {
      await step.click();
      await expect(page.getByRole('dialog')).toBeVisible();
      await page.getByRole('button', { name: 'Cancel' }).click();
      await expect(page.getByRole('dialog')).toBeHidden();
    }
  });
});
