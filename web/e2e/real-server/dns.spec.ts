import type { Locator, Page, Response } from '@playwright/test';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

/**
 * The DNS pages against the real platformd (#2060, epic #1665). No page.route
 * mocks and no writes: each assertion compares the page with what the server
 * answered the page itself, and every DNS control's capability gate with the
 * server's capability list.
 */

/** The reason the capability gate shows for an op the server does not list. */
const NOT_OFFERED = 'not offered by this server';

interface Capability {
  op: string;
  enabled?: boolean;
  reason?: string;
}

/** Waits for the page's own GET whose path the predicate accepts. */
function apiResponse(page: Page, accept: (path: string) => boolean): Promise<Response> {
  return page.waitForResponse(
    (r) => r.request().method() === 'GET' && accept(new URL(r.url()).pathname),
  );
}

/** Asserts one control carries the gate the server's capability list implies. */
async function expectGated(control: Locator, op: string, listed: Map<string, Capability>) {
  const cap = listed.get(op);
  const enabled = cap?.enabled === true;
  await expect(control).toHaveAttribute('data-capability-op', op);
  await expect(control).toHaveAttribute('data-capability-enabled', enabled ? 'true' : 'false');
  if (!enabled) {
    // An offered control is never asserted enabled: Sign Zone and Resolve
    // can be disabled for other reasons (no keys yet, an empty name).
    await expect(control).toBeDisabled();
    await expect(control).toHaveAttribute('title', cap?.reason ?? NOT_OFFERED);
  }
}

/** Loads /networking/dns and returns the zones the server listed to the page. */
async function openZones(page: Page): Promise<Array<{ name: string }>> {
  const zonesRes = apiResponse(page, (p) => p === '/api/v1/dns/zones');
  await page.goto('/networking/dns');
  const res = await zonesRes;
  expect(res.ok(), `GET /api/v1/dns/zones answered ${res.status()}`).toBeTruthy();
  const body = unwrapPayload<{ zones?: Array<{ name: string }> }>(await res.json());
  return body.zones ?? [];
}

test.describe('DNS pages', () => {
  test('the zone list shows one row per zone the server answers', async ({ adminPage }) => {
    // One row per zone, or the table's single empty-state row when none.
    const zones = await openZones(adminPage);

    const rows = adminPage.getByTestId('dns-zone-row');
    await expect(rows).toHaveCount(zones.length);
    if (zones.length === 0) {
      await expect(adminPage.getByTestId('dns-zone-table')).toContainText('No DNS zones found');
      return;
    }
    for (const zone of zones) {
      await expect(rows.filter({ hasText: zone.name })).toHaveCount(1);
    }
  });

  test("the zone list gates Add Zone and zone Delete on the server's capabilities", async ({
    adminPage,
    sdk,
  }) => {
    const res = await sdk.capabilities.list();
    expect(res.success, JSON.stringify(res.error)).toBeTruthy();
    const listed = new Map<string, Capability>(
      (res.data?.capabilities ?? []).map((c) => [c.op, c]),
    );

    const zones = await openZones(adminPage);

    await expectGated(
      adminPage.getByRole('button', { name: 'Add Zone', exact: true }),
      'POST /api/v1/dns/zones',
      listed,
    );

    // The zone list mounts the lookup card with its Resolve and Register.
    const lookup = adminPage.getByTestId('dns-lookup-card');
    await expectGated(
      lookup.getByRole('button', { name: 'Resolve', exact: true }),
      'GET /api/v1/dns/resolve',
      listed,
    );
    await expectGated(
      lookup.getByRole('button', { name: 'Register', exact: true }),
      'POST /api/v1/dns/register',
      listed,
    );

    if (zones.length === 0) return;
    const row = adminPage.getByTestId('dns-zone-row').first();
    await row.getByRole('button').first().click();
    await expectGated(
      adminPage.getByRole('menuitem', { name: 'Delete', exact: true }),
      'DELETE /api/v1/dns/zones/{zone}',
      listed,
    );
    await adminPage.keyboard.press('Escape');
  });

  test("a zone's page shows its records and gates Add Record and Sign Zone", async ({
    adminPage,
    sdk,
  }) => {
    const zones = await openZones(adminPage);
    if (zones.length === 0) {
      // Nothing to open: the spec creates no zone.
      await expect(adminPage.getByTestId('dns-zone-row')).toHaveCount(0);
      return;
    }

    const res = await sdk.capabilities.list();
    expect(res.success, JSON.stringify(res.error)).toBeTruthy();
    const listed = new Map<string, Capability>(
      (res.data?.capabilities ?? []).map((c) => [c.op, c]),
    );

    const zone = zones[0].name;
    const recordsRes = apiResponse(
      adminPage,
      (p) => p.startsWith('/api/v1/dns/zones/') && p.endsWith('/records'),
    );
    await adminPage.goto(`/networking/dns/${zone}`);
    const records = await recordsRes;

    if (records.ok()) {
      const body = unwrapPayload<{ records?: unknown[] }>(await records.json());
      await expect(adminPage.getByTestId('dns-record-row')).toHaveCount(
        (body.records ?? []).length,
      );
    }

    await expectGated(
      adminPage.getByRole('button', { name: 'Add Record', exact: true }),
      'POST /api/v1/dns/zones/{zone}/records',
      listed,
    );
    await expectGated(
      adminPage.getByRole('button', { name: 'Sign Zone', exact: true }),
      'POST /api/v1/dns/zones/{zone}/sign',
      listed,
    );
    await expectGated(
      adminPage.getByRole('button', { name: 'Edit Zone', exact: true }),
      'PUT /api/v1/dns/zones/{zone}',
      listed,
    );
  });
});
