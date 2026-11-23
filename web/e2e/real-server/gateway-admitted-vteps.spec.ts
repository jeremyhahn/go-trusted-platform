import type { Locator, Page, Response } from '@playwright/test';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

/**
 * The admitted-VTEP view of a gateway snapshot and its two gates against the
 * real platformd (#2051, epic #1665). No page.route mocks and no writes: the
 * page is compared with what the server answered the page itself, and each
 * control's capability gate with the server's capability list. The test
 * daemon may run no gatewayd and no state store, so the spec branches on the
 * answer instead of expecting a fixed state.
 */

/** The reason the capability gate shows for an op the server does not list. */
const NOT_OFFERED = 'not offered by this server';

const LIST_OP = 'GET /api/v1/gateway/state/{id}/admitted-vteps';
const GET_OP = 'GET /api/v1/gateway/state/{id}/admitted-vteps/{vtep}';

interface Capability {
  op: string;
  enabled?: boolean;
  reason?: string;
}

/** Waits for the page's own GET on exactly this path. */
function apiResponse(page: Page, path: string): Promise<Response> {
  return page.waitForResponse(
    (r) => r.request().method() === 'GET' && new URL(r.url()).pathname === path,
  );
}

/** Asserts one control carries the gate the server's capability list implies. */
async function expectGated(control: Locator, op: string, listed: Map<string, Capability>) {
  const cap = listed.get(op);
  const enabled = cap?.enabled === true;
  await expect(control).toHaveAttribute('data-capability-op', op);
  await expect(control).toHaveAttribute('data-capability-enabled', enabled ? 'true' : 'false');
  if (!enabled) {
    await expect(control).toBeDisabled();
    await expect(control).toHaveAttribute('title', cap?.reason ?? NOT_OFFERED);
  }
}

async function capabilityMap(sdk: {
  capabilities: { list: () => Promise<{ success: boolean; error?: unknown; data?: { capabilities?: Capability[] } }> };
}): Promise<Map<string, Capability>> {
  const caps = await sdk.capabilities.list();
  expect(caps.success, JSON.stringify(caps.error)).toBeTruthy();
  return new Map<string, Capability>((caps.data?.capabilities ?? []).map((c) => [c.op, c]));
}

test.describe('Gateway admitted VTEPs', () => {
  test('the overlay section lists the admitted VTEPs behind the Refresh and Details gates', async ({
    adminPage,
    sdk,
  }) => {
    const listed = await capabilityMap(sdk);

    const stateRes = apiResponse(adminPage, '/api/v1/gateway/state');
    await adminPage.goto('/networking/gateway');
    const state = await stateRes;
    const card = adminPage.getByTestId('gateway-snapshots-card');
    await expect(card).toBeVisible();

    let reported: Array<{ gateway_id: string }> = [];
    if (state.ok()) {
      const body = unwrapPayload<{ gateways?: Array<{ gateway_id: string }> }>(await state.json());
      reported = body.gateways ?? [];
    }

    if (reported.length === 0) {
      if (state.ok()) {
        await expect(card.getByTestId('gateway-snapshots-empty')).toBeVisible();
      } else {
        // The SDK retries a 5xx with backoff before the card shows the refusal.
        await expect(card.getByTestId('gateway-snapshots-error')).toBeVisible({ timeout: 30_000 });
      }
      // No gateway reported: the admitted-VTEP list of an unknown gateway is
      // refused with an HTTP status (404 for an unknown gateway, 503 when the
      // daemon runs no state store), never an empty success.
      const missing = await sdk.gateway.listAdmittedVTEPs('e2e-missing');
      expect(missing.success).toBe(false);
      expect(missing.error?.status ?? 0).toBeGreaterThanOrEqual(400);
      return;
    }

    const gatewayId = reported[0].gateway_id;
    const view = card.getByRole('button', { name: `View ${gatewayId}`, exact: true });
    if (await view.isDisabled()) {
      // The snapshot read is withheld: the overlay section cannot open.
      await expect(adminPage.getByTestId('gateway-admitted-vtep-row')).toHaveCount(0);
      return;
    }
    const detailRes = apiResponse(adminPage, `/api/v1/gateway/state/${encodeURIComponent(gatewayId)}`);
    await view.click();
    await detailRes;

    const summary = adminPage.getByTestId('gateway-overlay-summary');
    try {
      await summary.waitFor({ state: 'visible', timeout: 5_000 });
    } catch {
      // The snapshot reports no overlay: no admitted-VTEP section at all.
      await expect(adminPage.getByTestId('gateway-admitted-vtep-row')).toHaveCount(0);
      return;
    }

    // The innermost element holding the overlay summary is the overlay
    // section; its Refresh is not the snapshots card's.
    const section = adminPage.locator('div').filter({ has: summary }).last();
    await expectGated(section.getByRole('button', { name: 'Refresh', exact: true }), LIST_OP, listed);

    const rows = section.getByTestId('gateway-admitted-vtep-row');
    if ((await rows.count()) > 0) {
      await expectGated(rows.first().getByRole('button', { name: /^Details / }), GET_OP, listed);
    } else {
      await expect(section.getByText('No VTEP is admitted')).toBeVisible();
    }
  });

  test('the server lists both admitted-VTEP ops in its capabilities', async ({ sdk }) => {
    const listed = await capabilityMap(sdk);
    // A renamed route drops its op from the list and fails here.
    for (const op of [LIST_OP, GET_OP]) {
      const cap = listed.get(op);
      expect(cap, `${op} is not in the capability list`).toBeDefined();
      expect(cap?.enabled === true || Boolean(cap?.reason), `${op} is neither enabled nor carries a reason`).toBe(true);
    }
  });
});
