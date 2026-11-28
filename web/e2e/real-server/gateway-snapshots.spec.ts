import type { Locator, Page, Response } from '@playwright/test';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

/**
 * The gateway snapshots card and the gateway mode and BGP controls against
 * the real platformd (#2051, epic #1665). No page.route mocks and no writes:
 * each assertion compares the page with what the server answered the page
 * itself, and every control's capability gate with the server's capability
 * list. The test daemon may run no gatewayd and no state store, so the spec
 * branches on the answer instead of expecting a fixed state.
 */

/** The reason the capability gate shows for an op the server does not list. */
const NOT_OFFERED = 'not offered by this server';

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
    // An offered control is never asserted enabled: Sign Zone and Resolve
    // can be disabled for other reasons (no keys yet, an empty name).
    await expect(control).toBeDisabled();
    await expect(control).toHaveAttribute('title', cap?.reason ?? NOT_OFFERED);
  }
}

test.describe('Gateway snapshots and controls', () => {
  test('the snapshots card shows what GET /api/v1/gateway/state answered', async ({ adminPage, sdk }) => {
    const caps = await sdk.capabilities.list();
    expect(caps.success, JSON.stringify(caps.error)).toBeTruthy();
    const listed = new Map<string, Capability>(
      (caps.data?.capabilities ?? []).map((c) => [c.op, c]),
    );

    const stateRes = apiResponse(adminPage, '/api/v1/gateway/state');
    await adminPage.goto('/networking/gateway');
    const state = await stateRes;
    const card = adminPage.getByTestId('gateway-snapshots-card');
    await expect(card).toBeVisible();

    let reported: Array<{ gateway_id: string }> = [];
    if (state.ok()) {
      const body = unwrapPayload<{ gateways?: Array<{ gateway_id: string }> }>(await state.json());
      reported = body.gateways ?? [];
      if (reported.length === 0) {
        await expect(card.getByTestId('gateway-snapshots-empty')).toBeVisible();
        await expect(card.getByTestId('gateway-snapshot-row')).toHaveCount(0);
      } else {
        await expect(card.getByTestId('gateway-snapshot-row')).toHaveCount(reported.length);
      }
    } else {
      // The SDK retries a 5xx with backoff (about 7 s in all) before the card
      // shows the refusal.
      await expect(card.getByTestId('gateway-snapshots-error')).toBeVisible({ timeout: 30_000 });
    }

    await expectGated(card.getByRole('button', { name: 'Refresh', exact: true }), 'GET /api/v1/gateway/state', listed);
    if (reported.length > 0) {
      await expectGated(
        card.getByRole('button', { name: `View ${reported[0].gateway_id}`, exact: true }),
        'GET /api/v1/gateway/state/{id}',
        listed,
      );
    }
  });

  test('the mode and BGP controls carry the gates the server lists, or are absent when gatewayd does not run', async ({
    adminPage,
    sdk,
  }) => {
    const caps = await sdk.capabilities.list();
    expect(caps.success, JSON.stringify(caps.error)).toBeTruthy();
    const listed = new Map<string, Capability>(
      (caps.data?.capabilities ?? []).map((c) => [c.op, c]),
    );

    const statusRes = apiResponse(adminPage, '/api/v1/gateway/status');
    await adminPage.goto('/networking/gateway');
    const status = await statusRes;
    // The snapshots card renders in either branch; wait for it so the
    // absence checks below run against a rendered page.
    await expect(adminPage.getByTestId('gateway-snapshots-card')).toBeVisible();

    if (status.status() === 503) {
      await expect(adminPage.getByTestId('gateway-mode-card')).toHaveCount(0);
      await expect(adminPage.getByRole('button', { name: 'Announce', exact: true })).toHaveCount(0);
      return;
    }

    // The BGP peers card has no testid: take the innermost element holding
    // both its title and a Refresh button (the snapshots card has its own
    // Refresh, so a page-wide Refresh is ambiguous).
    const peersCard = adminPage
      .locator('div')
      .filter({ has: adminPage.getByRole('heading', { name: 'BGP peers', exact: true }) })
      .filter({ has: adminPage.getByRole('button', { name: 'Refresh', exact: true }) })
      .last();
    await expectGated(
      peersCard.getByRole('button', { name: 'Refresh', exact: true }),
      'GET /api/v1/gateway/bgp/peers',
      listed,
    );
    await expectGated(
      adminPage.getByRole('button', { name: 'Announce', exact: true }),
      'POST /api/v1/gateway/bgp/prefixes',
      listed,
    );

    const modeCard = adminPage.getByTestId('gateway-mode-card');
    if ((await modeCard.count()) > 0) {
      await expectGated(
        modeCard.getByRole('button', { name: 'Apply modes', exact: true }),
        'POST /api/v1/gateway/mode',
        listed,
      );
    }

    const prefixRows = adminPage.getByTestId('bgp-prefix-row');
    if ((await prefixRows.count()) > 0) {
      await expectGated(
        prefixRows.first().getByRole('button', { name: /^Withdraw / }),
        'DELETE /api/v1/gateway/bgp/prefixes',
        listed,
      );
    }
  });
});
