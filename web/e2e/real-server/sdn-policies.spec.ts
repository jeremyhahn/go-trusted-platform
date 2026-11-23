import type { Locator, Page, Response } from '@playwright/test';
import { expect, test } from './fixtures';

/**
 * The SDN policies page against the real platformd (#2064, epic #1665). No
 * page.route mocks: each assertion compares the page with what the server
 * answered the page itself. Without an SDN service platformd answers 503 and
 * the page says SDN is not configured; with one, the spec checks the Gated
 * controls against the server's capabilities and, when the server offers
 * ApplyPolicy, applies its own policy through the SDK, opens its Details and
 * deletes it again. It never clicks Apply or Delete in the page.
 */

/** The reason the capability gate shows for an op the server does not list. */
const NOT_OFFERED = 'not offered by this server';

const POLICIES_PATH = '/api/v1/sdn/policies';
const LIST_OP = 'GET /api/v1/sdn/policies';
const GET_OP = 'GET /api/v1/sdn/policies/{id}';
const APPLY_OP = 'POST /api/v1/sdn/policies';
const DELETE_OP = 'DELETE /api/v1/sdn/policies/{id}';

/** The SDK retries a 5xx read three times with backoff before the page shows it. */
const SETTLED = { timeout: 20_000 };

type Capability = { op: string; enabled?: boolean; reason?: string };

/** Waits for the page's own GET on exactly this path. */
function apiResponse(page: Page, path: string): Promise<Response> {
  return page.waitForResponse(
    (r) => r.request().method() === 'GET' && new URL(r.url()).pathname === path,
  );
}

/** Asserts a Gated control carries the op and the server's answer for it. */
async function expectGated(
  control: Locator,
  op: string,
  listed: Map<string, Capability>,
): Promise<void> {
  const cap = listed.get(op);
  const enabled = cap?.enabled === true;
  await expect(control).toHaveAttribute('data-capability-op', op);
  await expect(control).toHaveAttribute('data-capability-enabled', enabled ? 'true' : 'false');
  if (!enabled) {
    await expect(control).toHaveAttribute('title', cap ? (cap.reason ?? '') : NOT_OFFERED);
  }
}

test.describe('SDN policies page', () => {
  test('the policies page shows what the server answers and gates its controls', async ({ adminPage, sdk }) => {
    const caps = await sdk.capabilities.list();
    expect(caps.success, JSON.stringify(caps.error)).toBeTruthy();
    const listed = new Map<string, Capability>(
      (caps.data?.capabilities ?? []).map((c) => [c.op, c]),
    );

    const policiesRes = apiResponse(adminPage, POLICIES_PATH);
    await adminPage.goto('/networking/policies');
    const policies = await policiesRes;

    if (policies.status() === 503) {
      await expect(adminPage.getByTestId('sdn-policies-not-configured')).toBeVisible(SETTLED);
      await expect(adminPage.getByText('Error Loading Policies')).toHaveCount(0);
      return;
    }

    if (!policies.ok()) {
      // Any other refused list read shows the server's message in an alert.
      await expect(adminPage.getByRole('alert').first()).toBeVisible(SETTLED);
      await expect(adminPage.getByText('Error Loading Policies')).toBeVisible();
      return;
    }

    await expect(adminPage.getByRole('heading', { name: 'SDN Policies' })).toBeVisible();
    await expectGated(adminPage.getByRole('button', { name: 'Refresh', exact: true }), LIST_OP, listed);
    await expectGated(adminPage.getByRole('button', { name: 'Apply Policy', exact: true }), APPLY_OP, listed);
  });

  test('an applied policy is listed with gated Details and Delete', async ({ adminPage, sdk }) => {
    const caps = await sdk.capabilities.list();
    expect(caps.success, JSON.stringify(caps.error)).toBeTruthy();
    const listed = new Map<string, Capability>(
      (caps.data?.capabilities ?? []).map((c) => [c.op, c]),
    );

    const probe = await sdk.sdn.listPolicies();
    if (!probe.success) {
      // No SDN service (503) or another refusal: the first test covers the page.
      return;
    }

    if (listed.get(APPLY_OP)?.enabled !== true) {
      await adminPage.goto('/networking/policies');
      await expectGated(adminPage.getByRole('button', { name: 'Apply Policy', exact: true }), APPLY_OP, listed);
      return;
    }

    const name = `e2e-pol-${Date.now().toString(36)}`;
    const applied = await sdk.sdn.applyPolicy({
      policyId: name,
      config: { name, type: 'POLICY_TYPE_ACL', priority: 100, enabled: false },
    });
    expect(applied.success, JSON.stringify(applied.error)).toBeTruthy();
    const policyId = applied.data?.policy?.id ?? name;
    try {
      const policiesRes = apiResponse(adminPage, POLICIES_PATH);
      await adminPage.goto('/networking/policies');
      expect((await policiesRes).ok()).toBeTruthy();

      const row = adminPage.getByRole('row').filter({ hasText: name }).first();
      await expect(row).toBeVisible(SETTLED);

      await row.getByRole('button', { name: 'Open menu' }).click();
      const details = adminPage.getByRole('menuitem', { name: 'Details' });
      await expectGated(details, GET_OP, listed);
      await expectGated(adminPage.getByRole('menuitem', { name: 'Delete' }), DELETE_OP, listed);

      if (listed.get(GET_OP)?.enabled === true) {
        await details.click();
        await expect(adminPage.getByTestId('sdn-policy-detail')).toContainText(name, SETTLED);
      } else {
        await adminPage.keyboard.press('Escape');
      }
    } finally {
      await sdk.sdn.deletePolicy(policyId);
    }
  });
});
