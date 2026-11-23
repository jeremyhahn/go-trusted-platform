import type { Locator } from '@playwright/test';
import type { PlatformClient } from 'trusted-platform-sdk';
import { expect, test } from './fixtures';

/**
 * The migrations page against the real platformd (#2044, epic #1665).
 *
 * Read-only: no page.route, no fills and no write control is clicked. The
 * Prepare receiver gate is checked against GET /api/v1/capabilities; an
 * offered control is never asserted enabled (the page disables it until the
 * form is filled).
 */

const NOT_OFFERED = 'not offered by this server';

interface Capability {
  op: string;
  kind: string;
  enabled: boolean;
  reason?: string;
}

type Capabilities = Map<string, Capability>;

/** The server's capability list, keyed by op. */
async function capabilityMap(sdk: PlatformClient): Promise<Capabilities> {
  const res = await sdk.capabilities.list();
  expect(res.success, JSON.stringify(res.error)).toBeTruthy();
  return new Map((res.data?.capabilities ?? []).map((c) => [c.op, c]));
}

/**
 * Asserts control carries the Gated attributes for op as listed: a control
 * the server does not enable is disabled with the reason (or NOT_OFFERED) as
 * its title.
 */
async function expectGated(control: Locator, op: string, listed: Capabilities): Promise<void> {
  const cap = listed.get(op);
  const enabled = cap?.enabled === true;
  await expect(control).toHaveAttribute('data-capability-op', op);
  await expect(control).toHaveAttribute('data-capability-enabled', enabled ? 'true' : 'false');
  if (!enabled) {
    await expect(control).toBeDisabled();
    await expect(control).toHaveAttribute('title', cap?.reason ?? NOT_OFFERED);
  }
}

test.describe('Migrations page', () => {
  test("the migrations page gates Prepare receiver on the server's capability list", async ({ adminPage, sdk }) => {
    const listed = await capabilityMap(sdk);
    await adminPage.goto('/compute/migrations');
    await expectGated(
      adminPage.getByRole('button', { name: 'Prepare receiver' }),
      'POST /api/v1/compute/migrations/prepare',
      listed,
    );
    // The receiver needs the guest spec: the form asks for memory and vCPUs.
    await expect(adminPage.getByLabel('Memory (MB)')).toBeVisible();
    await expect(adminPage.getByLabel('vCPUs')).toBeVisible();
  });

  test('the server lists the finalize op the receiver controls gate', async ({ adminPage, sdk }) => {
    // The Finalize control lives in the receiver card, which only a Prepare
    // the page made shows; this read-only spec checks its op against the
    // server's list so the control can never read NOT_OFFERED.
    const listed = await capabilityMap(sdk);
    const finalize = listed.get('POST /api/v1/compute/migrations/{receiverId}/finalize');
    expect(finalize, 'the capability list carries the finalize op').toBeDefined();
    expect(finalize?.kind).toBe('route');

    await adminPage.goto('/compute/migrations');
    await expect(adminPage.getByRole('button', { name: 'Prepare receiver' })).toBeVisible();
    await expect(adminPage.getByTestId('migration-receiver')).toHaveCount(0);
  });
});
