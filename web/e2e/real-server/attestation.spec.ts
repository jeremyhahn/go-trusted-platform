import type { Page, Response } from '@playwright/test';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

/**
 * Attestation views against the real platformd (#2038, epic #1665).
 *
 * No page.route mocks: each test visits one attestation page, waits for the
 * page's own GET and compares what the page shows with what the server
 * answered. Every control wrapped in the capability gate must carry the
 * enabled state the server's capabilities listing gives for its op.
 */

/** Waits for the page's own GET whose path matches. */
function apiResponse(page: Page, path: RegExp): Promise<Response> {
  return page.waitForResponse(
    (r) => r.request().method() === 'GET' && path.test(new URL(r.url()).pathname),
  );
}

async function json<T>(r: Response): Promise<T> {
  expect(r.ok(), `${r.url()} answered ${r.status()}`).toBeTruthy();
  return unwrapPayload<T>(await r.json());
}

/** The server's capabilities listing as op -> enabled. */
async function capabilityMap(sdk: {
  capabilities: { list(): Promise<{ success: boolean; data?: { capabilities: Array<{ op: string; enabled: boolean }> }; error?: unknown }> };
}): Promise<Map<string, boolean>> {
  const res = await sdk.capabilities.list();
  expect(res.success, JSON.stringify(res.error)).toBeTruthy();
  return new Map((res.data?.capabilities ?? []).map((c) => [c.op, c.enabled]));
}

/** Each gated control on the page reports the server's answer for its op. */
async function expectGatedControlsMatch(page: Page, caps: Map<string, boolean>): Promise<number> {
  const controls = page.locator('[data-capability-op]');
  const count = await controls.count();
  for (let i = 0; i < count; i++) {
    const control = controls.nth(i);
    const op = await control.getAttribute('data-capability-op');
    expect(op, 'gated control names its op').toBeTruthy();
    const enabled = caps.get(op as string) ?? false;
    await expect(control, `${op}`).toHaveAttribute('data-capability-enabled', enabled ? 'true' : 'false');
  }
  return count;
}

interface ManifestList {
  manifests?: Array<{ id: string; hostId?: string }>;
}

test.describe('Attestation collect', () => {
  test('gates the host, VM and container collect controls on the capabilities', async ({ adminPage, sdk }) => {
    const caps = await capabilityMap(sdk);
    await adminPage.goto('/attestation/collect');
    for (const id of ['collect-host-submit', 'collect-vm-submit', 'collect-container-submit']) {
      await expect(adminPage.getByTestId(id)).toBeVisible();
    }
    expect(await expectGatedControlsMatch(adminPage, caps)).toBeGreaterThanOrEqual(3);
  });
});

test.describe('Attestation manifests', () => {
  test('shows the manifests the server lists and gates verify and delete', async ({ adminPage, sdk }) => {
    const caps = await capabilityMap(sdk);
    const listRes = apiResponse(adminPage, /\/api\/v1\/attestation\/manifests$/);
    await adminPage.goto('/attestation/manifests');
    const body = await json<ManifestList>(await listRes);
    const manifests = body.manifests ?? [];

    const total = adminPage.getByText('Total Manifests').locator('xpath=../..');
    await expect(total).toContainText(String(manifests.length));
    if (manifests.length === 0) {
      await expect(adminPage.getByText('No manifests found')).toBeVisible();
    }
    await expectGatedControlsMatch(adminPage, caps);
  });
});

test.describe('Attestation quotes', () => {
  test('gates get and verify quote on the capabilities', async ({ adminPage, sdk }) => {
    const caps = await capabilityMap(sdk);
    const listRes = apiResponse(adminPage, /\/api\/v1\/attestation\/manifests$/);
    await adminPage.goto('/attestation/quotes');
    await json<ManifestList>(await listRes);
    await expect(adminPage.getByTestId('quote-verify')).toBeVisible();
    expect(await expectGatedControlsMatch(adminPage, caps)).toBeGreaterThanOrEqual(2);
  });
});

test.describe('Attestation verify', () => {
  test('lists a row per manifest the server lists and gates Run Verification', async ({ adminPage, sdk }) => {
    const caps = await capabilityMap(sdk);
    const listRes = apiResponse(adminPage, /\/api\/v1\/attestation\/manifests$/);
    await adminPage.goto('/attestation/verify');
    const body = await json<ManifestList>(await listRes);
    for (const m of body.manifests ?? []) {
      if (m.hostId) await expect(adminPage.getByText(m.hostId).first()).toBeVisible();
    }
    await expect(adminPage.getByRole('button', { name: /Run Verification/ })).toBeVisible();
    expect(await expectGatedControlsMatch(adminPage, caps)).toBeGreaterThanOrEqual(1);
  });
});

test.describe('Attestation verdicts', () => {
  test('shows the caller policy and the verdicts the server answers', async ({ adminPage, sdk }) => {
    const caps = await capabilityMap(sdk);
    const callersRes = apiResponse(adminPage, /\/api\/v1\/attestation\/callers$/);
    const verdictsRes = apiResponse(adminPage, /\/api\/v1\/attestation\/verdicts$/);
    await adminPage.goto('/attestation/verdicts');

    const callers = await json<{ policy?: { strategy?: string }; strategy?: string }>(await callersRes);
    const strategy = callers.policy?.strategy ?? callers.strategy;
    const policyCard = adminPage.getByTestId('caller-policy');
    await expect(policyCard).toBeVisible();
    if (strategy) await expect(policyCard).toContainText(strategy);

    const verdicts = await json<{ verdicts?: unknown[] }>(await verdictsRes);
    const card = adminPage.getByTestId('device-verdicts');
    if ((verdicts.verdicts ?? []).length === 0) {
      await expect(card.getByText('No verdicts yet.')).toBeVisible();
    } else {
      await expect(card.getByText('No verdicts yet.')).toHaveCount(0);
    }
    await expectGatedControlsMatch(adminPage, caps);
  });
});
