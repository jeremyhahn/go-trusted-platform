import type { Page, Response } from '@playwright/test';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

/**
 * Registry page against the real platformd (#2063, RegistryService).
 *
 * No page.route mocks: each assertion compares the page with what the
 * server answered the page itself.
 *
 * Inspect, Delete and the OCI capability gates of a real pushed tag are in registry-seeded.spec.ts.
 */

/** Waits for the page's own GET whose path matches. */
function apiResponse(page: Page, path: RegExp): Promise<Response> {
  return page.waitForResponse(
    (r) => r.request().method() === 'GET' && path.test(new URL(r.url()).pathname),
  );
}

const HEALTH_LABEL: Record<number, string> = {
  0: 'Unknown',
  1: 'Healthy',
  2: 'Degraded',
  3: 'Unhealthy',
};

test.describe('Registry', () => {
  test('the status card shows what /compute/images/status returns', async ({ adminPage }) => {
    const statusRes = apiResponse(adminPage, /\/api\/v1\/compute\/images\/status$/);
    await adminPage.goto('/compute/registry');
    const res = await statusRes;
    expect(res.ok(), `${res.url()} answered ${res.status()}`).toBeTruthy();
    const status = unwrapPayload<{ Health?: number; Version?: string }>(await res.json());

    const card = adminPage.getByTestId('registry-status');
    await expect(card).toContainText(HEALTH_LABEL[status.Health ?? 0] ?? HEALTH_LABEL[0]);
    await expect(card).toContainText(status.Version || '—');
  });

  test('listing an unknown repository shows what /v2/<name>/tags/list returns', async ({
    adminPage,
  }) => {
    const name = `e2e-missing-${Date.now()}`;
    await adminPage.goto('/compute/registry');
    await expect(adminPage.getByTestId('registry-status')).toBeVisible();

    const tagsRes = apiResponse(adminPage, new RegExp(`^/v2/${name}/tags/list$`));
    await adminPage.getByRole('textbox', { name: 'Repository' }).fill(name);
    await adminPage.getByRole('button', { name: /list tags/i }).click();
    const res = await tagsRes;

    if (res.ok()) {
      const body = (await res.json()) as { tags?: string[] | null };
      expect(body.tags ?? []).toHaveLength(0);
      await expect(adminPage.getByText(`${name} has no tags.`)).toBeVisible();
    } else {
      // An unknown repository is the OCI NAME_UNKNOWN answer.
      expect(res.status()).toBe(404);
      await expect(adminPage.getByText(/Failed to list tags/)).toBeVisible();
    }
    await expect(adminPage.getByRole('button', { name: /^Inspect / })).toHaveCount(0);
  });
});
