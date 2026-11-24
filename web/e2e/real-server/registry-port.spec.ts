/**
 * Container registry page against the real-server harness (#2036, epic #1665).
 *
 * Ported from web/e2e/registry.spec.ts. The SDK can list tags, delete a
 * manifest and read status, but cannot push an image, and the harness seeds
 * none, so the tag list, delete-after-confirm and cancel cases have no server
 * state behind them and are listed as gaps in the PR body. The status card is
 * held to the status answer the server gave the page itself, and an unknown
 * repository is held to the server's refusal.
 */
import type { Page, Response } from '@playwright/test';
import { test, expect } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

interface RegistryStatus {
  Health: number;
  Version?: string;
  ReadOnly?: boolean;
}

/** Labels the page gives the registry health codes. */
const HEALTH_LABEL: Record<number, string> = {
  0: 'Unknown',
  1: 'Healthy',
  2: 'Degraded',
  3: 'Unhealthy',
};

function isStatusRead(r: Response): boolean {
  return r.request().method() === 'GET' && /\/compute\/images\/status\b/.test(r.url());
}

async function openPage(page: Page): Promise<Response> {
  const status = page.waitForResponse(isStatusRead);
  await page.goto('/compute/registry');
  return status;
}

test.describe('Container registry', () => {
  test('shows the registry status the server reports', async ({ adminPage }) => {
    const response = await openPage(adminPage);

    const card = adminPage.getByTestId('registry-status');
    if (!response.ok()) {
      await expect(card).toContainText(/failed to load status/i);
      return;
    }
    const status = unwrapPayload<RegistryStatus>(await response.json());
    await expect(card).toContainText(HEALTH_LABEL[status.Health] ?? HEALTH_LABEL[0]);
    if (status.Version) {
      await expect(card).toContainText(status.Version);
    }
    await expect(card).toContainText(status.ReadOnly ? 'Read-only' : 'Read-write');
  });

  test('shows an error for a repository the server does not hold', async ({ adminPage }) => {
    await openPage(adminPage);
    const repository = `e2e-missing-${Date.now().toString(36)}`;

    const answered = adminPage.waitForResponse(
      (r) => r.request().method() === 'GET' && r.url().includes(`${repository}/tags`)
    );
    await adminPage.getByLabel('Repository').fill(repository);
    await adminPage.getByRole('button', { name: /list tags/i }).click();

    expect((await answered).ok()).toBe(false);
    await expect(adminPage.getByText(/failed to list tags/i)).toBeVisible();
  });

  test('redirects an unauthenticated browser to login', async ({ browser }) => {
    const context = await browser.newContext();
    const page = await context.newPage();
    try {
      await page.goto('/compute/registry');
      await expect(page).toHaveURL(/\/auth\/webauthn/);
    } finally {
      await context.close();
    }
  });
});
