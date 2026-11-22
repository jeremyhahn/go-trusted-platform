import type { Page } from '@playwright/test';
import { expect, test } from './fixtures';

/**
 * vTPM runtime page against the real daemon (#2072, epic #1665).
 *
 * No page.route mocks: every reply comes from the harness server.
 *
 * Covered here:
 *  - the eight runtime controls (Check state, Start, Stop, Quote, Seal,
 *    Unseal, Read PCR, Extend PCR) follow GET /api/v1/capabilities: each
 *    control's data-capability-enabled matches what the server lists;
 *  - Check state (IsVTPMRunning, GET /bundles/{id}/state): when the server
 *    offers the vTPM routes and creates a bundle, the run state the page shows
 *    is the page's own state reply; when it does not, the page shows the
 *    server's refusal.
 *
 * Not covered, and why (gaps):
 *  - Start, Stop, Quote, Seal, Unseal, Read PCR and Extend PCR are not driven:
 *    the harness config (platformd.test.yaml) has no vtpm block and no software
 *    TPM to start, so a bundle cannot run and these operations have nothing to
 *    act on. The mocked spec e2e/vtpm-runtime.spec.ts drives their UI.
 */

const STATE_OP = 'GET /api/v1/vtpm/bundles/{id}/state';

const controls: Array<[string, string]> = [
  ['Check state', STATE_OP],
  ['Start vTPM', 'POST /api/v1/vtpm/bundles/{id}/start'],
  ['Stop vTPM', 'POST /api/v1/vtpm/bundles/{id}/stop'],
  ['Quote', 'POST /api/v1/vtpm/bundles/{id}/quote'],
  ['Seal', 'POST /api/v1/vtpm/bundles/{id}/seal'],
  ['Unseal', 'POST /api/v1/vtpm/bundles/{id}/unseal'],
  ['Read PCR', 'GET /api/v1/vtpm/bundles/{id}/pcrs'],
  ['Extend PCR', 'POST /api/v1/vtpm/bundles/{id}/pcrs/extend'],
];

/** The ops the server lists as enabled, from GET /api/v1/capabilities. */
async function enabledOps(page: Page): Promise<Set<string>> {
  const res = await page.request.get('/api/v1/capabilities');
  expect(res.ok(), `GET /api/v1/capabilities: ${res.status()}`).toBe(true);
  const body = (await res.json()) as {
    capabilities?: Array<{ op: string; enabled: boolean }>;
    data?: { capabilities?: Array<{ op: string; enabled: boolean }> };
  };
  const list = body.capabilities ?? body.data?.capabilities ?? [];
  return new Set(list.filter((c) => c.enabled).map((c) => c.op));
}

function gap(description: string): void {
  test.info().annotations.push({ type: 'gap', description });
}

test.describe('vTPM runtime page against the real server', () => {
  test('each runtime control follows the server capabilities', async ({ adminPage }) => {
    const enabled = await enabledOps(adminPage);
    await adminPage.goto('/tpm/vtpm/e2e-probe');
    await expect(adminPage.getByRole('heading', { name: 'vTPM Runtime' })).toBeVisible();

    for (const [name, op] of controls) {
      const button = adminPage.getByRole('button', { name, exact: true });
      await expect(button, name).toHaveAttribute('data-capability-op', op);
      await expect(button, name).toHaveAttribute('data-capability-enabled', enabled.has(op) ? 'true' : 'false');
      if (!enabled.has(op)) {
        await expect(button, name).toBeDisabled();
        gap(`${op} is not offered by the harness server`);
      }
    }
  });

  test('Check state shows the state the server answers', async ({ adminPage, sdk }) => {
    const enabled = await enabledOps(adminPage);

    if (!enabled.has(STATE_OP)) {
      // The server offers no vTPM backend: the control carries its refusal.
      await adminPage.goto('/tpm/vtpm/e2e-probe');
      const button = adminPage.getByRole('button', { name: 'Check state', exact: true });
      await expect(button).toHaveAttribute('data-capability-enabled', 'false');
      await expect(button).toBeDisabled();
      await expect(button).toHaveAttribute('title', /.+/);
      gap('no vtpm block in platformd.test.yaml: IsVTPMRunning is not offered');
      return;
    }

    const created = await sdk.vtpm.createBundle({ options: {} });
    const bundleId = created.success && created.data ? created.data.id : 'e2e-missing-bundle';
    if (!created.success) {
      gap(`createBundle refused: ${created.error?.message ?? 'no message'}`);
    }

    try {
      await adminPage.goto(`/tpm/vtpm/${encodeURIComponent(bundleId)}`);
      const button = adminPage.getByRole('button', { name: 'Check state', exact: true });
      await expect(button).toBeEnabled();

      const replyPromise = adminPage.waitForResponse(
        (r) => r.request().method() === 'GET' && r.url().includes(`/vtpm/bundles/${encodeURIComponent(bundleId)}/state`),
      );
      await button.click();
      const reply = await replyPromise;
      const body = (await reply.json()) as Record<string, unknown>;

      if (reply.ok()) {
        const state = ((body.data as Record<string, unknown> | undefined) ?? body) as { running?: boolean };
        await expect(adminPage.getByTestId('vtpm-run-state')).toHaveText(state.running ? 'Running' : 'Stopped');
      } else {
        // The page shows the server's refusal, not a state of its own.
        const err = body.error as { message?: string } | string | undefined;
        const message = typeof err === 'string' ? err : err?.message ?? (body.message as string | undefined);
        await expect(adminPage.getByText('Error reading vTPM state').first()).toBeVisible();
        if (message) {
          await expect(adminPage.getByText(message).first()).toBeVisible();
        }
        gap(`GET /bundles/{id}/state refused (${reply.status()}): ${message ?? 'no message'}`);
      }
    } finally {
      if (created.success && created.data) {
        await sdk.vtpm.deleteBundle(created.data.id);
      }
    }
  });
});
