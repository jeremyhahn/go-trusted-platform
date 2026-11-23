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
 *    server's refusal;
 *  - the runtime flow: on a bundle the server creates, Start, Check state,
 *    Quote, Seal, Unseal, Read PCR, Extend PCR (the new value differs from
 *    the one read before) and Stop, each driven by its page control. The
 *    harness config (platformd.test.yaml) gives the daemon a vtpm block in
 *    its run directory, so the vTPM routes are served.
 *
 * Not covered, and why (gaps):
 *  - bundle creation and Start need the swtpm binary on PATH. The Web
 *    Console E2E runner installs none, so there the flow test records
 *    createBundle's missing-swtpm refusal (a `gap` annotation) instead of
 *    driving the controls; any other refusal fails the test.
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

/**
 * The one createBundle refusal that is a harness gap: the runner has no swtpm
 * binary (pkg/swtpm "swtpm not installed", wrapped by pkg/vtpm as "vtpm: swtpm
 * create failed: ..."; the REST handler's error body keeps the cause text).
 */
const MISSING_SWTPM = /swtpm not installed/;

/** Records a createBundle refusal as a gap, and fails on any other refusal. */
function createRefusedGap(message: string | undefined): void {
  expect(message ?? '', 'createBundle refused for a reason other than a missing swtpm binary').toMatch(MISSING_SWTPM);
  gap(`createBundle refused: ${message}`);
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
      createRefusedGap(created.error?.message);
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

  test('drives a running bundle through every runtime control', async ({ adminPage, sdk }) => {
    const START_OP = 'POST /api/v1/vtpm/bundles/{id}/start';
    const enabled = await enabledOps(adminPage);

    if (!enabled.has(START_OP)) {
      await adminPage.goto('/tpm/vtpm/e2e-probe');
      await expect(adminPage.getByRole('button', { name: 'Start vTPM', exact: true })).toBeDisabled();
      gap(`${START_OP} is not offered by the harness server: no runtime flow`);
      return;
    }

    const created = await sdk.vtpm.createBundle({ options: {} });
    if (!created.success || !created.data) {
      // A runner without the swtpm binary lands here: the server refuses, and
      // only that refusal is a gap; any other refusal fails the test.
      createRefusedGap(created.error?.message);
      return;
    }

    const bundleId = created.data.id;
    const page = adminPage;
    const runState = page.getByTestId('vtpm-run-state');
    const button = (name: string) => page.getByRole('button', { name, exact: true });
    const confirm = async (title: string) => {
      const dialog = page.getByRole('dialog', { name: title });
      await expect(dialog).toBeVisible();
      await dialog.getByRole('button', { name: 'Confirm', exact: true }).click();
    };
    const checkState = async (want: 'Running' | 'Stopped') => {
      const reply = page.waitForResponse(
        (r) => r.request().method() === 'GET' && r.url().includes(`/vtpm/bundles/${encodeURIComponent(bundleId)}/state`),
      );
      await button('Check state').click();
      expect((await reply).ok(), 'GET /bundles/{id}/state').toBe(true);
      await expect(runState).toHaveText(want);
    };

    try {
      await page.goto(`/tpm/vtpm/${encodeURIComponent(bundleId)}`);

      // Start
      await button('Start vTPM').click();
      await expect(runState).toHaveText('Running');
      await expect(page.getByTestId('vtpm-socket')).toBeVisible();

      // Check state (IsVTPMRunning)
      await checkState('Running');

      // Quote
      await button('Quote').click();
      await expect(page.getByTestId('vtpm-quote-result')).toContainText('Hash algorithm');

      // Seal, then Unseal the blob Seal returned
      await page.getByLabel('Data to seal', { exact: true }).fill('e2e-sealed-secret');
      await button('Seal').click();
      await expect(page.getByTestId('vtpm-sealed-blob')).not.toHaveValue('');
      await button('Unseal').click();
      await expect(page.getByTestId('vtpm-unsealed-data')).toContainText('e2e-sealed-secret');

      // Read PCR
      const pcrValue = page.getByTestId('vtpm-pcr-value');
      await page.getByLabel('Read PCR index', { exact: true }).fill('16');
      await button('Read PCR').click();
      await expect(pcrValue).not.toHaveText('');
      const before = (await pcrValue.textContent()) ?? '';

      // Extend PCR, then Read PCR shows a new value
      await page.getByLabel('Extend PCR index', { exact: true }).fill('16');
      await page.getByLabel('Data to extend (hex)', { exact: true }).fill('00112233');
      await button('Extend PCR').click();
      await confirm('Extend this PCR?');
      await expect(page.getByTestId('vtpm-extend-result')).toContainText('PCR 16 extended');
      await button('Read PCR').click();
      await expect(pcrValue).not.toHaveText(before);

      // Stop
      await button('Stop vTPM').click();
      await confirm('Stop this vTPM?');
      await expect(runState).toHaveText('Stopped');
      await checkState('Stopped');
    } finally {
      await sdk.vtpm.stopBundle(bundleId).catch(() => undefined);
      await sdk.vtpm.deleteBundle(bundleId);
    }
  });
});
