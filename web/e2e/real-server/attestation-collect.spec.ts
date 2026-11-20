import type { Page, Request } from '@playwright/test';
import { test, expect } from './fixtures';

// #1732 (epic #1665, slice 1): attestation collect and manifest delete from
// the dashboard, against the real-server harness (#2035). Manifest
// verification is not offered until the verifier fails closed (#1732 review).

interface Call {
  method: string;
  path: string;
}

/** Records every attestation request the page sends; it answers none. */
function recordCalls(page: Page): Call[] {
  const calls: Call[] = [];
  page.on('request', (request: Request) => {
    const path = new URL(request.url()).pathname;
    if (!path.includes('/api/v1/attestation')) return;
    calls.push({ method: request.method(), path: path.replace(/^.*\/api\/v1\/attestation/, '') });
  });
  return calls;
}

async function openCollectPage(page: Page): Promise<Call[]> {
  const calls = recordCalls(page);
  await page.goto('/attestation/collect');
  await expect(page.getByRole('heading', { name: 'Attestation Collect' })).toBeVisible();
  return calls;
}

function isPath(method: string, path: string) {
  return (r: { request(): Request; url(): string }) =>
    r.request().method() === method && new URL(r.url()).pathname.endsWith(`/api/v1/attestation${path}`);
}

test.describe('Attestation collect and manifests (#1732), real server', () => {
  test('the page offers no manifest verification (#1732 review)', async ({ adminPage }) => {
    const calls = await openCollectPage(adminPage);
    await expect(adminPage.getByLabel('Manifest JSON')).toHaveCount(0);
    await expect(adminPage.getByRole('button', { name: 'Verify manifest' })).toHaveCount(0);

    await adminPage.getByLabel('Manifest ID').fill('e2e-absent-manifest');
    await adminPage.getByRole('button', { name: 'Delete manifest' }).click();
    await adminPage.getByRole('dialog').getByRole('button', { name: 'Confirm delete' }).click();
    await expect(adminPage.getByTestId('collect-result')).toContainText('Manifest deletion');

    expect(calls.filter((c) => c.path === '/manifests/verify')).toHaveLength(0);
  });

  test('DeleteManifest: DELETE /manifests/{id} after confirm, shown as the server answers', async ({ adminPage }) => {
    const calls = await openCollectPage(adminPage);
    const id = `e2e-m-${Date.now()}`;
    await adminPage.getByLabel('Manifest ID').fill(id);
    await adminPage.getByRole('button', { name: 'Delete manifest' }).click();

    // Cancel first: nothing is deleted.
    const dialog = adminPage.getByRole('dialog');
    await expect(dialog).toContainText('Delete manifest?');
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    await expect(dialog).toBeHidden();
    expect(calls.filter((c) => c.method === 'DELETE')).toHaveLength(0);

    await adminPage.getByRole('button', { name: 'Delete manifest' }).click();
    const answer = adminPage.waitForResponse(isPath('DELETE', `/manifests/${id}`));
    await adminPage.getByRole('dialog').getByRole('button', { name: 'Confirm delete' }).click();
    const res = await answer;
    await expect(adminPage.getByTestId('collect-result')).toContainText('Manifest deletion');
    // No manifest with this id was ever built, so the server must not
    // report a deletion that did not happen.
    expect(res.ok()).toBe(false);
    expect(calls.filter((c) => c.method === 'DELETE').map((c) => c.path)).toEqual([`/manifests/${id}`]);
  });

  test('CollectHostAttestation: POST /host with a nonce, and the page shows what the server answered', async ({ adminPage }) => {
    await openCollectPage(adminPage);
    const answer = adminPage.waitForResponse(isPath('POST', '/host'));
    await adminPage.getByRole('button', { name: 'Collect host attestation' }).click();
    const res = await answer;

    const nonce = (res.request().postDataJSON() as { nonce?: string } | null)?.nonce ?? '';
    expect(nonce.length).toBeGreaterThan(0);
    await expect(adminPage.getByTestId('collect-result')).toBeVisible();
    if (res.ok()) {
      const body = (await res.json()) as { payload?: { attestation?: { hostId?: string } }; attestation?: { hostId?: string } };
      const hostId = body.payload?.attestation?.hostId ?? body.attestation?.hostId ?? '';
      if (hostId) await expect(adminPage.getByTestId('collect-result')).toContainText(hostId);
    }
  });

  test('CollectVMAttestation and CollectContainerAttestation are gated as unavailable', async ({ adminPage }) => {
    const calls = await openCollectPage(adminPage);

    await expect(adminPage.getByTestId('workload-collect-unavailable')).toContainText('not available');
    await expect(adminPage.getByLabel('VM ID')).toBeDisabled();
    await expect(adminPage.getByLabel('Container ID')).toBeDisabled();
    await expect(adminPage.getByRole('button', { name: 'Collect VM attestation' })).toBeDisabled();
    await expect(adminPage.getByRole('button', { name: 'Collect container attestation' })).toBeDisabled();
    await expect(adminPage.getByTestId('collect-result')).toHaveCount(0);
    expect(calls.filter((c) => c.path.startsWith('/vm/') || c.path.startsWith('/container/'))).toHaveLength(0);
  });

  test('the sidebar lists the collect page', async ({ adminPage }) => {
    await openCollectPage(adminPage);
    await expect(adminPage.locator('a[href="/attestation/collect"]').first()).toBeAttached();
  });
});
