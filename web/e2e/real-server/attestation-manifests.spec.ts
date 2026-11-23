import type { Page, Request } from '@playwright/test';
import type { HostManifest, PlatformClient } from 'trusted-platform-sdk';
import { expect, test } from './fixtures';

/*
 * Delete manifest on /attestation/manifests against the real server (#2038,
 * UI epic #1665). The spec seeds a manifest through the SDK, then deletes it
 * through the row's Delete manifest control and its confirm dialog, and reads
 * the list again: the row is gone. When the server does not offer
 * DELETE /api/v1/attestation/manifests/{id}, the control is disabled with the
 * server's reason as its title and no DELETE is sent. No page.route mocks.
 */

const OP = 'DELETE /api/v1/attestation/manifests/{id}';
const MANIFESTS_PATH = '/api/v1/attestation/manifests';
const NOT_OFFERED = 'not offered by this server';

interface DeleteCapability {
  enabled: boolean;
  reason: string;
}

/** The server's answer for OP from its capabilities list. */
async function deleteCapability(sdk: PlatformClient): Promise<DeleteCapability> {
  const res = await sdk.capabilities.list();
  if (!res.success || !res.data) {
    throw new Error(`capabilities list failed: ${JSON.stringify(res.error)}`);
  }
  const entry = res.data.capabilities.find((c) => c.op === OP);
  if (!entry) return { enabled: false, reason: NOT_OFFERED };
  return { enabled: entry.enabled, reason: entry.reason ?? '' };
}

/** Seeds one manifest for hostId; the built manifest, or the server's refusal. */
async function seedManifest(
  sdk: PlatformClient,
  hostId: string,
): Promise<{ manifest?: HostManifest; refusal?: string }> {
  const res = await sdk.attestation.buildManifest({ config: { hostId } });
  if (!res.success || !res.data?.manifest) {
    return { refusal: JSON.stringify(res.error ?? res.data) };
  }
  return { manifest: res.data.manifest };
}

function isManifestDelete(r: Request): boolean {
  return r.method() === 'DELETE' && new URL(r.url()).pathname.startsWith(`${MANIFESTS_PATH}/`);
}

/** Opens the manifests list filtered to the seeded host's row name. */
async function openFiltered(page: Page, rowName: string) {
  await page.goto('/attestation/manifests');
  await page.getByPlaceholder('Search manifests...').fill(rowName);
}

test.describe('Manifests delete (real server)', () => {
  test('redirects to login when not authenticated', async ({ page }) => {
    await page.goto('/attestation/manifests');
    await expect(page).toHaveURL(/\/auth\/webauthn/);
  });

  test('deletes a seeded manifest through the dialog, or withholds the control', async ({ adminPage, sdk }) => {
    const cap = await deleteCapability(sdk);
    const hostId = `e2e-delete-${Date.now()}`;
    const rowName = `Manifest ${hostId}`;
    const seeded = await seedManifest(sdk, hostId);

    const sent: string[] = [];
    adminPage.on('request', (req) => {
      if (isManifestDelete(req)) sent.push(req.url());
    });

    if (!seeded.manifest) {
      // The server refused the build: record its answer, and the control on
      // the list (if any rows exist) still follows the capability.
      test.info().annotations.push({ type: 'build refused', description: seeded.refusal ?? '' });
      await adminPage.goto('/attestation/manifests');
      const buttons = adminPage.getByRole('button', { name: 'Delete manifest' });
      if ((await buttons.count()) > 0 && !cap.enabled) {
        await expect(buttons.first()).toBeDisabled();
        if (cap.reason) await expect(buttons.first()).toHaveAttribute('title', cap.reason);
      }
      expect(sent).toEqual([]);
      return;
    }

    await openFiltered(adminPage, rowName);
    const row = adminPage.getByRole('row').filter({ hasText: rowName });
    await expect(row).toHaveCount(1);
    const button = row.getByRole('button', { name: 'Delete manifest' });

    if (!cap.enabled) {
      await expect(button).toBeDisabled();
      await expect(button).toHaveAttribute('data-capability-enabled', 'false');
      if (cap.reason) await expect(button).toHaveAttribute('title', cap.reason);
      expect(sent).toEqual([]);
      return;
    }

    await expect(button).toHaveAttribute('data-capability-enabled', 'true');
    await button.click();
    const dialog = adminPage.getByRole('dialog');
    await expect(dialog).toContainText('Delete manifest?');
    await expect(dialog).toContainText(rowName);
    expect(sent).toEqual([]);

    const deleted = adminPage.waitForResponse((r) => isManifestDelete(r.request()));
    await dialog.getByRole('button', { name: 'Delete', exact: true }).click();
    const r = await deleted;
    expect(r.status()).toBeGreaterThanOrEqual(200);
    expect(r.status()).toBeLessThan(300);
    expect(new URL(r.url()).pathname).toBe(`${MANIFESTS_PATH}/${encodeURIComponent(seeded.manifest.id)}`);

    await adminPage.reload();
    await adminPage.getByPlaceholder('Search manifests...').fill(rowName);
    await expect(adminPage.getByRole('row').filter({ hasText: rowName })).toHaveCount(0);
  });
});
