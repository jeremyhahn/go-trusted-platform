import type { Request } from '@playwright/test';
import type { HostManifest, PlatformClient } from 'trusted-platform-sdk';
import { expect, test } from './fixtures';

/*
 * Verify manifest on the manifest detail page against the real server
 * (#2038, UI epic #1665). The spec seeds a manifest through the SDK, opens
 * /attestation/<manifest id>, and verifies it through the header's Verify
 * manifest control and its dialog: the verify answer is 2xx and the dialog
 * shows the verifier's status. When the server does not offer
 * POST /api/v1/attestation/manifests/verify, the control is disabled with the
 * server's reason as its title and nothing is sent. No page.route mocks.
 * The test is skipped, not passed, when BuildManifest is refused, because
 * production BuildManifest needs a daemon-managed TPM session the real-server
 * daemon config does not set up (ErrTPMSessionNotConfigured).
 */

const OP = 'POST /api/v1/attestation/manifests/verify';
const VERIFY_PATH = '/api/v1/attestation/manifests/verify';
const NOT_OFFERED = 'not offered by this server';

interface VerifyCapability {
  enabled: boolean;
  reason: string;
}

/** The server's answer for OP from its capabilities list. */
async function verifyCapability(sdk: PlatformClient): Promise<VerifyCapability> {
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

function isManifestVerify(r: Request): boolean {
  return r.method() === 'POST' && new URL(r.url()).pathname === VERIFY_PATH;
}

/** The verifier's status in a verify answer, enveloped or bare. */
function resultStatus(body: unknown): string | undefined {
  const b = body as { payload?: { result?: { status?: string } }; result?: { status?: string } };
  return b?.payload?.result?.status ?? b?.result?.status;
}

test.describe('Manifest verify (real server)', () => {
  test('redirects to login when not authenticated', async ({ page }) => {
    await page.goto('/attestation/verify');
    await expect(page).toHaveURL(/\/auth\/webauthn/);
  });

  test('verifies a seeded manifest through the dialog, or withholds the control', async ({ adminPage, sdk }) => {
    const cap = await verifyCapability(sdk);
    const hostId = `e2e-verify-${Date.now()}`;
    const seeded = await seedManifest(sdk, hostId);

    const sent: string[] = [];
    adminPage.on('request', (req) => {
      if (isManifestVerify(req)) sent.push(req.url());
    });

    if (!seeded.manifest) {
      // No manifest, nothing to verify: skip, never pass, so the report does
      // not count a verify that did not happen.
      test.skip(
        true,
        `BuildManifest refused, so no manifest can be seeded: the real-server daemon has no daemon-managed TPM session (ErrTPMSessionNotConfigured, pkg/attestation/service/service.go:73-74): ${seeded.refusal ?? ''}`,
      );
      throw new Error('unreachable: test.skip(true) ends the test');
    }

    await adminPage.goto(`/attestation/${encodeURIComponent(seeded.manifest.id)}`);
    const button = adminPage.getByRole('button', { name: 'Verify manifest' });
    await expect(button).toBeVisible();

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
    await expect(dialog).toContainText('Verify manifest');
    expect(sent).toEqual([]);

    const verified = adminPage.waitForResponse((r) => isManifestVerify(r.request()));
    await dialog.getByRole('button', { name: 'Verify', exact: true }).click();
    const r = await verified;
    expect(r.status()).toBeGreaterThanOrEqual(200);
    expect(r.status()).toBeLessThan(300);
    const status = resultStatus(await r.json());
    expect(status).toBeTruthy();
    await expect(dialog.getByTestId('manifest-verify-result')).toContainText(status as string);
  });
});
