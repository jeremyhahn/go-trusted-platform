import { generateKeyPairSync } from 'node:crypto';
import type { Locator, Page, Response } from '@playwright/test';
import type { PlatformClient } from 'trusted-platform-sdk';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

/**
 * Device attestation against the real platformd (#2048, epic #1665).
 *
 * No route mock: a device is seeded through the SDK with an EC P-256
 * attest_pub, so the detail page treats it as TPM-backed and mounts the
 * attest and attestation-certificate cards. No TPM stands behind the key, so
 * the attest verdict and the certificate record are whatever the server says
 * about junk evidence and an uncertified key; each assertion compares the
 * page with the server's own answer. An op the server lists disabled is
 * checked as a disabled control carrying the server's reason, and no POST.
 */

const CHALLENGE_OP = 'POST /api/v1/devices/{id}/attest/challenge';
const ATTEST_OP = 'POST /api/v1/devices/{id}/attest';
const RECORD_OP = 'POST /api/v1/devices/{id:[0-9]+}/attest-cert/record';

type Sdk = PlatformClient;

interface Seeded {
  id: string;
  serial: string;
}

/** An EC P-256 public key PEM; nothing holds a TPM behind it. */
function attestPub(): string {
  const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return publicKey.export({ type: 'spki', format: 'pem' }).toString();
}

async function seedTpmDevice(sdk: Sdk): Promise<Seeded> {
  const serial = `e2e-att-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
  const res = await sdk.device.createDevice({ device: { serial, attest_pub: attestPub() } } as never);
  expect(res.success, JSON.stringify(res.error)).toBeTruthy();
  const { id } = res.data as unknown as { id: number | string };
  return { id: String(id), serial };
}

/** The server's reason for each op it lists disabled; an op absent here is enabled. */
async function disabledReasons(sdk: Sdk): Promise<Map<string, string>> {
  const res = await sdk.capabilities.list();
  expect(res.success, JSON.stringify(res.error)).toBeTruthy();
  const body = res.data as unknown as {
    capabilities?: { op: string; enabled: boolean; reason?: string }[];
  };
  const off = new Map<string, string>();
  for (const c of body.capabilities ?? []) {
    if (!c.enabled) off.set(c.op, c.reason ?? '');
  }
  return off;
}

/** Waits for the page's own POST whose path matches. */
function postResponse(page: Page, path: RegExp): Promise<Response> {
  return page.waitForResponse(
    (r) => r.request().method() === 'POST' && path.test(new URL(r.url()).pathname),
  );
}

/** Counts the page's POSTs whose path matches, from now on. */
function countPosts(page: Page, path: RegExp): () => number {
  let n = 0;
  page.on('request', (r) => {
    if (r.method() === 'POST' && path.test(new URL(r.url()).pathname)) n += 1;
  });
  return () => n;
}

/** The error text of a refused response, as the SDK hands it to the card. */
async function errorMessage(r: Response): Promise<string> {
  const raw = (await r.json().catch(() => ({}))) as {
    error?: { message?: string } | string;
    message?: string;
  };
  if (typeof raw.error === 'string') return raw.error;
  return raw.error?.message ?? raw.message ?? '';
}

async function expectGatedOff(control: Locator, reason: string): Promise<void> {
  await expect(control).toBeDisabled();
  await expect(control).toHaveAttribute('title', reason);
}

test.describe('Device attestation against the real server', () => {
  test('the device page redirects to login without a session', async ({ page }) => {
    await page.goto('/devices/1');
    await expect(page).toHaveURL(/\/auth\/webauthn/);
  });

  test('issue challenge shows the nonce, and verify shows the server verdict', async ({ adminPage, sdk }) => {
    const dev = await seedTpmDevice(sdk);
    const off = await disabledReasons(sdk);
    const challengePath = new RegExp(`/api/v1/devices/${dev.id}/attest/challenge$`);
    const attestPath = new RegExp(`/api/v1/devices/${dev.id}/attest$`);
    const challengePosts = countPosts(adminPage, challengePath);
    const attestPosts = countPosts(adminPage, attestPath);

    await adminPage.goto(`/devices/${dev.id}`);
    const card = adminPage.getByTestId('device-attest-card');
    await expect(card).toBeVisible();
    const issue = card.getByRole('button', { name: 'Issue challenge' });
    const verify = card.getByRole('button', { name: 'Verify evidence' });

    if (off.has(CHALLENGE_OP)) {
      await expectGatedOff(issue, off.get(CHALLENGE_OP)!);
      expect(challengePosts()).toBe(0);
      return;
    }

    const challengeRes = postResponse(adminPage, challengePath);
    await issue.click();
    const cr = await challengeRes;
    if (!cr.ok()) {
      await expect(card.getByTestId('device-attest-refusal')).toContainText(await errorMessage(cr));
      return;
    }
    const challenge = unwrapPayload<{ nonce: string; challenge_id: string }>(await cr.json());
    await expect(card.getByTestId('device-attest-nonce')).toHaveText(challenge.nonce);

    // Junk evidence: the seeded key has no TPM behind it.
    await card.getByLabel('Evidence (base64)').fill(Buffer.from('not a quote').toString('base64'));

    if (off.has(ATTEST_OP)) {
      await expectGatedOff(verify, off.get(ATTEST_OP)!);
      expect(attestPosts()).toBe(0);
      return;
    }

    const attestRes = postResponse(adminPage, attestPath);
    await verify.click();
    const ar = await attestRes;
    if (ar.ok()) {
      const verdict = unwrapPayload<{ verified: boolean }>(await ar.json());
      await expect(card.getByTestId('device-attest-verdict')).toHaveText(
        verdict.verified ? 'Verified' : 'Not verified',
      );
    } else {
      await expect(card.getByTestId('device-attest-refusal')).toContainText(await errorMessage(ar));
    }
    // The challenge is single-use: the card forgets it either way.
    await expect(card.getByTestId('device-attest-nonce')).toHaveCount(0);
  });

  test('record certificate shows the server refusal for an uncertified key', async ({ adminPage, sdk }) => {
    const dev = await seedTpmDevice(sdk);
    const off = await disabledReasons(sdk);
    const recordPath = new RegExp(`/api/v1/devices/${dev.id}/attest-cert/record$`);
    const recordPosts = countPosts(adminPage, recordPath);

    await adminPage.goto(`/devices/${dev.id}`);
    const card = adminPage.getByTestId('attest-cert-card');
    await expect(card).toBeVisible();
    await expect(card.getByTestId('attest-cert-absent')).toBeVisible();
    const open = card.getByRole('button', { name: 'Record certificate' });

    if (off.has(RECORD_OP)) {
      await expectGatedOff(open, off.get(RECORD_OP)!);
      expect(recordPosts()).toBe(0);
      return;
    }

    await open.click();
    const dialog = adminPage.getByRole('dialog');
    await expect(dialog).toBeVisible();
    const recordRes = postResponse(adminPage, recordPath);
    await dialog.getByRole('button', { name: 'Record', exact: true }).click();
    const rr = await recordRes;
    if (rr.ok()) {
      // The server recorded a certificate after all: the dialog closes and
      // the card shows it in place of the absent note.
      await expect(dialog).toHaveCount(0);
      await expect(card.getByTestId('attest-cert-absent')).toHaveCount(0);
      return;
    }
    await expect(adminPage.getByTestId('attest-cert-refusal')).toContainText(await errorMessage(rr));
  });
});
