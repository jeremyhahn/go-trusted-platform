import type { Locator, Page, Request, Response } from '@playwright/test';
import type {
  CollectContainerAttestationResponse,
  CollectHostAttestationResponse,
  CollectVMAttestationResponse,
  PlatformClient,
} from 'trusted-platform-sdk';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

/*
 * The collect cards on /attestation/collect against the real server (#2038,
 * UI epic #1665). For each of CollectHostAttestation, CollectVMAttestation
 * and CollectContainerAttestation the spec compares what the card shows with
 * what the server answered, or, when the server does not offer the route,
 * checks the button is withheld with the server's reason and sends nothing.
 * No page.route mocks.
 */

const HOST_OP = 'POST /api/v1/attestation/host';
const VM_OP = 'POST /api/v1/attestation/vm/{id}';
const CONTAINER_OP = 'POST /api/v1/attestation/container/{id}';
const VM_ID = 'e2e-no-such-vm';
const CONTAINER_ID = 'e2e-no-such-container';
const HOST_PATH = '/api/v1/attestation/host';
const VM_PATH = `/api/v1/attestation/vm/${VM_ID}`;
const CONTAINER_PATH = `/api/v1/attestation/container/${CONTAINER_ID}`;
const NOT_OFFERED = 'not offered by this server';
const NONCE = Buffer.from('real-server collect card nonce').toString('base64');

interface Capability {
  enabled: boolean;
  reason: string;
}

/** The server's answers for the three collect ops from its capabilities list. */
async function collectCapabilities(sdk: PlatformClient): Promise<Record<string, Capability>> {
  const res = await sdk.capabilities.list();
  if (!res.success || !res.data) {
    throw new Error(`capabilities list failed: ${JSON.stringify(res.error)}`);
  }
  const out: Record<string, Capability> = {};
  for (const op of [HOST_OP, VM_OP, CONTAINER_OP]) {
    const entry = res.data.capabilities.find((c) => c.op === op);
    out[op] = entry ? { enabled: entry.enabled, reason: entry.reason ?? '' } : { enabled: false, reason: NOT_OFFERED };
  }
  return out;
}

function isPost(r: Request, path: string): boolean {
  return r.method() === 'POST' && new URL(r.url()).pathname === path;
}

function postResponse(page: Page, path: string): Promise<Response> {
  return page.waitForResponse((r) => isPost(r.request(), path));
}

/** The error text of a refused answer, from the control plane's error envelope. */
async function refusalText(r: Response): Promise<string> {
  const body = (await r.json().catch(() => ({}))) as { error?: unknown; message?: unknown };
  if (typeof body.error === 'string') return body.error;
  if (body.error && typeof body.error === 'object' && 'message' in body.error) {
    return String((body.error as { message: unknown }).message);
  }
  return typeof body.message === 'string' ? body.message : '';
}

async function openCollect(page: Page): Promise<void> {
  await page.goto('/attestation/collect');
  await expect(page.getByTestId('attestation-collect-host')).toBeVisible();
}

/** Withheld: the button is disabled with the server's reason and a click sends nothing. */
async function expectWithheld(page: Page, name: string, cap: Capability, path: string, fill: () => Promise<void>): Promise<void> {
  const seen: string[] = [];
  page.on('request', (req) => {
    if (isPost(req, path)) seen.push(req.url());
  });
  await openCollect(page);
  await fill();
  const button = page.getByRole('button', { name });
  await expect(button).toHaveAttribute('data-capability-enabled', 'false');
  await expect(button).toBeDisabled();
  if (cap.reason && cap.reason !== NOT_OFFERED) await expect(button).toHaveAttribute('title', cap.reason);
  await button.click({ force: true });
  expect(seen).toEqual([]);
}

/** Click the card's button and return the server's answer to its POST. */
async function send(page: Page, name: string, path: string): Promise<Response> {
  const button = page.getByRole('button', { name });
  await expect(button).toHaveAttribute('data-capability-enabled', 'true');
  await expect(button).toBeEnabled();
  const res = postResponse(page, path);
  await button.click();
  return res;
}

/** A refused answer: the card shows the server's message and no result block. */
async function expectRefused(card: Locator, r: Response, resultId: string): Promise<void> {
  const text = await refusalText(r);
  const alert = card.getByRole('alert');
  await expect(alert).toBeVisible();
  if (text) await expect(alert).toContainText(text);
  await expect(card.getByTestId(resultId)).toHaveCount(0);
}

test.describe('Collect attestation cards (real server)', () => {
  test('redirects to login when not authenticated', async ({ page }) => {
    await page.goto('/attestation/collect');
    await expect(page).toHaveURL(/\/auth\/webauthn/);
  });

  test('Collect host attestation shows what the server answers, or is withheld', async ({ adminPage, sdk }) => {
    const caps = await collectCapabilities(sdk);
    const card = adminPage.getByTestId('attestation-collect-host');
    const fill = async () => {
      await card.getByLabel('Nonce (base64)').fill(NONCE);
      await card.getByLabel('PCR indices').fill('0,7');
    };
    if (!caps[HOST_OP].enabled) {
      await expectWithheld(adminPage, 'Collect host attestation', caps[HOST_OP], HOST_PATH, fill);
      return;
    }
    await openCollect(adminPage);
    await fill();
    const r = await send(adminPage, 'Collect host attestation', HOST_PATH);
    if (!r.ok()) {
      await expectRefused(card, r, 'attestation-collect-host-result');
      return;
    }
    const answer = unwrapPayload<CollectHostAttestationResponse>(await r.json());
    if (answer.status?.success === false || !answer.attestation) {
      await expect(card.getByRole('alert')).toBeVisible();
      await expect(card.getByTestId('attestation-collect-host-result')).toHaveCount(0);
      return;
    }
    const result = card.getByTestId('attestation-collect-host-result');
    await expect(result).toBeVisible();
    if (answer.attestation.pcrDigest) await expect(result).toContainText(answer.attestation.pcrDigest);
    if (answer.attestation.signatureAlgorithm) await expect(result).toContainText(answer.attestation.signatureAlgorithm);
    await expect(result.getByTestId('attestation-collect-host-pcr')).toHaveCount(answer.attestation.pcrs?.length ?? 0);
  });

  test('Collect VM attestation shows what the server answers, or is withheld', async ({ adminPage, sdk }) => {
    const caps = await collectCapabilities(sdk);
    const card = adminPage.getByTestId('attestation-collect-vm');
    const fill = async () => {
      await card.getByLabel('VM ID').fill(VM_ID);
      await card.getByLabel('Nonce (base64)').fill(NONCE);
    };
    if (!caps[VM_OP].enabled) {
      await expectWithheld(adminPage, 'Collect VM attestation', caps[VM_OP], VM_PATH, fill);
      return;
    }
    await openCollect(adminPage);
    await fill();
    const r = await send(adminPage, 'Collect VM attestation', VM_PATH);
    if (!r.ok()) {
      await expectRefused(card, r, 'attestation-collect-vm-result');
      return;
    }
    const answer = unwrapPayload<CollectVMAttestationResponse>(await r.json());
    const result = card.getByTestId('attestation-collect-vm-result');
    await expect(result).toBeVisible();
    await expect(result).toContainText(answer.vm_id);
    await expect(result).toContainText(answer.verified ? 'Verified' : 'Not verified');
  });

  test('Collect container attestation shows what the server answers, or is withheld', async ({ adminPage, sdk }) => {
    const caps = await collectCapabilities(sdk);
    const card = adminPage.getByTestId('attestation-collect-container');
    const fill = async () => {
      await card.getByLabel('Container ID').fill(CONTAINER_ID);
    };
    if (!caps[CONTAINER_OP].enabled) {
      await expectWithheld(adminPage, 'Collect container attestation', caps[CONTAINER_OP], CONTAINER_PATH, fill);
      return;
    }
    await openCollect(adminPage);
    await fill();
    const r = await send(adminPage, 'Collect container attestation', CONTAINER_PATH);
    if (!r.ok()) {
      await expectRefused(card, r, 'attestation-collect-container-result');
      return;
    }
    const answer = unwrapPayload<CollectContainerAttestationResponse>(await r.json());
    const result = card.getByTestId('attestation-collect-container-result');
    await expect(result).toBeVisible();
    await expect(result).toContainText(answer.container_id);
    await expect(result).toContainText(answer.verified ? 'Verified' : 'Not verified');
  });
});
