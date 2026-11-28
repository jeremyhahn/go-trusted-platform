import type { Locator, Page, Response } from '@playwright/test';
import type { PlatformClient } from 'trusted-platform-sdk';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

/**
 * TPM operations against the real platformd on the TPM simulator (#2069,
 * epic #1665, coverage-matrix slice 32): GetEventLog, ExtendPCR,
 * MakeCredential, ActivateCredential and GetRandom, with GetAK filling the
 * AK name the credential flow needs.
 *
 * No page.route mocks: every assertion compares the page with what the
 * server answered the page itself, or with a read through the SDK. Each
 * control first asserts its capability gate against the server's own
 * listing; a control the server does not offer must be disabled with the
 * reason, and a click on it must send nothing.
 *
 * The spec extends PCR 16 (a debug PCR) only, never the platform PCR 23.
 */

const PCR_INDEX = 16;

interface ServerCapability {
  enabled: boolean;
  reason?: string;
}

/** The server's own answer for op, or undefined when it does not list it. */
async function serverCapability(sdk: PlatformClient, op: string): Promise<ServerCapability | undefined> {
  const listing = await sdk.capabilities.list();
  expect(listing.success, `capabilities listing failed: ${JSON.stringify(listing.error)}`).toBeTruthy();
  return listing.data?.capabilities.find((c) => c.op === op);
}

/**
 * Asserts the gate of control against the server's listing and returns
 * whether the control is offered. An op the server does not list, or lists
 * disabled, must leave the control disabled with a reason.
 */
async function assertGate(sdk: PlatformClient, control: Locator, op: string): Promise<boolean> {
  const cap = await serverCapability(sdk, op);
  const enabled = cap?.enabled === true;
  await expect(control).toHaveAttribute('data-capability-enabled', enabled ? 'true' : 'false');
  if (!enabled) {
    await expect(control).toBeDisabled();
    if (cap?.reason) {
      await expect(control).toHaveAttribute('title', cap.reason);
    } else {
      await expect(control).toHaveAttribute('title', /.+/);
    }
  }
  return enabled;
}

/** Records every request the page sends under /api/v1/tpm/. */
function tpmRequests(page: Page): string[] {
  const sent: string[] = [];
  page.on('request', (r) => {
    const path = new URL(r.url()).pathname;
    if (path.startsWith('/api/v1/tpm/')) sent.push(`${r.method()} ${path}`);
  });
  return sent;
}

/** Waits for the page's own request of method to a path matching path. */
function apiResponse(page: Page, method: string, path: RegExp): Promise<Response> {
  return page.waitForResponse((r) => r.request().method() === method && path.test(new URL(r.url()).pathname));
}

/** A clicked control the server does not offer sends no request. */
async function assertWithheld(page: Page, control: Locator, sent: string[], route: string): Promise<void> {
  await control.click({ force: true });
  await page.waitForLoadState('networkidle');
  expect(sent).not.toContain(route);
}

/** The PCR value of index in the SHA256 bank, read through the SDK. */
async function pcrValue(sdk: PlatformClient, index: number): Promise<string | undefined> {
  const resp = await sdk.tpm.getPCRs({ indices: [index], bank: 'SHA256' });
  expect(resp.success, `getPCRs failed: ${JSON.stringify(resp.error)}`).toBeTruthy();
  return resp.data?.pcrValues.find((p) => p.index === index)?.value;
}

test.describe('TPM operations access', () => {
  test('redirects the credential page to login when not authenticated', async ({ page }) => {
    await page.goto('/tpm/credential');
    await expect(page).toHaveURL(/\/auth\/webauthn/);
  });
});

test.describe('TPM event log', () => {
  test("shows what the server's GET /tpm/eventlog answered", async ({ adminPage }) => {
    const answered = apiResponse(adminPage, 'GET', /^\/api\/v1\/tpm\/eventlog$/);
    await adminPage.goto('/tpm/eventlog');
    const resp = await answered;

    if (resp.ok()) {
      const log = unwrapPayload<{ eventCount?: number; entries?: unknown[] }>(await resp.json());
      const total = log.eventCount || (log.entries ?? []).length;
      const card = adminPage.locator('div').filter({ has: adminPage.getByText('Total Events', { exact: true }) });
      await expect(card.getByText(String(total), { exact: true }).first()).toBeVisible();
    } else {
      await expect(adminPage.getByText('Error', { exact: true }).first()).toBeVisible();
    }
  });
});

test.describe('TPM PCR extend', () => {
  test(`extends PCR ${PCR_INDEX} through the confirm`, async ({ adminPage, sdk }) => {
    const sent = tpmRequests(adminPage);
    await adminPage.goto('/tpm/pcrs');
    await adminPage.getByLabel('PCR index').fill(String(PCR_INDEX));
    await adminPage.getByLabel('Data').fill('real-server e2e measurement');

    const extend = adminPage.getByRole('button', { name: 'Extend PCR', exact: true });
    if (!(await assertGate(sdk, extend, 'POST /api/v1/tpm/pcrs/extend'))) {
      await assertWithheld(adminPage, extend, sent, 'POST /api/v1/tpm/pcrs/extend');
      return;
    }

    const before = await pcrValue(sdk, PCR_INDEX);
    await extend.click();
    await expect(adminPage.getByText(`Extend PCR ${PCR_INDEX}?`)).toBeVisible();
    const answered = apiResponse(adminPage, 'POST', /^\/api\/v1\/tpm\/pcrs\/extend$/);
    await adminPage.getByRole('button', { name: 'Confirm' }).click();
    const resp = await answered;

    expect(resp.ok(), `extend answered ${resp.status()}`).toBeTruthy();
    expect(resp.request().postDataJSON()).toMatchObject({ index: PCR_INDEX });
    const after = await pcrValue(sdk, PCR_INDEX);
    expect(after).toBeDefined();
    expect(after).not.toBe(before);
  });
});

test.describe('TPM credential and random', () => {
  test('makes and activates a credential to the platform AK', async ({ adminPage, sdk }) => {
    const sent = tpmRequests(adminPage);
    await adminPage.goto('/tpm/credential');

    const useAK = adminPage.getByRole('button', { name: 'Use platform AK' });
    if (!(await assertGate(sdk, useAK, 'GET /api/v1/tpm/ak'))) {
      await assertWithheld(adminPage, useAK, sent, 'GET /api/v1/tpm/ak');
      return;
    }

    const ak = await sdk.tpm.getAK();
    expect(ak.success, `getAK failed: ${JSON.stringify(ak.error)}`).toBeTruthy();
    const akName = ak.data?.name;
    expect(akName, 'GetAK carries the AK name').toBeTruthy();

    await useAK.click();
    await expect(adminPage.getByLabel('AK name (base64)')).toHaveValue(akName as string);
    await adminPage.getByLabel('Secret (optional)').fill('real-server e2e secret');

    const make = adminPage.getByRole('button', { name: 'Make Credential', exact: true });
    if (!(await assertGate(sdk, make, 'POST /api/v1/tpm/make-credential'))) {
      await assertWithheld(adminPage, make, sent, 'POST /api/v1/tpm/make-credential');
      return;
    }
    const madeResp = apiResponse(adminPage, 'POST', /^\/api\/v1\/tpm\/make-credential$/);
    await make.click();
    expect((await madeResp).ok(), 'make-credential answered 2xx').toBeTruthy();
    const wrapped = adminPage.getByTestId('wrapped-secret');
    await expect(wrapped).toBeVisible();
    const madeSecret = (await wrapped.textContent()) ?? '';
    expect(madeSecret).not.toBe('');

    const activate = adminPage.getByRole('button', { name: 'Activate Credential', exact: true });
    if (!(await assertGate(sdk, activate, 'POST /api/v1/tpm/activate-credential'))) {
      await assertWithheld(adminPage, activate, sent, 'POST /api/v1/tpm/activate-credential');
      return;
    }
    await activate.click();
    await expect(adminPage.getByText('Activate this credential?')).toBeVisible();
    const activated = apiResponse(adminPage, 'POST', /^\/api\/v1\/tpm\/activate-credential$/);
    await adminPage.getByRole('button', { name: 'Confirm' }).click();
    expect((await activated).ok(), 'activate-credential answered 2xx').toBeTruthy();

    await expect(adminPage.getByTestId('activated-secret')).toHaveText(madeSecret);
  });

  test('draws 16 random bytes', async ({ adminPage, sdk }) => {
    const sent = tpmRequests(adminPage);
    await adminPage.goto('/tpm/credential');
    await adminPage.getByLabel('Number of bytes').fill('16');

    const random = adminPage.getByRole('button', { name: 'Get Random', exact: true });
    if (!(await assertGate(sdk, random, 'POST /api/v1/tpm/random'))) {
      await assertWithheld(adminPage, random, sent, 'POST /api/v1/tpm/random');
      return;
    }

    const answered = apiResponse(adminPage, 'POST', /^\/api\/v1\/tpm\/random$/);
    await random.click();
    const resp = await answered;
    expect(resp.ok(), `random answered ${resp.status()}`).toBeTruthy();
    expect(resp.request().postDataJSON()).toMatchObject({ numBytes: 16 });

    // The page shows the bytes as hex: 16 bytes are 32 hex digits.
    await expect(adminPage.getByTestId('random-bytes')).toHaveText(/^[0-9a-f]{32}$/);
  });
});
