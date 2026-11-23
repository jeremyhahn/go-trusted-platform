import type { Page, Request, Response } from '@playwright/test';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

/**
 * Gateway VIPs, LB/NAT64 status and perf counters (#2052, ruling 972).
 *
 * These specs run on the real-server harness against its own platformd (no
 * api-mock), with an admin session the server issues through its WebAuthn
 * flow; without that session they fail, never skip. Each read the page makes
 * shows what the server answered, or the refusal it wrote as its JSON error
 * envelope. Each control follows GET /api/v1/capabilities. Reads are counted
 * with the page's SDK retry policy: one request on a 2xx or a non-retryable
 * refusal, 1 + READ_RETRIES on a retryable status, and a refusal assertion
 * waits out the retry backoff, since the card shows a retried refusal only
 * after the last retry. The perf test clicks the datapath and conntrack
 * reads. Writes are not retried and are each sent once. The VIP write
 * test sends AddVIP once from the form on a TEST-NET VIP (192.0.2.200, a port
 * no other run picks); the row controls (Details = GetVIP, Save =
 * SetVIPBackends, Remove + confirm = RemoveVIP) run only when the server
 * accepted the add, and the test removes that VIP again through the SDK in
 * `finally`. A node without a gateway refuses the add with its 503 envelope,
 * and the spec then checks the card shows that refusal and no row.
 */

const GATEWAY = '/api/v1/gateway';
const VIPS_PATH = `${GATEWAY}/lb/vips`;
const LB_STATUS_PATH = `${GATEWAY}/lb/status`;
const NAT64_STATUS_PATH = `${GATEWAY}/nat64/status`;
const DATAPATH_PATH = `${GATEWAY}/perf/datapath`;
const CAPABILITIES_PATH = '/api/v1/capabilities';

const ADD_OP = `POST ${VIPS_PATH}`;
const DATAPATH_OP = `GET ${DATAPATH_PATH}`;
const CONNTRACK_PATH = `${GATEWAY}/perf/conntrack`;
const CONNTRACK_OP = `GET ${CONNTRACK_PATH}`;

// These mirror the PlatformProvider retry in web/src/app/providers.tsx:63-69
// (src/lib/coverage-matrix-gateway-vip.test.ts keeps them in step): a read
// answered with a retryable status is sent again up to READ_RETRIES times.
const READ_RETRIES = 3;
const RETRYABLE = [408, 429, 500, 502, 503, 504];
// The retry backoff is 1 s + 2 s + 4 s; wait for it with margin.
const RETRY_WAIT_MS = 20_000;

/** expectedReads is how many requests the page's SDK sends for one read answered `status`. */
function expectedReads(status: number): number {
  return RETRYABLE.includes(status) ? 1 + READ_RETRIES : 1;
}

interface Capability {
  op: string;
  enabled: boolean;
  reason?: string;
}

interface VIPEntry {
  vip?: { protocol?: string; address?: string; port?: number };
}

/** isGet matches one GET of exactly `path` (query string allowed). */
function isGet(r: Request, path: string): boolean {
  return r.method() === 'GET' && new URL(r.url()).pathname === path;
}

/** answerOf waits for the page's own GET of `path`. */
function answerOf(page: Page, path: string): Promise<Response> {
  return page.waitForResponse((r) => isGet(r.request(), path));
}

/**
 * refusal checks a non-2xx answer is the server's JSON error envelope and
 * returns its text. A node without a gateway answers 503, a missing backend
 * 404, 409 or 500 from the backend; a missing route, a wrong method or a
 * non-JSON answer fails. The session is server-issued, so 401 or 403 fails.
 */
async function refusal(res: Response): Promise<string> {
  expect([401, 403]).not.toContain(res.status());
  const body: unknown = await res.json().catch(() => null);
  expect(body, 'refusal is the server JSON envelope, not a missing route').not.toBeNull();
  expect(typeof body).toBe('object');
  const envelope = body as { error?: unknown; message?: unknown };
  const message =
    typeof envelope.error === 'string' && envelope.error !== '' ? envelope.error : envelope.message;
  expect(typeof message, 'refusal carries the server error text').toBe('string');
  expect(message).not.toBe('');
  expect(res.status()).not.toBe(405);
  expect([404, 409, 500, 503]).toContain(res.status());
  return message as string;
}

/** capabilitiesOf reads the capability answer the page itself received. */
async function capabilitiesOf(res: Response): Promise<Map<string, Capability>> {
  expect(res.status()).toBe(200);
  const payload = unwrapPayload<{ capabilities?: Capability[] }>(await res.json());
  return new Map((payload.capabilities ?? []).map((c) => [c.op, c]));
}

/** expectGated checks a control carries `op` and the server's answer for it. */
async function expectGated(page: Page, testId: string, op: string, caps: Map<string, Capability>) {
  const control = page.getByTestId(testId);
  await expect(control).toHaveAttribute('data-capability-op', op);
  const cap = caps.get(op);
  await expect(control).toHaveAttribute('data-capability-enabled', cap?.enabled ? 'true' : 'false');
  if (!cap?.enabled) {
    await expect(control).toBeDisabled();
    if (cap?.reason) {
      await expect(control).toHaveAttribute('title', cap.reason);
    }
  }
}

test.describe('Gateway VIPs, LB/NAT64 status and perf counters (real server)', () => {
  test('the VIP card shows what GET /api/v1/gateway/lb/vips answered', async ({ adminPage }) => {
    const [res] = await Promise.all([answerOf(adminPage, VIPS_PATH), adminPage.goto('/networking/gateway')]);
    expect([401, 403]).not.toContain(res.status());

    const card = adminPage.getByTestId('vips-card');
    await expect(card).toBeVisible();
    await expect(adminPage.getByTestId('vips-admin-only')).toHaveCount(0);
    const error = adminPage.getByTestId('vips-error');
    if (res.ok()) {
      expect(res.status()).toBe(200);
      const vips = unwrapPayload<{ vips?: VIPEntry[] }>(await res.json()).vips ?? [];
      if (vips.length === 0) {
        await expect(adminPage.getByTestId('vips-empty')).toBeVisible();
      }
      for (const v of vips) {
        const key = `${v.vip?.protocol ?? ''}-${v.vip?.address ?? ''}-${v.vip?.port ?? 0}`;
        await expect(card.getByTestId(`vip-${key}`)).toHaveCount(1);
      }
      await expect(error).toHaveCount(0);
    } else {
      const message = await refusal(res);
      await expect(error).toBeVisible({ timeout: RETRY_WAIT_MS });
      await expect(error).toContainText(message, { timeout: RETRY_WAIT_MS });
    }
  });

  test('the LB and NAT64 cards show what their status reads answered', async ({ adminPage }) => {
    const [lb, nat64] = await Promise.all([
      answerOf(adminPage, LB_STATUS_PATH),
      answerOf(adminPage, NAT64_STATUS_PATH),
      adminPage.goto('/networking/gateway'),
    ]);

    const card = adminPage.getByTestId('lb-nat64-status-card');
    await expect(card).toBeVisible();
    for (const [res, name] of [
      [lb, 'lb-status'],
      [nat64, 'nat64-status'],
    ] as const) {
      expect([401, 403]).not.toContain(res.status());
      const shown = card.getByTestId(name);
      const error = card.getByTestId(`${name}-error`);
      if (res.ok()) {
        expect(res.status()).toBe(200);
        await expect(shown).toBeVisible();
        await expect(error).toHaveCount(0);
      } else {
        const message = await refusal(res);
        await expect(error).toBeVisible({ timeout: RETRY_WAIT_MS });
        await expect(error).toContainText(message, { timeout: RETRY_WAIT_MS });
      }
    }
  });

  test('the perf counter reads follow the server capability', async ({ adminPage }) => {
    const [capsRes] = await Promise.all([
      answerOf(adminPage, CAPABILITIES_PATH),
      adminPage.goto('/networking/gateway'),
    ]);
    const caps = await capabilitiesOf(capsRes);

    await expect(adminPage.getByTestId('perf-counters-card')).toBeVisible();
    await expect(adminPage.getByTestId('perf-counters-admin-only')).toHaveCount(0);
    await expectGated(adminPage, 'perf-datapath-load', DATAPATH_OP, caps);
    await expectGated(adminPage, 'perf-conntrack-load', CONNTRACK_OP, caps);

    if (caps.get(DATAPATH_OP)?.enabled) {
      const reads: Request[] = [];
      adminPage.on('request', (r) => {
        if (isGet(r, DATAPATH_PATH)) reads.push(r);
      });
      const [res] = await Promise.all([
        answerOf(adminPage, DATAPATH_PATH),
        adminPage.getByTestId('perf-datapath-load').click(),
      ]);
      expect([401, 403]).not.toContain(res.status());
      // A retryable refusal is sent 1 + READ_RETRIES times before the card shows it.
      await expect.poll(() => reads.length, { timeout: RETRY_WAIT_MS }).toBe(expectedReads(res.status()));
      const result = adminPage.getByTestId('perf-datapath-result');
      const error = adminPage.getByTestId('perf-counters-error');
      if (res.ok()) {
        expect(res.status()).toBe(200);
        await expect(result).toBeVisible();
        await expect(error).toHaveCount(0);
      } else {
        const message = await refusal(res);
        await expect(error).toBeVisible({ timeout: RETRY_WAIT_MS });
        await expect(error).toContainText(message, { timeout: RETRY_WAIT_MS });
        await expect(result).toHaveCount(0);
      }
    }

    if (caps.get(CONNTRACK_OP)?.enabled) {
      const reads: Request[] = [];
      adminPage.on('request', (r) => {
        if (isGet(r, CONNTRACK_PATH)) reads.push(r);
      });
      // The zone field stays empty: the read asks for every zone.
      const [res] = await Promise.all([
        answerOf(adminPage, CONNTRACK_PATH),
        adminPage.getByTestId('perf-conntrack-load').click(),
      ]);
      expect([401, 403]).not.toContain(res.status());
      // A retryable refusal is sent 1 + READ_RETRIES times before the card shows it.
      await expect.poll(() => reads.length, { timeout: RETRY_WAIT_MS }).toBe(expectedReads(res.status()));
      const result = adminPage.getByTestId('perf-conntrack-result');
      const error = adminPage.getByTestId('perf-counters-error');
      if (res.ok()) {
        expect(res.status()).toBe(200);
        await expect(result).toBeVisible();
        await expect(error).toHaveCount(0);
      } else {
        const message = await refusal(res);
        await expect(error).toBeVisible({ timeout: RETRY_WAIT_MS });
        await expect(error).toContainText(message, { timeout: RETRY_WAIT_MS });
        await expect(result).toHaveCount(0);
      }
    }
  });

  test('AddVIP sends the form once and the VIP row drives GetVIP, SetVIPBackends and RemoveVIP', async ({
    adminPage,
    sdk,
  }) => {
    const requests: Request[] = [];
    adminPage.on('request', (r) => requests.push(r));
    const lbWrites = () =>
      requests.filter(
        (r) => ['POST', 'PUT', 'DELETE'].includes(r.method()) && new URL(r.url()).pathname.startsWith(`${GATEWAY}/lb/`),
      );

    const [capsRes] = await Promise.all([
      answerOf(adminPage, CAPABILITIES_PATH),
      adminPage.goto('/networking/gateway'),
    ]);
    const caps = await capabilitiesOf(capsRes);
    await expect(adminPage.getByTestId('vips-card')).toBeVisible();
    await expectGated(adminPage, 'vip-add', ADD_OP, caps);

    if (!caps.get(ADD_OP)?.enabled) {
      await adminPage.waitForLoadState('networkidle');
      expect(lbWrites().map((r) => `${r.method()} ${r.url()}`)).toEqual([]);
      return;
    }

    // A TEST-NET VIP on a port no other run is likely to pick.
    const address = '192.0.2.200';
    const port = 40000 + (Date.now() % 20000);
    const key = `tcp-${address}-${port}`;
    const vipPath = `${VIPS_PATH}/tcp/${address}/${port}`;
    const row = adminPage.getByTestId(`vip-${key}`);
    const error = adminPage.getByTestId('vips-error');

    await adminPage.getByTestId('vip-protocol').selectOption('tcp');
    await adminPage.getByTestId('vip-address').fill(address);
    await adminPage.getByTestId('vip-port').fill(String(port));
    await adminPage.getByTestId('vip-backends').fill('192.0.2.201:8080');
    const [addRes] = await Promise.all([
      adminPage.waitForResponse(
        (r) => r.request().method() === 'POST' && new URL(r.url()).pathname === VIPS_PATH,
      ),
      adminPage.getByTestId('vip-add').click(),
    ]);
    expect([401, 403]).not.toContain(addRes.status());
    const posts = requests.filter((r) => r.method() === 'POST' && new URL(r.url()).pathname === VIPS_PATH);
    expect(posts).toHaveLength(1);
    const sent = posts[0].postDataJSON() as { vip?: { address?: string; port?: number } };
    expect(sent.vip?.address).toBe(address);
    expect(sent.vip?.port).toBe(port);

    if (!addRes.ok()) {
      const message = await refusal(addRes);
      await expect(error).toBeVisible();
      await expect(error).toContainText(message);
      await expect(row).toHaveCount(0);
      return;
    }

    try {
      await expect(row).toBeVisible();

      // Details reads the VIP through GetVIP.
      const [getRes] = await Promise.all([
        answerOf(adminPage, vipPath),
        adminPage.getByTestId(`vip-details-${key}`).click(),
      ]);
      expect([401, 403]).not.toContain(getRes.status());
      if (getRes.ok()) {
        await expect(adminPage.getByTestId(`vip-detail-${key}`)).toBeVisible();
      } else {
        const message = await refusal(getRes);
        await expect(adminPage.getByTestId(`vip-detail-error-${key}`)).toContainText(message, {
          timeout: RETRY_WAIT_MS,
        });
      }

      // Save replaces the backends through SetVIPBackends.
      await adminPage.getByTestId(`vip-edit-${key}`).click();
      await adminPage.getByTestId(`vip-edit-backends-${key}`).fill('192.0.2.202:8080');
      const [putRes] = await Promise.all([
        adminPage.waitForResponse(
          (r) => r.request().method() === 'PUT' && new URL(r.url()).pathname === `${vipPath}/backends`,
        ),
        adminPage.getByTestId(`vip-save-${key}`).click(),
      ]);
      expect([401, 403]).not.toContain(putRes.status());
      const puts = requests.filter((r) => r.method() === 'PUT' && new URL(r.url()).pathname === `${vipPath}/backends`);
      expect(puts).toHaveLength(1);
      expect(puts[0].postData() ?? '').toContain('192.0.2.202');
      if (!putRes.ok()) {
        await expect(error).toContainText(await refusal(putRes));
      }

      // Remove asks first; only the confirm sends RemoveVIP.
      const deletes = () => requests.filter((r) => r.method() === 'DELETE' && new URL(r.url()).pathname === vipPath);
      await adminPage.getByTestId(`vip-remove-${key}`).click();
      expect(deletes()).toHaveLength(0);
      const [delRes] = await Promise.all([
        adminPage.waitForResponse((r) => r.request().method() === 'DELETE' && new URL(r.url()).pathname === vipPath),
        adminPage.getByTestId('vip-remove-confirm').click(),
      ]);
      expect([401, 403]).not.toContain(delRes.status());
      expect(deletes()).toHaveLength(1);
      if (delRes.ok()) {
        await expect(row).toHaveCount(0);
      } else {
        await expect(error).toContainText(await refusal(delRes));
      }
    } finally {
      const listed = await sdk.gateway.listVIPs();
      const still = (listed.data?.vips ?? []).some(
        (v) => v.vip?.protocol === 'tcp' && v.vip?.address === address && v.vip?.port === port,
      );
      if (still) {
        await sdk.gateway.removeVIP('tcp', address, port);
      }
    }
  });
});
