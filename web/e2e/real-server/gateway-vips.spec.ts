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
 * envelope. Each control follows GET /api/v1/capabilities. The daemon is
 * shared by every spec, so nothing here fills a form or sends a write: the
 * only click is the perf datapath read.
 */

const GATEWAY = '/api/v1/gateway';
const VIPS_PATH = `${GATEWAY}/lb/vips`;
const LB_STATUS_PATH = `${GATEWAY}/lb/status`;
const NAT64_STATUS_PATH = `${GATEWAY}/nat64/status`;
const DATAPATH_PATH = `${GATEWAY}/perf/datapath`;
const CAPABILITIES_PATH = '/api/v1/capabilities';

const ADD_OP = `POST ${VIPS_PATH}`;
const DATAPATH_OP = `GET ${DATAPATH_PATH}`;
const CONNTRACK_OP = `GET ${GATEWAY}/perf/conntrack`;

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
      await expect(error).toBeVisible();
      await expect(error).toContainText(message);
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
        await expect(error).toBeVisible();
        await expect(error).toContainText(message);
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
      const result = adminPage.getByTestId('perf-datapath-result');
      const error = adminPage.getByTestId('perf-counters-error');
      if (res.ok()) {
        expect(res.status()).toBe(200);
        await expect(result).toBeVisible();
        await expect(error).toHaveCount(0);
      } else {
        const message = await refusal(res);
        await expect(error).toBeVisible();
        await expect(error).toContainText(message);
        await expect(result).toHaveCount(0);
      }
      await adminPage.waitForLoadState('networkidle');
      expect(reads).toHaveLength(1);
    }
  });

  test('the VIP writes follow the server capability and send nothing', async ({ adminPage }) => {
    const requests: Request[] = [];
    adminPage.on('request', (r) => requests.push(r));

    const [capsRes] = await Promise.all([
      answerOf(adminPage, CAPABILITIES_PATH),
      adminPage.goto('/networking/gateway'),
    ]);
    const caps = await capabilitiesOf(capsRes);

    await expect(adminPage.getByTestId('vips-card')).toBeVisible();
    const add = adminPage.getByTestId('vip-add');
    await expect(add).toHaveAttribute('data-capability-op', ADD_OP);
    await expect(add).toHaveAttribute('data-capability-enabled', caps.get(ADD_OP)?.enabled ? 'true' : 'false');

    await adminPage.waitForLoadState('networkidle');
    const writes = requests.filter(
      (r) => ['POST', 'PUT', 'DELETE'].includes(r.method()) && new URL(r.url()).pathname.startsWith(`${GATEWAY}/lb/`),
    );
    expect(writes.map((r) => `${r.method()} ${r.url()}`)).toEqual([]);
  });
});
